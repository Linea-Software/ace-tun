# Making `ace-tun` Cross-Platform

**Date:** 2026-08-23
**Scope:** Analysis of the current Windows-only implementation, per-OS research, a
recommended architecture, and a phased migration plan.
**References:** the `ace-tun` source itself, a fresh clone of
[tun-rs](https://github.com/tun-rs/tun-rs) (v2.8.8, at
`ace-tun/thirdparty/tun-rs-reference/`), Linux kernel sources
(`net/ipv4/ip_sockglue.c`, `net/ipv6/ipv6_sockglue.c`), `libc` crate headers,
and platform documentation.

---

## 1. Executive summary

`ace-tun` is a transparent-redirect layer: it creates a virtual adapter, pulls
the machine's traffic into it with split-default routes, terminates each flow in
a userland TCP/IP stack, and decides per flow (by owning process + rule set) to
proxy it, relay it directly, or drop it.

**The good news: roughly two thirds of the crate is already platform-agnostic.**
The netstack, rule engine, DNS snoop cache, proxy client, callbacks, state, and
the whole `TunRedirect` lifecycle live on top of the `ipstack` crate (which is
portable by design — it just needs an `AsyncRead + AsyncWrite` framed packet
device). Those modules compile unchanged on any OS.

**The Windows-specific surface is small and well-contained** — five modules:

| Module | Windows mechanism |
|---|---|
| `adapter.rs` | `wintun` crate: adapter create, session, teardown |
| `netcfg.rs` | IP Helper APIs (`iphlpapi.dll`): addresses, routes, metrics, best-route probe |
| `dial.rs` | `IP_UNICAST_IF` / `IPV6_UNICAST_IF` socket pinning |
| `process.rs` | `GetExtendedTcpTable` / `GetExtendedUdpTable` + `OpenProcess` |
| `device.rs` | blocking WinTun session → tokio async device (reader thread) |
| `build.rs` | copies `wintun.dll` next to binaries (already Windows-gated) |

Everything else — flow decisions, QUIC policy, fail-open behaviour, DNS
snooping, HTTP CONNECT/SOCKS5 relay, watchdog teardown — ports over as-is.

**Recommendation: do not adopt `tun-rs` wholesale.** It is a good reference and
a good device-creation library, but its Windows path is *worse* than what
`ace-tun` already has (it configures addresses via `netsh`, loads `wintun.dll`
without the signed-bundle story, and does no process attribution, no loop-guard
pinning, and no routing policy). The right shape is: keep ace-tun's own
architecture, add a thin per-OS backend behind a small internal trait, and use
`tun-rs` (or raw fds) only as the Linux/macOS device layer.

Effort estimate (experienced Rust engineer): **Linux ~1–1.5 weeks**,
**macOS ~2–3 weeks** (process attribution and routing are the hard parts),
**BSD/Android/iOS later**.

---

## 2. Current architecture — portability matrix

```
app ──routes──▶ [adapter+netcfg] ──▶ [device] ──▶ [ipstack] ──▶ [netstack]
                                                        │
                ┌───────────────────────────────────────┘
                ▼
        [rule] ──► [proxy] ──► internet        (portable everywhere)
        [process] ──► decision                  (per-OS table lookup)
        [dns cache] ◄── UDP 53 snoop            (portable)
```

| Layer | Portable? | Notes |
|---|---|---|
| `netstack.rs` | ✅ | Uses `ipstack` (narrowlink), flow-level decision, QUIC drop, group-address drop, DNS snoop hook. No OS calls at all. |
| `rule.rs` | ✅ | Pure matching logic, heavy unit-test coverage. |
| `dns.rs` | ✅ | Pure DNS wire parsing. |
| `proxy.rs` | ✅ | Pure tokio sockets (HTTP CONNECT / SOCKS5). |
| `config.rs`, `callback.rs`, `state.rs` | ✅ | Pure data/logic. |
| `error.rs` | ✅ / ⚠️ | Ports as-is; add per-OS variants (e.g. `NotElevated` semantics differ). |
| `lib.rs` (builder, start/stop, watchdog) | ✅ / ⚠️ | The only Windows hook is `PhysicalInterface::discover` (used pre-start) and `TunAdapter::create`. |
| `adapter.rs` | ❌ | WinTun only. |
| `netcfg.rs` | ❌ | IP Helper only. |
| `dial.rs` | ❌ | `IP_UNICAST_IF` semantics differ per OS (see §4.1). |
| `process.rs` | ❌ | Windows socket tables only. |
| `device.rs` | ⚠️ | The `AsyncRead/AsyncWrite` contract is portable; the backend is WinTun. |
| `build.rs` | ⚠️ | Already no-ops off Windows; nothing to do. |

The important architectural fact: **`ipstack::IpStack::new(cfg, device)` takes
any `AsyncRead + AsyncWrite` that frames one IP packet per read/write** — that
is exactly what `TunDevice` provides today. Swapping the backend under that
interface is the smallest possible change.

---

## 3. Target platform support in the ecosystem (what the internet says)

### 3.1 The TUN device layer (all well-trodden)

| OS | Native device | Notes |
|---|---|---|
| Windows | WinTun (in-kernel driver, DLL-carried) | Already done, and done well (signed 0.14.1 DLL vendored, no `netsh`, real error codes). |
| Linux | `/dev/net/tun` + `TUNSETIFF` | Kernel module `tun`; `IFF_TUN \| IFF_NO_PI` gives raw IP packets. Requires `CAP_NET_ADMIN`. Non-persistent by default: **device dies with the last fd → routes die with the interface → hard-kill is safe**, exactly like WinTun. |
| macOS | `utunN` via `com.apple.net.utun_control` kernel control socket (or `/dev/utunN`) | **4-byte AF header on every packet** (must be stripped on read, prepended on write — `tun-rs`'s `packet_information(false)` handles this). Requires root. Non-persistent: fd close removes the interface. |
| FreeBSD/OpenBSD/NetBSD | `/dev/tun` | `TUNSIFMODE` ioctls; similar to Linux but ioctl-based; route config via `route_manager` crate. |
| Android | `VpnService.Builder.establish()` fd | No root; app-level VPN; attribution is per-UID, not per-PID. |
| iOS/tvOS | `NEPacketTunnelProvider` fd | Same; no process attribution at all. |

`tun-rs` v2.8.8 supports all of the above (Windows, Linux, macOS, the three
BSDs, Android, iOS, tvOS, OpenHarmony) with sync + tokio async APIs, TAP mode,
and Linux TSO/GSO offload + multi-queue. Its Linux device layer is high quality
(handles `IFF_VNET_HDR`, creates `/dev/net/tun` if missing, etc.).

### 3.2 Addressing & routing

| OS | Recommended mechanism |
|---|---|
| Windows | IP Helper (`CreateUnicastIpAddressEntry`, `CreateIpForwardEntry2`, `SetIpInterfaceEntry`) — what ace-tun does today. Best-in-class; keep it. |
| Linux | **netlink rtnetlink** (`RTM_NEWADDR` / `RTM_NEWROUTE`). Rust crates: `rtnetlink` (rust-netlink) or `netlink-packet-route` + `netlink-sys`. Alternative: `netconfig-rs` (used by tun-rs, netlink-based on Linux). Avoid shelling to `ip` — same "no output parsing" argument as the README's case against `netsh`. |
| macOS | No netlink. Two options: (a) `SIOCAIFADDR`/`SIOCSIFMTU`/`SIOCSIFFLAGS` ioctls for addresses (what tun-rs does) + the `/sbin/route` command for routes (what `route_manager` does — the same approach WireGuard's macOS client uses), or (b) SystemConfiguration APIs (`SCDynamicStoreCopy`…) for routes, which is heavier and still undocumented-ish. Pragmatic choice: **ioctls + `route` command**, wrapped with strict error checking. |

**The split-default trick ports unchanged to every OS.** `0.0.0.0/1` +
`128.0.0.0/1` (and `::/1` + `8000::/1`) are more specific than any `/0`
default route, so longest-prefix match wins and teardown is "delete my four
routes". On Linux the routes are `dev tun0` with no gateway (point-to-point),
exactly like the zero next-hop rows ace-tun already creates. On macOS:
`route add -net 0.0.0.0/1 -interface utunN` etc.

One Windows-only concept disappears on Unix: **interface metric**. Windows needs
`SetIpInterfaceEntry` to force metric 1; on Linux the `/1` vs `/0` prefix-length
difference already wins, and on macOS the `route` command has no competing
metric. (Linux route metrics exist but are unnecessary here.)

### 3.3 Loop prevention (pinning outbound sockets) — the subtle part

The engine's own upstream connections must bypass the tunnel. Today:
`IP_UNICAST_IF` / `IPV6_UNICAST_IF`, discovered *before* routes are installed.

Verified per-OS semantics (this is the trap the README warns about, now with a
full table):

| OS | Option | Byte order | Notes |
|---|---|---|---|
| Windows | `IP_UNICAST_IF` | **network** | (current ace-tun code, correct) |
| Windows | `IPV6_UNICAST_IF` | **host** | (current ace-tun code, correct) |
| Linux | `IP_UNICAST_IF` (= 50) | **network** | kernel does `ifindex = ntohl(val)` — confirmed in `net/ipv4/ip_sockglue.c` |
| Linux | `IPV6_UNICAST_IF` (= 76) | **network** | kernel does `ntohl(val)` too — confirmed in `net/ipv6/ipv6_sockglue.c`. **Differs from Windows!** |
| macOS | `IP_BOUND_IF` (= 25) | **host** | plain `int` ifindex; xnu `in_pcbbind` path |
| macOS | `IPV6_BOUND_IF` (= 125) | **host** | plain `int` ifindex |

So the "v4 network order, v6 host order" rule that is correct on Windows is
**wrong on Linux** (v6 is also network order there). The per-OS byte-order
encoder must move into the platform backend and be unit-tested per target.

Bonus Linux difference: Linux's `IP_UNICAST_IF` returns `EADDRNOTAVAIL` if the
ifindex doesn't exist (an *error*), whereas Windows silently pins to a
nonexistent interface (a *hang*). The Linux failure mode is friendlier; log it
either way. Linux alternative: `SO_BINDTODEVICE` (name-based, needs
`CAP_NET_RAW`, no byte-order trap) — but it conflicts with the
"discovered index" design, so `IP_UNICAST_IF` is the closer port. macOS has no
`SO_BINDTODEVICE`; `IP_BOUND_IF` is the way.

### 3.4 Process attribution — the genuinely hard part

The whole product depends on "which process owns this flow". Per OS:

**Linux — netlink sock_diag (the `ss` mechanism).**
`NETLINK_SOCK_DIAG` + `inet_diag_req_v2` returns, per socket, the socket *inode*
(`idiag_inode`) for both TCP and UDP. Map inode → PID by scanning
`/proc/<pid>/fd/*` symlinks (`socket:[<inode>]`) — that is literally what
`ss -tunp` does. Then `/proc/<pid>/comm` or `/proc/<pid>/exe` gives the process
name (compare against `chrome`, `firefox`, … — note: **no `.exe` suffix on
Linux**, so the engine's rule strings need normalizing, see §5).
Rust crates: `netlink-packet-sock-diag` + `netlink-sys` (actively maintained).
Caveats:
- **Cost:** one netlink round-trip per flow is heavier than the Windows table
  dump. Mitigate with a short-TTL cache (pid by `(family, ip, port)` for
  ~250 ms) and/or batch queries (`ss`-style dumps).
- Root sees all sockets; non-root sees only its own — the engine runs
  privileged anyway.
- `/proc/net/tcp` is *not* a substitute: it exposes UID, not PID.

**macOS — sysctl PCB lists.**
`sysctl net.inet.tcp.pcblist_n` / `net.inet.udp.pcblist_n` return tagged,
variable-length `xinpcb_n` records that **include `inp_pid`** (added in macOS
10.15; the older `pcblist` structs lack it). This is what `nettop`/modern
`netstat` use — no kext, root-readable. There is no mature Rust crate; plan to
hand-roll the sysctl parse (fixed header `xinpgen_n`, then walk
`xig_len`-length records). For macOS < 10.15, fall back to no attribution
(fail open, as today's `pid.is_none()` path does).
UDP note: the pcblist includes UDP PCBs; match the local endpoint like the
Windows code does (exact match, then wildcard-address match).

**Android/iOS (future):** VpnService gives UID, NE gives nothing — process-name
rules would not work there. That is a product decision, not an engineering one.

### 3.5 Privilege model

| OS | Required | Detect with |
|---|---|---|
| Windows | Administrator token | `TOKEN_ELEVATION` (existing `is_elevated()`) |
| Linux | `CAP_NET_ADMIN` (root usually) | `capget`, or just attempt `TUNSETIFF` and map `EPERM` → a clear error |
| macOS | root (euid 0) | `geteuid() == 0` |

The existing `Error::NotElevated` degrades gracefully in the engine (it logs
"running WITHOUT traffic interception" and retries in the background) — keep
that contract, just compute the predicate per OS.

### 3.6 Teardown / hard-kill safety — already portable

On Linux and macOS, a non-persistent TUN interface is destroyed when the last
fd closes, and the kernel drops routes whose interface vanishes. That is the
same property WinTun gives on Windows: **SIGKILL restores connectivity by
itself**. No new watchdog logic needed; the existing watchdog + `Drop` paths
are correct as-is.

### 3.7 Known-gaps parity check

| Gap (from README) | Linux | macOS |
|---|---|---|
| ICMP not proxied | same (ipstack surfaces it as `UnknownTransport`; dropped) | same |
| UDP `Proxy` degrades to direct | same (HTTP CONNECT cannot tunnel UDP) | same |
| Multicast/broadcast dropped → **LAN discovery breaks** | same, *but easier to fix*: add `224.0.0.0/4` and `ff00::/8` routes via the discovered physical NIC instead of deleting auto-routes (there is no auto-`224.0.0.0/4`-on-tun on Linux; you just don't install it). | same, fix like Linux |

The group-drop path also has one Windows-specific behaviour that does not port:
Windows *auto-creates* a `224.0.0.0/4` route on the tunnel interface; Unixes
don't. On Unix the multicast packets reach the tunnel only because the `/1`
routes cover them — so the README's "better fix" (keep multicast on the
physical NIC) is the *default* approach on Unix: add explicit group routes via
the physical interface during `start()`, and optionally keep dropping them via
rules if that is preferred.

### 3.8 DNS snooping — portable, one caveat

The UDP-53 response snoop works identically (DNS queries still traverse the
tunnel as plain UDP). Linux caveat: apps commonly resolve via the
`systemd-resolved` stub (`127.0.0.53`); the stub's own upstream queries are
regular UDP sockets owned by `systemd-resolved` and still cross the tunnel, so
the snoop still populates the cache. Loopback DNS is already handled by the
"loopback goes direct" rule. No change needed.

---

## 4. Recommended architecture

Keep the crate's current shape; introduce one `platform` module with four small
backends behind it. Do **not** restructure `netstack`/`rule`/`dns`/`proxy`.

### 4.1 Proposed module layout

```
src/
├── lib.rs            # unchanged; builder/start/stop/watchdog stay portable
├── netstack.rs       # unchanged
├── rule.rs / dns.rs / proxy.rs / config.rs / callback.rs / state.rs  # unchanged
├── device.rs         # unchanged contract (AsyncRead+AsyncWrite framed device);
│                     #   impls move behind the backend
└── platform/
    ├── mod.rs        # pub(crate) Backend trait + per-OS re-exports
    ├── windows/      # current adapter.rs + netcfg.rs + dial.rs + process.rs
    │                 #   (moved, byte-for-byte)
    ├── linux/        # tun device, rtnetlink cfg, IP_UNICAST_IF dial, sock_diag
    └── macos/        # utun device (+AF-header shim), ioctl+route cfg,
                      #   IP_BOUND_IF dial, sysctl pcblist attribution
```

```rust
// platform/mod.rs (sketch)
pub(crate) struct PhysicalInterface { v4_index: Option<u32>, v6_index: Option<u32> }

pub(crate) trait Backend {
    /// Create the adapter, assign addresses/routes, return a session handle.
    fn create(ipv6: bool) -> Result<AdapterHandle>;
    fn discover_physical_interface() -> PhysicalInterface;   // pre-routes
    fn is_privileged() -> bool;                               // NotElevated
}

pub(crate) trait ProcessTable {
    fn resolve_pid(local: SocketAddr, is_udp: bool) -> Option<u32>;
    fn process_name(pid: u32) -> Option<String>;
}

/// Byte-order-correct per-OS. Unit-tested on every target (see §3.3 table).
pub(crate) fn unicast_if_value(index: u32, is_ipv6: bool) -> u32;

/// Pin an outbound socket to a physical interface (loop guard).
pub(crate) fn pin_socket(raw: RawSocket, index: u32, is_ipv6: bool) -> io::Result<()>;
```

`dial.rs`, `netcfg.rs`, `process.rs`, and `adapter.rs` become thin wrappers over
`platform::*`; `device.rs` keeps its `TunDevice` contract but its constructor
is fed by the backend (on Linux/macOS it can wrap `tokio::io::unix::AsyncFd`
over a nonblocking fd — no reader thread needed — or reuse the thread pattern
for uniformity).

### 4.2 What to take from `tun-rs` (the reference clone)

**Take:**
- The Linux device implementation (`src/platform/linux/device.rs`, `sys.rs`) —
  solid handling of `TUNSETIFF`, `IFF_NO_PI`, offload negotiation, fd setup.
  Either depend on `tun-rs` (features `async_tokio`, layer 3 only) or vendor
  this file.
- The macOS `utun_control` open sequence (`src/platform/apple/`, `macos/`) and
  the `packet_information(false)` shim that strips the 4-byte AF header.
- The address-ioctl pattern (`SIOCAIFADDR` via a control socket).
- The `route_manager` approach for macOS routes (or its crate).

**Do not take:**
- Its Windows path (`netsh.rs`, `winreg`-based driver installation, no signed
  DLL bundling, no elevation check) — strictly worse than current ace-tun.
- Its config surface (DeviceBuilder with `name`/`ipv4`/`ipv6` strings) — ace-tun
  needs LUID-level control and its own constants.
- It provides **no** process attribution, no DNS snooping, no proxy relay, no
  routing policy (split-default, metrics) — those stay ace-tun's job either way.

### 4.3 Dependency plan

| Target | Add | Purpose |
|---|---|---|
| Linux | `tun-rs` (or vendored linux device), `rtnetlink` (+ `netlink-packet-route`), `netlink-packet-sock-diag` + `netlink-sys`, `libc` | device; addressing/routing; attribution; constants |
| macOS | `libc`, `route_manager` (or hand-rolled `route` wrapper), sysctl code (hand-rolled) | device ioctls; routes; attribution |
| all | `socket2` already present (has `bind_device` on Unix if needed) | pinning |
| Windows | unchanged | — |

`wintun`, `windows` crate, and `build.rs` stay Windows-only deps (cargo
handles that automatically with `[target.'cfg(windows)'.dependencies]`).

### 4.4 Process-name normalization (small but real)

Rules match `chrome.exe`/`brave.exe` today; the engine configures them via
`ace-engine/src/service/proxy/mod.rs` with hard-coded Windows names. On Linux
the same binaries are `chrome`, `firefox`, `brave`, `msedge`. Plan: normalize
in `process_name()` (strip `.exe` on Unix) **or** add an OS-aware alias table
in ace-engine. Prefer normalizing in ace-tun so the engine's rule strings stay
unchanged.

---

## 5. Phased migration plan

### Phase 0 — Pure refactor (no behaviour change, ~2–3 days)
1. Move `adapter.rs`/`netcfg.rs`/`dial.rs`/`process.rs` into
   `platform/windows/`; introduce the `Backend`/`ProcessTable` seams; make
   `lib.rs` go through them.
2. Keep all existing unit tests green (`cargo test`), including
   `vendored_wintun_dll_loads`.
3. Add the per-OS byte-order table as a doc + unit tests gated per target.

### Phase 1 — Linux (target: `x86_64-unknown-linux-gnu`, ~1–1.5 weeks)
1. **Device:** depend on `tun-rs` (async feature) or vendor its linux device;
   wrap in `TunDevice`'s contract via `AsyncFd`. `IFF_NO_PI`, MTU 1500, no
   offload (netstack doesn't need it; can come later).
2. **Netcfg:** `rtnetlink` — add `10.63.7.1/24`, `fd00:ace:7::1/64`, MTU,
   up-flag, the four split-default routes, plus (optionally) the multicast
   group routes via the physical NIC. No metric step.
3. **Dial:** `IP_UNICAST_IF`/`IPV6_UNICAST_IF` with the *network-order* encoder
   for **both** families (Linux rule, differs from Windows v6).
4. **Process:** sock_diag query → inode → `/proc` scan → `/proc/<pid>/comm`;
   cache with ~250 ms TTL.
5. **Privilege:** `CAP_NET_ADMIN` check → `Error::NotElevated`.
6. **Validation:** `cargo test`; `live_check` equivalent under a root shell;
   test hard-kill (`kill -9`) leaves routing intact; QUIC drop (Chrome + `--disable-quic` fallback); IPv6; multicast LAN discovery.

### Phase 2 — macOS (target: `aarch64-apple-darwin` / `x86_64-apple-darwin`, ~2–3 weeks)
1. **Device:** utun via `utun_control`; strip/prepend the 4-byte AF header;
   `AsyncFd` wrapping.
2. **Netcfg:** `SIOCAIFADDR` (addresses), `SIOCSIFMTU`, `SIOCSIFFLAGS`;
   routes via `route` command (or `route_manager`): the four split-defaults
   with `-interface utunN`.
3. **Dial:** `IP_BOUND_IF`/`IPV6_BOUND_IF` with plain-index encoder.
4. **Process:** sysctl `net.inet.{tcp,udp}.pcblist_n` parser for `inp_pid`;
   `< 10.15` fallback → unattributed (fail open).
5. **Privilege:** `geteuid() == 0` → `Error::NotElevated`.
6. **Validation:** macOS CI runner (GitHub Actions `macos-14` supports `sudo`);
   same checklist as Linux.

### Phase 3 — Hardening, docs, CI (1 week, can overlap)
- GitHub Actions matrix: `windows-latest` (admin by default), `ubuntu-latest`
  (`sudo modprobe tun` in CI setup), `macos-14`.
- Port `live_check.rs` into a per-OS harness (the CONNECT proxy part is
  portable; only elevation/browser names differ).
- Update README (requirements, bundling, per-OS gaps) and this document's
  status table.
- Optional: BSDs via tun-rs (cheap once the Linux backend exists, ~2–3 days
  each); Android/iOS later via `VpnService`/`NEPacketTunnelProvider` fds
  (requires rethinking attribution → UID, and a separate app shell).

### Out of scope for now (call out, don't build)
- TSO/GSO offload, multi-queue (Linux perf later).
- `SO_MARK` + policy-routing alternative for loop prevention (unneeded with
  `IP_UNICAST_IF`).
- eBPF-based attribution (more accurate, much more work; sock_diag suffices
  for the flow-open model).
- ICMP proxying (same gap on all platforms).

---

## 6. Risks and open questions

1. **macOS `route` command fragility** — output/exit-code semantics differ
   across macOS versions. Mitigation: wrap in one place, treat non-zero exits
   as teardown-worthy errors, and rely on the "interface death removes routes"
   property as the safety net. (This is what WireGuard's macOS app lives with.)
2. **Linux attribution cost** — a netlink query per flow could add latency at
   high connection rates. The 250 ms cache should absorb it; benchmark with
   `live_check` under load before shipping.
3. **`inp_pid` availability on old macOS** — decide a floor (10.15+) and fail
   open below it.
4. **Process-name aliasing** (`chrome.exe` vs `chrome`) — must be settled
   before Phase 1, or blocking silently stops matching on Linux.
5. **Sandboxed apps on macOS** (App Store) — if ace-engine is ever sandboxed,
   utun creation requires the `com.apple.developer.networking.vpn.api` /
   packet-tunnel entitlement and the NE framework instead of raw utun. Today
   the engine is a root daemon, so raw utun is fine.
6. **systemd-networkd / NetworkManager interference** — on Linux, a manager
   that "helpfully" removes unknown routes could yank our split-defaults.
   Mitigation: re-add on a watchdog timer (or verify route presence in the
   existing periodic stats task).

---

## 7. Verified facts used in this report (with sources)

- Linux `IP_UNICAST_IF` = 50, `IPV6_UNICAST_IF` = 76 — `libc` headers
  (`unix/linux_like/mod.rs`).
- Linux takes **network byte order** for both: `ifindex = ntohl(val)` in
  `net/ipv4/ip_sockglue.c` and `net/ipv6/ipv6_sockglue.c` (kernel v7.2 sources
  via Elixir). Linux returns `EADDRNOTAVAIL` for a bogus index.
- Windows: v4 network order / v6 host order (MSDN + current ace-tun code,
  which the WireGuard client follows).
- macOS `IP_BOUND_IF` = 25, `IPV6_BOUND_IF` = 125 — `libc` headers
  (`unix/bsd/apple/mod.rs`); plain host-order index (xnu `in_pcbbind` path —
  verify once in CI).
- `SO_BINDTODEVICE` exists on Linux (`socket(7)`), not on macOS.
- macOS `net.inet.tcp.pcblist_n` tagged records include PID (`inp_pid`) —
  confirmed via nettop/bsd-xtcp references; not a stable ABI (Apple forums
  note it is "private/fragile") — budget for it.
- `netlink-packet-sock-diag` 0.4.2 on crates.io implements the sock_diag
  protocol (`ss` mechanism: inode → `/proc/<pid>/fd` scan for PID).
- tun-rs v2.8.8: Linux/Windows use `netconfig-rs`; macOS/BSD use
  `route_manager`; Windows addressing via `netsh`; supports
  iOS/Android fd-based devices.

---

## 8. Status and verified corrections (2026-08-23)

Phase 0 (platform refactor) and Phase 1 (Linux) are implemented; see the git
log. Two claims in the analysis above were **corrected during implementation**
(both verified against kernel 6.18 sources and live in Docker/WSL2):

### 8.1 Linux loop prevention must use `SO_BINDTODEVICE`, not `IP_UNICAST_IF`

§3.3 recommended `IP_UNICAST_IF` as "the closer port" for Linux. That is
wrong for the loop guard: `tcp_v4_connect` (and the v6 equivalent) route the
initial SYN with `sk->sk_bound_dev_if` — which only `SO_BINDTODEVICE` sets.
`IP_UNICAST_IF` (`inet->uc_index`) is applied later, on the packet-output
path, after the route and source address were already chosen from the routing
table. A socket pinned with `IP_UNICAST_IF` therefore still sends its SYN into
the tunnel, and the own-process loop-guard dial re-enters the netstack
forever (observed as thousands of ESTAB relay sockets with the tunnel's source
address). The implementation uses `SO_BINDTODEVICE` (name resolved from the
discovered index), skips loopback destinations (the kernel's local table
rejects `oif`-constrained lookups to 127/8 — and loopback never enters the
tunnel anyway), and requires `CAP_NET_RAW` alongside `CAP_NET_ADMIN` in the
privilege check.

The byte-order table in §3.3 remains correct as a description of the option
semantics (Linux: network order for both), but the Linux columns are now
moot for the loop guard; they were kept as unit tests in
`platform/linux/dial.rs`.

### 8.2 Linux TCP attribution needs the flow's remote endpoint

§3.4 assumed a local-endpoint query suffices (as on Windows). It does not:
the kernel hashes *established* TCP sockets by the full four-tuple, so
`inet_diag_find_one_icsk` cannot find them from the local endpoint alone. The
`ProcessTable` seam now takes the flow's remote endpoint, and the Linux
backend queries a small sequence of socket-id orientations (established
four-tuple → listener local-only → wildcard listener; UDP: connected
receive-orientation → unconnected → wildcard). The UDP quirk is confirmed in
`udp_diag.c`: "src and dst are swapped for historical reasons" — the exact
lookup hashes on `dport`/`dst` and scores `sk_dport == sport`,
`sk_rcv_saddr == src`.

### 8.3 Other implementation notes

- `netlink-sys` 0.8.8's `Socket::recv` appends into a `bytes::BufMut`: the
  receive buffer must be `Vec::with_capacity(n)` (length 0), or datagrams land
  in spare capacity beyond the slice that gets read.
- netlink-packet-route 0.19 does not re-export the `RTM_*` message types and
  its message structs are `#[non_exhaustive]`; both are handled locally.
- The kernel answers a `RTM_GETROUTE` lookup with an `RTM_NEWROUTE` message.
- Requests without `NLM_F_ACK` get no reply on success — the ack is what
  makes `request_ack` wait for commit.
- After a hard kill on Linux the `224.0.0.0/4` / `ff00::/8` group routes via
  the physical NIC survive (they are not bound to the tunnel). They are inert
  and a graceful stop removes them.
- Process-name normalization (`.exe` stripping) lives in `rule.rs` matching,
  so engine rule strings (`chrome.exe`) match Linux names (`chrome`) and vice
  versa on every platform.

### 8.4 macOS (Phase 2) — implemented, compiled, not yet run on hardware

The macOS backend (`src/platform/macos/`) is implemented behind the same
seams as Linux. It compiles and passes clippy for both `x86_64-apple-darwin`
and `aarch64-apple-darwin` (checked from the Windows development machine; test
binaries cannot be linked without a macOS SDK). **Nothing has been run on a
real Mac** — the items marked *needs a Mac* below are the first things to
verify there. The struct layouts and ioctl numbers were transcribed from the
macOS 14 xnu sources (linked in §7) and are pinned by compile-time assertions
and unit tests; the `pcblist_n` parser tests construct synthetic tables and
must be run with `cargo test` on a Mac.

- **Device** (`adapter.rs`) — utun via the `com.apple.net.utun_control` kernel
  control (socket + `CTLIOCGINFO` + `connect` with unit 0, which makes the
  kernel assign the lowest free `utunN`; name read back via `UTUN_OPT_IFNAME`).
  The fd owns the interface, so the hard-kill property holds exactly as on
  Linux. `ADAPTER_NAME` is `"utun%d"` — informational only, macOS does not
  accept a name template.
- **AF header** (`device.rs`) — utun prepends a 4-byte protocol-family header
  to every datagram. It is big-endian on the wire (`xnu`'s `utun_input`
  byte-swaps with `ntohl`); writes prepend `AF_INET` (2) / `AF_INET6` (30) as
  `u32::to_be_bytes`, reads strip 4 bytes. *Needs a Mac:* the end-to-end
  framing.
- **Netcfg** (`netcfg.rs`) — addresses via `SIOCAIFADDR` / `SIOCAIFADDR_IN6`
  (v4 broadcast slot = the address itself, point-to-point with no peer; v6
  gets `IN6_IFF_NODAD` + infinite lifetimes, mirroring tun-rs), MTU and link
  up via `SIOCSIFMTU` / `SIOCGIFFLAGS`+`SIOCSIFFLAGS`. Routes via `/sbin/route`
  (`add -inet6/-inet <dest>/<prefix> -interface <if>`; delete by destination
  only). Exit-code handling: `File exists` on add and `not in table` /
  `No such process` on delete count as success (idempotent). Physical
  interface discovery parses `route -n get` output. *Needs a Mac:* the route
  command's exact stderr strings on current macOS, and whether IPv6 `::/1`
  needs `-inet6` passed before `add` on any supported version.
- **Dial** (`dial.rs`) — `IP_BOUND_IF` (25) / `IPV6_BOUND_IF` (125), plain
  host-order index for both families (libc constants pinned by a test).
  Loopback destinations are left unpinned; *needs a Mac:* confirm the local
  table accepts an `ifscope`-constrained lookup to 127/8 (the Linux kernel
  rejects it, which is why the skip exists).
- **Process** (`process.rs`) — `net.inet.{tcp,udp}.pcblist_n` via
  `sysctlbyname` (size-then-fetch), records walked by `xi_len`/`xso_len`.
  Layouts transcribed from xnu `in_pcb.h` / `socketvar.h` (`#pragma pack(4)`):
  ports at 16/18 (network order), `inp_vflag` at 44, addresses at 48/64
  (v4 in the 4-in-6 slot), `so_last_pid` at 68 in `xsocket_n` — pinned by
  `#[repr(C, packed(4))]` mirror structs + compile-time `offset_of!` asserts.
  Matching scores records (full four-tuple > specific local > wildcard) so an
  accepted socket beats the listener it hangs off. Kernel < 10.15 fails open
  (no `pcblist_n` → `None`). Process names via `proc_pidinfo`
  (`PROC_PIDT_SHORTBSDINFO` → `pbi_comm`, no `.exe`). *Needs a Mac:* the
  `so_last_pid` value for live flows, the 250 ms cache's hit rate, and the
  table-walk against real kernels (several macOS versions).
- **Privilege** — `geteuid() == 0`, mapped to `Error::NotElevated`; `EPERM`
  from the control socket is mapped the same way as a second line of defense.

Untested-on-hardware caveats: `route` stderr strings, `so_last_pid` semantics
for UDP (unconnected sockets attribute to the last sender), and the
`IP_BOUND_IF` loop-guard behaviour on a real network. The report's §3.3 table
stands as written for macOS (`IP_BOUND_IF`, host order for both families).
