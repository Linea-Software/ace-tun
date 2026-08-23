# ace-tun

A transparent redirect for Windows, Linux, and macOS. It creates a virtual
network adapter (WinTun on Windows, a TUN device on Linux/macOS), points the
routing table at it, runs a userland TCP/IP stack over the raw IP packets that
arrive, and hands each terminated flow to a local MITM proxy — or connects it
straight out, or drops it.

```
  app ──routes──▶ TUN adapter ──▶ userland netstack ──┬─▶ MITM proxy ──▶ internet
                                                      └─▶ direct socket ─▶ internet
```

This crate replaces `proxy-redirect`, a WinDivert packet-interception layer.

## Why the rewrite

The WinDivert design intercepted individual packets and reverse-mapped each one
to its owning process to decide what to do with it. Three problems were
structural rather than incidental:

| Problem | Why it happened | How this crate avoids it |
|---|---|---|
| **HTTP/3 leaked past blocking.** Instagram and YouTube loaded despite matching block rules. | The per-packet `GetExtendedUdpTable` lookup raced UDP socket setup. On a miss the flow was passed through *uninspected*. | Attribution happens once per **flow**, at open. The SYN could not exist unless the socket already did, so there is nothing to race. And QUIC is dropped regardless of attribution — see below. |
| **NAT bookkeeping.** Destination rewriting needed a table mapping ephemeral ports back to real destinations, plus checksum fixups. | Packet-level redirection destroys the original destination. | Under a TUN the destination is simply in the IP header. No rewriting, no table. |
| **IPv6 bypassed everything.** | The capture filter was `ip and (...)`, which never matched IPv6. | The netstack handles both families identically; IPv6 addressing and routes are installed by default. |

A later attempt to fix attribution with a second WinDivert handle on the Socket
layer made things worse: QUIC still leaked *and* ordinary sites stopped loading.
That is the failure mode this crate is designed against.

## Design

### Routing

We never touch the system's default route. Instead we install the two halves of
the address space as *more specific* routes on the tunnel:

* IPv4 — `0.0.0.0/1` and `128.0.0.0/1`
* IPv6 — `::/1` and `8000::/1`

Longest-prefix match makes these beat any `0.0.0.0/0`, so traffic enters the
tunnel while the original default route sits untouched underneath. Teardown is
just "delete our four routes".

All addressing and routing goes through the IP Helper APIs (`iphlpapi.dll`)
rather than shelling out to `netsh` — real error codes, no output parsing, no
dependence on the machine's UI language.

### Loop prevention

Once the tunnel owns the routing table, the engine's *own* upstream connections
would route into it too, and each one would open another upstream connection.
The guard is a per-OS socket option that pins a socket to a specific interface
and bypasses the routing table entirely. We discover the internet-facing
interface once at startup — **before** installing our routes, so the answer
describes the real network — and pin every outbound socket to it.

| OS | Mechanism | Notes |
|---|---|---|
| Windows | `IP_UNICAST_IF` / `IPV6_UNICAST_IF` | index in **network** byte order for v4, **host** order for v6 — see the byte-order trap below |
| Linux | `SO_BINDTODEVICE` | `IP_UNICAST_IF` does *not* affect the connect-time route lookup there, so the SYN would still enter the tunnel; `SO_BINDTODEVICE` sets `sk_bound_dev_if`, which `tcp_v4_connect` honours. Requires `CAP_NET_RAW`. Loopback destinations are left unpinned (the local table already keeps them out of the tunnel). |
| macOS | `IP_BOUND_IF` / `IPV6_BOUND_IF` | plain interface index in **host** byte order for both families — the connect-time lookup honours the bound interface, so the SYN never enters the tunnel |

> **Byte-order trap:** on Windows, `IP_UNICAST_IF` takes the interface index
> in *network* byte order; `IPV6_UNICAST_IF` takes it in *host* byte order.
> (Linux takes network order for both, but does not use these options.)
> Getting this wrong silently pins the socket to a nonexistent interface,
> which looks like "all outbound traffic hangs". See `unicast_if_value` in
> `src/platform/<os>/dial.rs`.

If no interface can be discovered for a family, our own flows in that family are
**dropped** rather than relayed — an unpinned relay would loop forever, and the
flow could not have succeeded anyway.

### Failure posture

The engine fails open. Process lookup failure, empty rule set, unreachable
upstream proxy — every one of those results in traffic flowing. Breaking a site
the user is allowed to visit is treated as a worse outcome than missing a block.

`StatsSnapshot::proxy_fallbacks` counts flows that reached the internet
uninspected because the proxy was down. That is the number to alert on.

The one deliberate exception is **QUIC**, which is dropped for *every* process
rather than just known browsers. Dropping costs nothing — every QUIC client
falls back to TCP, which is inspected reliably — whereas passing an
unattributable UDP/443 flow is exactly the bypass this rewrite exists to close.

### Teardown

Routes are removed on stop, on drop, and on netstack panic (a watchdog task
supervises the netstack and tears down whichever way it ends).

If the process dies without running any of that, the adapter is destroyed —
Windows closes the WinTun handle and the routes bound to its LUID go with it;
on Linux and macOS the non-persistent TUN/utun interface dies with its last
fd, taking its routes along. **Hard-kill restores normal connectivity by
itself** — the safety property does not depend on our cleanup code running.

## Requirements

* **Windows:** administrator privileges (WinTun cannot create an adapter
  otherwise) and `wintun.dll` next to the executable — see below.
* **Linux:** root, or `CAP_NET_ADMIN` + `CAP_NET_RAW` (the TUN device and the
  `SO_BINDTODEVICE` loop guard).
* **macOS:** root (utun creation requires root or the packet-tunnel
  entitlement).

`TunRedirect::start` returns `Error::NotElevated` so callers can degrade
gracefully instead of failing obscurely.

## Bundling `wintun.dll` (Windows only)

The official WinTun distribution is vendored at `thirdparty/wintun/` —
**version 0.14.1**, Authenticode-signed by `CN=WireGuard LLC`. It ships all four
architectures (`amd64`, `x86`, `arm`, `arm64`) plus the header and license.

`build.rs` copies the architecture-appropriate DLL next to every binary cargo
produces (`target/<profile>/`, `deps/`, `examples/`). Because it runs as a build
script of a path dependency, this also covers **`ace-engine`'s** output
directory, so the engine binary gets the DLL beside it with no extra step.

The `vendored_wintun_dll_loads` test loads the DLL and resolves its exports,
which catches a truncated, wrong-architecture, or mis-copied artifact at
`cargo test` time instead of as an opaque adapter-creation failure at runtime.

### Shipping it

`ace-installer/build.ps1` copies the DLL from this vendored tree — not from the
build output, so the shipped artifact is the reviewed one — verifies its
Authenticode signature is still `Valid`, and fails the build if it is not.
`installer.wxs` installs it beside `ace-engine.exe`.

**There is no separate driver to register.** Unlike WinDivert, WinTun's kernel
component is carried inside the DLL and installed on demand when the first
adapter is created, so the installer's `sc create WinDivert64` / `sc delete`
custom actions are gone rather than replaced.

Do not repack, patch, or recompress the DLL — the signature is what lets the
kernel component load.

### Licensing

WinTun is by WireGuard LLC / Jason A. Donenfeld and is released under the
**GPLv2 *or* the MIT license** — see `thirdparty/wintun/LICENSE.txt`. We
redistribute under the MIT option, which requires only that the copyright and
permission notice accompany the distribution. The installer ships that file as
`WINTUN-LICENSE.txt`; `build.ps1` fails if it is missing, so the obligation
cannot be dropped by accident.

## Usage

```rust
use ace_tun::{TunRedirect, ProxyConfig, Rule, RuleAction, RuleProtocol};

let redirect = TunRedirect::builder("127.0.0.1:8080")?
    .add_rule(Rule::new("chrome.exe;brave.exe")
        .ports("80;443")
        .protocol(RuleProtocol::Tcp)
        .action(RuleAction::Proxy))
    .add_rule(Rule::new("*").action(RuleAction::Direct))
    .proxy_config(ProxyConfig::http("127.0.0.1", 8080))
    .build()?;

redirect.start().await?;   // needs elevation
// ...
redirect.stop().await?;
```

Flows selected by a `Proxy` rule are handed to the upstream proxy as an HTTP
`CONNECT` (or SOCKS5), using the hostname from the DNS-snoop cache when one is
known. That matters: the MITM proxy needs a name to issue a certificate for and
to send as SNI upstream, so DNS snooping is load-bearing, not just diagnostic.

## Known gaps

* **ICMP is not proxied.** `ping` to an off-link address gets no reply while the
  tunnel is up. TCP and UDP are unaffected. This is the one thing the WinDivert
  build passed through that this one does not; forwarding it would need raw
  sockets and an ICMP-id NAT table.
* **UDP `Proxy` rules degrade to direct.** UDP cannot be tunnelled through an
  HTTP `CONNECT` proxy, so a `Proxy` action on a UDP flow relays it directly
  rather than dropping it.
* **Multicast and broadcast are dropped, not relayed.** Our split-default routes
  cover the whole address space. Windows then auto-creates a `224.0.0.0/4`
  route on the tunnel that wins on metric, so mDNS (5353), SSDP (1900) and
  LLMNR (5355) all arrive here. They cannot be relayed through a pinned,
  `connect`ed unicast socket in any meaningful way, and attempting it burns one
  socket per packet, which exhausts Windows' socket buffers on a busy LAN
  (`WSAENOBUFS`). Dropping them means **LAN device discovery does not work while
  the tunnel is up** on Windows — no Chromecast, network printer, or SMB
  browsing. Watch `StatsSnapshot::group_dropped` to see the volume involved.
  On Linux and macOS the problem does not arise: no auto-route is created,
  and the backend instead installs `224.0.0.0/4` and `ff00::/8` routes via
  the discovered physical NIC, so multicast never enters the tunnel.

  Note: after a hard kill (`SIGKILL`) on Linux or macOS, those two group
  routes survive (they point at the physical NIC, not the tunnel). They are
  inert — multicast keeps flowing on the real network — and a graceful stop
  removes them.

## Testing

`cargo test` covers the parts that do not need a kernel driver: rule evaluation,
the full flow-decision matrix (including the QUIC and loop-guard cases), DNS
parsing, the proxy client, socket-option encoding, and builder validation.

Adapter creation, routing, and packet forwarding cannot be exercised without
elevation and a real driver. Use `cargo run --example live_check` (elevated) for
those — it runs the whole stack against a self-contained blocking proxy and
prints what it sees.

The macOS backend is implemented and compiles for both Apple targets but has
not been run on real hardware from the development environment; see
`docs/cross-platform-report.md` §8.4 for what needs a macOS machine.
