//! Flow dispatch: decide what happens to each connection the netstack accepts.
//!
//! `ipstack` hands us fully-formed flows rather than packets. That is the whole
//! point of the migration: the original destination arrives in the IP header of
//! the SYN, so there is nothing to reverse-map, no NAT table to keep coherent,
//! and no window in which a flow is "not yet attributed". A flow is either
//! accepted here with its true destination, or it does not exist.
//!
//! # Failure posture
//!
//! Every decision path defaults to letting traffic through. If process lookup
//! fails, if the rule set is empty, if the upstream proxy is down — the flow
//! goes direct. Breaking a site the user is allowed to visit is treated as a
//! worse outcome than missing a block, because the former makes the machine
//! feel broken and the latter is recoverable.
//!
//! There are two deliberate exceptions — QUIC, and group-addressed traffic.
//! See [`decide`].

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ipstack::{IpStack, IpStackStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

use crate::callback::ConnectionInfo;
use crate::dial;
use crate::proxy::{self, Target};
use crate::rule::RuleAction;
use crate::state::{QuicPolicy, Shared};

/// How long a UDP flow may sit idle before we release it.
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest datagram we will relay. Anything bigger is already beyond the
/// tunnel MTU and would have been fragmented upstream.
const UDP_BUFFER: usize = 65_535;

/// What to do with an accepted flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Connect straight to the original destination, bypassing the tunnel.
    Direct,
    /// Relay through the upstream proxy identified by this config id.
    Proxy(u32),
    /// Drop the flow.
    Block,
}

/// The facts about a flow that feed [`decide`].
///
/// Bundled into a struct so the decision logic can be exercised in tests
/// without a TUN adapter, a kernel driver, or elevation.
#[derive(Debug, Clone)]
pub(crate) struct FlowFacts<'a> {
    /// Original destination address.
    pub(crate) dest: SocketAddr,
    /// `true` for UDP, `false` for TCP.
    pub(crate) is_udp: bool,
    /// PID that owns the local endpoint, if it could be resolved.
    pub(crate) pid: Option<u32>,
    /// Executable file name of that process, lowercased.
    pub(crate) process_name: &'a str,
    /// Destination hostname from the DNS-snoop cache, if known.
    pub(crate) domain: Option<&'a str>,
}

/// Choose an action for one flow.
///
/// The order of the checks is load-bearing:
///
/// 1. **Our own traffic goes direct, always.** This is the loop guard. The
///    engine's upstream connections re-enter the tunnel; if a rule could send
///    them back to the proxy we would recurse until the process died. The one
///    case where our own flow is dropped instead is when there is no physical
///    interface to pin the outbound socket to, because then "direct" would
///    itself re-enter the tunnel.
/// 2. **Loopback goes direct** unless explicitly configured otherwise.
/// 3. **Multicast and broadcast are dropped.** They cannot be relayed through a
///    pinned, `connect`ed unicast socket, and trying costs one socket per
///    packet — which is what exhausts Windows' socket buffers on a busy LAN.
/// 4. **QUIC is dropped** when the policy says so — *regardless of which
///    process owns it*. This is the one place we do not fail open, and it is
///    deliberate: the previous design scoped the QUIC block to known browser
///    executables, so any flow whose process could not be identified in time
///    leaked out uninspected over HTTP/3. Dropping unconditionally costs
///    nothing, because every QUIC client is required to fall back to TCP, and
///    TCP is inspected reliably. "Fail closed" here still means "the site
///    loads".
/// 5. Otherwise the rule set decides, defaulting to direct.
pub(crate) fn decide(shared: &Shared, facts: &FlowFacts<'_>) -> Decision {
    if facts.pid == Some(shared.current_pid) {
        // Our own upstream traffic reaches the internet only because
        // `dial::tcp` pins the socket to the physical NIC, bypassing our own
        // routes. If there is no interface to pin to, relaying this flow would
        // send it straight back into the tunnel and into this function again,
        // forever. Dropping it is the only terminating option — and the flow
        // could not have succeeded anyway.
        if !facts.dest.ip().is_loopback() && shared.iface().index_for(facts.dest.ip()).is_none() {
            tracing::error!(
                "no physical interface for {}; dropping our own flow to avoid a routing loop",
                facts.dest
            );
            return Decision::Block;
        }
        return Decision::Direct;
    }

    if facts.dest.ip().is_loopback() && !shared.localhost_via_proxy {
        return Decision::Direct;
    }

    // Multicast and broadcast cannot be relayed meaningfully. Our outbound
    // sockets are unicast, pinned, and `connect`ed to a single peer; sending a
    // group address down one of those is not what the sender asked for, and
    // replies would arrive on a socket nobody is reading. Windows also punishes
    // the attempt — a socket per mDNS/SSDP packet is how this exhausts buffers
    // and starts failing with WSAENOBUFS.
    if is_group_address(facts.dest.ip()) {
        return Decision::Block;
    }

    if facts.is_udp
        && facts.dest.port() == shared.quic_port
        && shared.quic_policy == QuicPolicy::Drop
    {
        return Decision::Block;
    }

    let m = shared.rules.evaluate(
        facts.process_name,
        facts.dest.ip(),
        facts.dest.port(),
        facts.is_udp,
        facts.domain,
    );

    match m.action {
        RuleAction::Direct => Decision::Direct,
        RuleAction::Block => Decision::Block,
        RuleAction::Proxy => Decision::Proxy(m.proxy_config_id),
    }
}

/// Whether `ip` is a multicast or broadcast address — i.e. addressed to a group
/// rather than to one host.
///
/// These reach us because our split-default routes cover the whole address
/// space and Windows then auto-creates a `224.0.0.0/4` route on our adapter,
/// which wins on metric. mDNS (5353), SSDP (1900), and LLMNR (5355) all land
/// here, and on a busy LAN that is a continuous stream.
fn is_group_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

/// Accept flows until the stack closes or `shutdown` fires.
pub(crate) async fn run(
    mut stack: IpStack,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let stream = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = stack.accept() => match accepted {
                Ok(s) => s,
                Err(e) => {
                    shared.log(format!("netstack accept ended: {e}"));
                    break;
                }
            },
        };

        let shared = Arc::clone(&shared);
        match stream {
            IpStackStream::Tcp(tcp) => {
                shared.stats.tcp_flows.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp(tcp, &shared).await {
                        shared.log(format!("tcp flow ended: {e}"));
                    }
                });
            }
            IpStackStream::Udp(udp) => {
                shared.stats.udp_flows.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    if let Err(e) = handle_udp(udp, &shared).await {
                        shared.log(format!("udp flow ended: {e}"));
                    }
                });
            }
            // ICMP and friends. We do not currently proxy these; see the
            // crate-level docs for what that means in practice.
            IpStackStream::UnknownTransport(u) => {
                tracing::trace!("dropping unsupported transport {:?}", u.ip_protocol());
            }
            IpStackStream::UnknownNetwork(bytes) => {
                tracing::trace!("dropping unparseable {}-byte packet", bytes.len());
            }
        }
    }
    shared.log("netstack accept loop stopped");
}

/// Gather the facts for a flow: owning process and cached hostname.
///
/// Attribution happens exactly once, here, at flow open — by which point the
/// socket is guaranteed to exist in the kernel's table, because the SYN we are
/// responding to could not have been sent otherwise.
fn attribute(src: SocketAddr, dest: SocketAddr, is_udp: bool) -> (Option<u32>, String) {
    let pid = crate::platform::resolve_pid(src, dest, is_udp);
    let name = pid
        .and_then(crate::platform::process_name)
        .map(|n| n.to_ascii_lowercase())
        .unwrap_or_default();
    if pid.is_none() {
        tracing::trace!("no owning process for {src} -> {dest}");
    }
    (pid, name)
}

/// Look up the destination hostname, but only if some rule actually needs it.
fn domain_for(shared: &Shared, dest: IpAddr) -> Option<String> {
    if shared.rules.needs_domain_resolution() {
        shared.dns_cache.lookup(dest)
    } else {
        None
    }
}

/// Relay one TCP flow.
async fn handle_tcp(mut stream: ipstack::IpStackTcpStream, shared: &Shared) -> std::io::Result<()> {
    let src = stream.local_addr();
    let dest = stream.peer_addr();

    let (pid, process_name) = attribute(src, dest, false);
    let domain = domain_for(shared, dest.ip());
    let facts = FlowFacts {
        dest,
        is_udp: false,
        pid,
        process_name: &process_name,
        domain: domain.as_deref(),
    };
    let decision = decide(shared, &facts);
    report(shared, &facts, decision);

    match decision {
        Decision::Block => {
            shared.stats.blocked.fetch_add(1, Ordering::Relaxed);
            // Dropping the stream sends a reset, which surfaces to the app as a
            // refused connection rather than a hang.
            drop(stream);
            Ok(())
        }
        Decision::Direct => {
            let mut upstream = dial::tcp(dest, &shared.iface()).await?;
            tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
            Ok(())
        }
        Decision::Proxy(config_id) => {
            let Some(cfg) = shared.find_proxy_config(config_id).cloned() else {
                // Configured to proxy but no proxy exists: go direct rather
                // than black-hole the flow.
                shared.stats.proxy_fallbacks.fetch_add(1, Ordering::Relaxed);
                let mut upstream = dial::tcp(dest, &shared.iface()).await?;
                tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
                return Ok(());
            };

            // Prefer the snooped hostname: the MITM proxy needs a name to issue
            // a certificate for and to send as SNI upstream. Falling back to the
            // IP literal still works for plaintext HTTP.
            let target = match (cfg.send_domain_to_proxy, domain) {
                (true, Some(d)) => Target::Domain(d, dest.port()),
                _ => Target::Ip(dest.ip(), dest.port()),
            };

            match proxy::connect_via_proxy(&cfg, &target).await {
                Ok(mut upstream) => {
                    tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
                    Ok(())
                }
                Err(e) => {
                    // The proxy is down or refused the tunnel. Blocking here
                    // would take the user's browser offline, so fall back to a
                    // direct connection and record that inspection was skipped.
                    shared.stats.proxy_fallbacks.fetch_add(1, Ordering::Relaxed);
                    shared.log(format!(
                        "proxy unavailable for {dest} ({e}); falling back to direct — \
                         this flow was NOT inspected"
                    ));
                    let mut upstream = dial::tcp(dest, &shared.iface()).await?;
                    tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
                    Ok(())
                }
            }
        }
    }
}

/// Relay one UDP flow, snooping DNS responses on the way back.
async fn handle_udp(mut stream: ipstack::IpStackUdpStream, shared: &Shared) -> std::io::Result<()> {
    let src = stream.local_addr();
    let dest = stream.peer_addr();

    let (pid, process_name) = attribute(src, dest, true);
    let domain = domain_for(shared, dest.ip());
    let facts = FlowFacts {
        dest,
        is_udp: true,
        pid,
        process_name: &process_name,
        domain: domain.as_deref(),
    };
    let decision = decide(shared, &facts);
    report(shared, &facts, decision);

    match decision {
        Decision::Block => {
            if dest.port() == shared.quic_port {
                shared.stats.quic_dropped.fetch_add(1, Ordering::Relaxed);
            } else if is_group_address(dest.ip()) {
                shared.stats.group_dropped.fetch_add(1, Ordering::Relaxed);
            } else {
                shared.stats.blocked.fetch_add(1, Ordering::Relaxed);
            }
            drop(stream);
            return Ok(());
        }
        // UDP is never tunnelled through an HTTP CONNECT proxy; a `Proxy` rule
        // on a UDP flow degrades to a direct relay so the flow still works.
        Decision::Direct | Decision::Proxy(_) => {}
    }

    let socket = dial::udp(dest, &shared.iface()).await?;
    let is_dns = dest.port() == 53;

    let mut from_client = vec![0u8; UDP_BUFFER];
    let mut from_server = vec![0u8; UDP_BUFFER];

    loop {
        tokio::select! {
            read = tokio::time::timeout(UDP_IDLE_TIMEOUT, stream.read(&mut from_client)) => {
                match read {
                    Err(_) => break,                       // idle timeout
                    Ok(Ok(0)) | Ok(Err(_)) => break,       // client closed
                    Ok(Ok(n)) => {
                        // A failed send loses one datagram; it must not end the
                        // flow. UDP is unreliable by contract, so the sender
                        // already has to cope with loss — whereas tearing the
                        // flow down turns a dropped packet into a broken
                        // connection. Windows returns WSAENOBUFS here whenever
                        // the socket's send queue is momentarily full, which is
                        // routine under load and entirely recoverable.
                        if let Err(e) = socket.send(&from_client[..n]).await {
                            shared.stats.udp_send_errors.fetch_add(1, Ordering::Relaxed);
                            tracing::debug!("dropping {n}-byte datagram to {dest}: {e}");
                        }
                    }
                }
            }
            recv = tokio::time::timeout(UDP_IDLE_TIMEOUT, socket.recv(&mut from_server)) => {
                match recv {
                    Err(_) => break,
                    // A receive error means this socket is done; unlike a send
                    // there is nothing to retry, so end the flow.
                    Ok(Err(_)) => break,
                    Ok(Ok(n)) => {
                        if is_dns {
                            // Build the IP -> hostname map that lets proxied
                            // flows be CONNECTed by name and lets domain rules
                            // match. This replaces the packet-layer DNS snoop
                            // the WinDivert build did.
                            shared.dns_cache.snoop_response(&from_server[..n]);
                        }
                        if stream.write_all(&from_server[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Emit the per-connection callback for a decided flow.
fn report(shared: &Shared, facts: &FlowFacts<'_>, decision: Decision) {
    if shared.conn_cb.is_none() {
        return;
    }
    let (action, proxy_info) = match decision {
        Decision::Direct => (RuleAction::Direct, "Direct".to_string()),
        Decision::Block => (RuleAction::Block, "Blocked".to_string()),
        Decision::Proxy(id) => {
            let desc = shared
                .find_proxy_config(id)
                .map(|c| format!("Proxy {:?}://{}:{}", c.proxy_type(), c.host(), c.port()))
                .unwrap_or_else(|| "Proxy (unconfigured)".to_string());
            (RuleAction::Proxy, desc)
        }
    };

    shared.report_connection(&ConnectionInfo {
        process_name: facts.process_name.to_string(),
        pid: facts.pid.unwrap_or(0),
        dest_ip: facts.dest.ip(),
        dest_port: facts.dest.port(),
        action,
        proxy_info,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyConfig;
    use crate::rule::{Rule, RuleProtocol};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn dest(ip: &str, port: u16) -> SocketAddr {
        format!("{ip}:{port}").parse().unwrap()
    }

    fn facts<'a>(d: SocketAddr, is_udp: bool, pid: Option<u32>, name: &'a str) -> FlowFacts<'a> {
        FlowFacts {
            dest: d,
            is_udp,
            pid,
            process_name: name,
            domain: None,
        }
    }

    /// Browser TCP 443 must reach the proxy — the core happy path.
    #[test]
    fn browser_tcp_443_goes_to_proxy() {
        let rules = [
            Rule::new("chrome.exe;brave.exe")
                .ports("80;443")
                .protocol(RuleProtocol::Tcp)
                .action(RuleAction::Proxy),
            Rule::new("*").action(RuleAction::Direct),
        ];
        let mut cfg = ProxyConfig::http("127.0.0.1", 8080);
        cfg.config_id = 1;
        let shared = Shared::new_for_test(&rules, vec![cfg]);

        let d = dest("140.82.113.4", 443);
        assert!(matches!(
            decide(&shared, &facts(d, false, Some(999), "brave.exe")),
            Decision::Proxy(_)
        ));
    }

    /// A non-browser doing TCP 443 falls through to the catch-all: direct.
    #[test]
    fn non_browser_tcp_is_direct() {
        let rules = [
            Rule::new("chrome.exe")
                .ports("443")
                .protocol(RuleProtocol::Tcp)
                .action(RuleAction::Proxy),
            Rule::new("*").action(RuleAction::Direct),
        ];
        let shared = Shared::new_for_test(&rules, vec![]);
        let d = dest("140.82.113.4", 443);
        assert_eq!(
            decide(&shared, &facts(d, false, Some(999), "curl.exe")),
            Decision::Direct
        );
    }

    /// The regression that motivated this rewrite: a flow whose owning process
    /// cannot be identified must still reach the internet, not be dropped.
    #[test]
    fn unattributed_tcp_flow_fails_open() {
        let rules = [
            Rule::new("chrome.exe")
                .ports("443")
                .protocol(RuleProtocol::Tcp)
                .action(RuleAction::Proxy),
            Rule::new("*").action(RuleAction::Direct),
        ];
        let shared = Shared::new_for_test(&rules, vec![]);
        let d = dest("140.82.113.4", 443);
        assert_eq!(
            decide(&shared, &facts(d, false, None, "")),
            Decision::Direct
        );
    }

    /// With no rules at all, everything still flows.
    #[test]
    fn empty_ruleset_fails_open() {
        let shared = Shared::new_for_test(&[], vec![]);
        let d = dest("1.1.1.1", 443);
        assert_eq!(
            decide(&shared, &facts(d, false, None, "")),
            Decision::Direct
        );
    }

    /// The other half of the regression: QUIC must be dropped even when the
    /// process is unknown, which is exactly the case that leaked before.
    #[test]
    fn unattributed_quic_is_dropped() {
        let rules = [Rule::new("*").action(RuleAction::Direct)];
        let shared = Shared::new_for_test(&rules, vec![]);
        let d = dest("157.240.1.35", 443);
        assert_eq!(decide(&shared, &facts(d, true, None, "")), Decision::Block);
    }

    /// QUIC over IPv6 is dropped too — IPv6 was a total bypass before.
    #[test]
    fn quic_over_ipv6_is_dropped() {
        let rules = [Rule::new("*").action(RuleAction::Direct)];
        let shared = Shared::new_for_test(&rules, vec![]);
        let d = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2a03, 0x2880, 0xf10c, 0, 0, 0, 0, 0x35)),
            443,
        );
        assert_eq!(decide(&shared, &facts(d, true, None, "")), Decision::Block);
    }

    /// A wildcard Direct rule must not resurrect QUIC.
    #[test]
    fn quic_drop_overrides_a_matching_direct_rule() {
        let rules = [Rule::new("*").action(RuleAction::Direct)];
        let shared = Shared::new_for_test(&rules, vec![]);
        let d = dest("157.240.1.35", 443);
        assert_eq!(
            decide(&shared, &facts(d, true, None, "chrome.exe")),
            Decision::Block
        );
    }

    /// mDNS, SSDP and LLMNR are dropped rather than relayed. Relaying them
    /// burned a pinned unicast socket per packet, which is what exhausted
    /// Windows' socket buffers (WSAENOBUFS) on a busy LAN.
    #[test]
    fn multicast_destinations_are_dropped() {
        let rules = [Rule::new("*").action(RuleAction::Direct)];
        let shared = Shared::new_for_test(&rules, vec![]);

        for (ip, port) in [
            ("224.0.0.251", 5353u16),  // mDNS
            ("239.255.255.250", 1900), // SSDP
            ("224.0.0.252", 5355),     // LLMNR
        ] {
            assert_eq!(
                decide(&shared, &facts(dest(ip, port), true, Some(9), "")),
                Decision::Block,
                "{ip}:{port} should be dropped"
            );
        }
    }

    /// Broadcast (DHCP, NetBIOS) is dropped for the same reason.
    #[test]
    fn broadcast_destinations_are_dropped() {
        let rules = [Rule::new("*").action(RuleAction::Direct)];
        let shared = Shared::new_for_test(&rules, vec![]);
        assert_eq!(
            decide(
                &shared,
                &facts(dest("255.255.255.255", 67), true, Some(9), "")
            ),
            Decision::Block
        );
    }

    /// IPv6 multicast (ff00::/8) too — neighbour discovery, mDNS over v6.
    #[test]
    fn ipv6_multicast_is_dropped() {
        let rules = [Rule::new("*").action(RuleAction::Direct)];
        let shared = Shared::new_for_test(&rules, vec![]);
        let d = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
            5353,
        );
        assert_eq!(
            decide(&shared, &facts(d, true, Some(9), "")),
            Decision::Block
        );
    }

    /// Ordinary unicast must not be caught by the group-address check — that
    /// would black-hole normal traffic.
    #[test]
    fn unicast_is_not_treated_as_a_group_address() {
        assert!(!is_group_address("140.82.113.4".parse().unwrap()));
        assert!(!is_group_address("8.8.8.8".parse().unwrap()));
        assert!(!is_group_address("2606:50c0:8000::153".parse().unwrap()));
        // 223.x is the last unicast /8 before the 224.0.0.0/4 multicast range.
        assert!(!is_group_address("223.255.255.255".parse().unwrap()));
        assert!(is_group_address("224.0.0.0".parse().unwrap()));
    }

    /// Non-QUIC UDP (e.g. DNS) is unaffected by the QUIC policy.
    #[test]
    fn dns_udp_is_not_dropped() {
        let rules = [Rule::new("*").action(RuleAction::Direct)];
        let shared = Shared::new_for_test(&rules, vec![]);
        let d = dest("1.1.1.1", 53);
        assert_eq!(decide(&shared, &facts(d, true, None, "")), Decision::Direct);
    }

    /// Allowing QUIC must actually let it through, so the policy is real.
    #[test]
    fn quic_allow_policy_lets_it_through() {
        let rules = [Rule::new("*").action(RuleAction::Direct)];
        let mut shared = Shared::new_for_test(&rules, vec![]);
        shared.quic_policy = QuicPolicy::Allow;
        let d = dest("157.240.1.35", 443);
        assert_eq!(decide(&shared, &facts(d, true, None, "")), Decision::Direct);
    }

    /// The loop guard: our own traffic is never sent back to the proxy, even
    /// when a rule says every process should be proxied.
    #[test]
    fn own_process_always_goes_direct() {
        let rules = [Rule::new("*")
            .protocol(RuleProtocol::Tcp)
            .action(RuleAction::Proxy)];
        let mut cfg = ProxyConfig::http("127.0.0.1", 8080);
        cfg.config_id = 1;
        let shared = Shared::new_for_test(&rules, vec![cfg]);

        let me = shared.current_pid;
        let d = dest("140.82.113.4", 443);
        assert_eq!(
            decide(&shared, &facts(d, false, Some(me), "ace-engine.exe")),
            Decision::Direct
        );
    }

    /// Our own process is exempt from Block rules as well, or a VPN-process
    /// rule matching our name would sever the engine from the internet.
    #[test]
    fn own_process_bypasses_block_rules() {
        let rules = [Rule::new("*").action(RuleAction::Block)];
        let shared = Shared::new_for_test(&rules, vec![]);
        let me = shared.current_pid;
        let d = dest("140.82.113.4", 443);
        assert_eq!(
            decide(&shared, &facts(d, false, Some(me), "")),
            Decision::Direct
        );
    }

    /// Even our own QUIC goes direct — the loop guard runs before the QUIC drop.
    #[test]
    fn own_process_quic_is_not_dropped() {
        let shared = Shared::new_for_test(&[], vec![]);
        let me = shared.current_pid;
        let d = dest("1.1.1.1", 443);
        assert_eq!(
            decide(&shared, &facts(d, true, Some(me), "")),
            Decision::Direct
        );
    }

    /// With an interface to pin to, our own traffic is relayed directly —
    /// the normal case, and the counterpart to the drop test below.
    #[test]
    fn own_process_goes_direct_when_an_interface_exists() {
        let shared = Shared::new_for_test(&[], vec![]);
        let me = shared.current_pid;
        let d = dest("140.82.113.4", 443);
        assert_eq!(
            decide(&shared, &facts(d, false, Some(me), "")),
            Decision::Direct
        );
    }

    /// Without one, relaying our own flow would loop forever, so it is dropped.
    #[test]
    fn own_process_is_dropped_when_there_is_nothing_to_pin_to() {
        let shared = Shared::new_for_test_without_interface(&[], vec![]);
        let me = shared.current_pid;
        let d = dest("140.82.113.4", 443);
        assert_eq!(
            decide(&shared, &facts(d, false, Some(me), "")),
            Decision::Block
        );
    }

    /// Our own loopback traffic (e.g. reaching the local proxy) is never at
    /// risk of looping, so it is relayed even with no interface known.
    #[test]
    fn own_process_loopback_is_direct_without_an_interface() {
        let shared = Shared::new_for_test_without_interface(&[], vec![]);
        let me = shared.current_pid;
        let d = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert_eq!(
            decide(&shared, &facts(d, false, Some(me), "")),
            Decision::Direct
        );
    }

    /// Loopback stays local regardless of rules.
    #[test]
    fn loopback_is_direct() {
        let rules = [Rule::new("*")
            .protocol(RuleProtocol::Tcp)
            .action(RuleAction::Proxy)];
        let mut cfg = ProxyConfig::http("127.0.0.1", 8080);
        cfg.config_id = 1;
        let shared = Shared::new_for_test(&rules, vec![cfg]);
        let d = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert_eq!(
            decide(&shared, &facts(d, false, Some(1), "chrome.exe")),
            Decision::Direct
        );
    }

    /// A VPN executable is blocked outright, on both transports.
    #[test]
    fn vpn_process_is_blocked() {
        let rules = [
            Rule::new("openvpn.exe;wireguard.exe").action(RuleAction::Block),
            Rule::new("*").action(RuleAction::Direct),
        ];
        let shared = Shared::new_for_test(&rules, vec![]);
        let d = dest("203.0.113.9", 1194);
        assert_eq!(
            decide(&shared, &facts(d, false, Some(42), "openvpn.exe")),
            Decision::Block
        );
        assert_eq!(
            decide(&shared, &facts(d, true, Some(42), "wireguard.exe")),
            Decision::Block
        );
    }

    /// Domain rules still work, now fed by the UDP-flow DNS snoop.
    #[test]
    fn domain_rule_blocks_by_snooped_hostname() {
        let rules = [
            Rule::new("*")
                .domains("*.protonvpn.com")
                .action(RuleAction::Block),
            Rule::new("*").action(RuleAction::Direct),
        ];
        let shared = Shared::new_for_test(&rules, vec![]);
        let d = dest("185.159.157.1", 443);

        let mut f = facts(d, false, Some(7), "chrome.exe");
        f.domain = Some("api.protonvpn.com");
        assert_eq!(decide(&shared, &f), Decision::Block);

        let mut f2 = facts(d, false, Some(7), "chrome.exe");
        f2.domain = Some("github.com");
        assert_eq!(decide(&shared, &f2), Decision::Direct);
    }

    /// IPv6 browser traffic is proxied exactly like IPv4 — under WinDivert it
    /// bypassed interception entirely.
    #[test]
    fn ipv6_browser_traffic_is_proxied() {
        let rules = [
            Rule::new("chrome.exe")
                .ports("443")
                .protocol(RuleProtocol::Tcp)
                .action(RuleAction::Proxy),
            Rule::new("*").action(RuleAction::Direct),
        ];
        let mut cfg = ProxyConfig::http("127.0.0.1", 8080);
        cfg.config_id = 1;
        let shared = Shared::new_for_test(&rules, vec![cfg]);

        let d = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x50c0, 0x8000, 0, 0, 0, 0, 0x153)),
            443,
        );
        assert!(matches!(
            decide(&shared, &facts(d, false, Some(3), "chrome.exe")),
            Decision::Proxy(_)
        ));
    }
}
