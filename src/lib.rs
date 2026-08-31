//! `ace-tun` — a transparent redirect over a virtual network adapter.
//!
//! The engine creates a virtual network adapter (WinTun on Windows, a TUN
//! device on Linux/macOS), points the routing table at it, and runs a userland
//! TCP/IP stack over the raw IP packets that arrive. Each flow is terminated
//! locally, matched against a rule set, and then either relayed through an
//! upstream MITM proxy, connected straight out, or dropped.
//!
//! ```text
//!   app ──routes──▶ TUN adapter ──▶ userland netstack ──┬─▶ MITM proxy ──▶ internet
//!                                                       └─▶ direct socket ─▶ internet
//! ```
//!
//! # Why not packet interception
//!
//! This crate replaces a WinDivert-based design that intercepted individual
//! packets and reverse-mapped each one to its owning process. That approach had
//! three structural problems, all of which disappear here rather than being
//! patched:
//!
//! * **Attribution races.** Deciding a packet's fate required a
//!   `GetExtendedUdpTable` lookup that raced with UDP socket setup. A miss meant
//!   the flow was passed through uninspected, which is how HTTP/3 traffic leaked
//!   past blocking. Here, attribution happens once per *flow*, at open, after
//!   the socket demonstrably exists.
//! * **No original destination.** Packet-level redirection had to rewrite
//!   addresses and keep a NAT table to remember where each connection was really
//!   going. Under a TUN the destination is simply in the IP header of the SYN.
//! * **IPv4 only.** The capture filter never matched IPv6, so all of it bypassed
//!   interception. The netstack handles both families identically.
//!
//! # Failure behaviour
//!
//! The engine is built to fail open. Every error path — process lookup failure,
//! empty rule set, unreachable upstream proxy — results in traffic flowing. The
//! sole exception is QUIC, which is dropped so clients fall back to TCP; that is
//! "fail closed" only in the narrow sense that the site still loads, over an
//! inspected transport.
//!
//! Teardown is likewise defensive. Routes are removed on stop, on drop, and on
//! netstack panic. If the process dies without running any of that, Windows
//! closes the adapter handle, the adapter disappears, and the routes bound to it
//! go with it — so a hard kill restores normal connectivity by itself.
//!
//! # Requirements
//!
//! * Administrator/root privileges (creating a virtual adapter requires them).
//!   [`TunRedirect::start`] returns [`Error::NotElevated`] rather than failing
//!   obscurely, so callers can degrade gracefully.
//! * On Windows, `wintun.dll` next to the executable. It is WireGuard's signed,
//!   permissively licensed user-mode library; see `README.md` for bundling
//!   notes.
//!
//! # Known gaps
//!
//! ICMP is not proxied: `ping` to an off-link address will not get a reply while
//! the tunnel is up. TCP and UDP are unaffected. This is the one behaviour the
//! WinDivert build passed through that this one does not.
//!
//! # Example
//!
//! ```no_run
//! use ace_tun::{TunRedirect, ProxyConfig, Rule, RuleAction, RuleProtocol};
//!
//! # async fn run() -> ace_tun::Result<()> {
//! let redirect = TunRedirect::builder("127.0.0.1:8080")?
//!     .add_rule(Rule::new("chrome.exe;brave.exe")
//!         .ports("80;443")
//!         .protocol(RuleProtocol::Tcp)
//!         .action(RuleAction::Proxy))
//!     .add_rule(Rule::new("*").action(RuleAction::Direct))
//!     .proxy_config(ProxyConfig::http("127.0.0.1", 8080))
//!     .build()?;
//!
//! redirect.start().await?;
//! // ... later ...
//! redirect.stop().await?;
//! # Ok(())
//! # }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

mod callback;
mod config;
mod device;
mod dial;
mod dns;
mod error;
mod netstack;
mod platform;
mod proxy;
mod rule;
mod state;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ipstack::{IpStack, IpStackConfig, TcpConfig};
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub use callback::{ConnectionCallback, ConnectionInfo, LogCallback};
pub use config::{ProxyConfig, ProxyType};
pub use dns::DnsCache;
pub use error::{Error, Result};
pub use platform::{ADAPTER_NAME, PhysicalInterface, TUN_IPV4, TUN_IPV6, TUN_MTU};
pub use rule::{Rule, RuleAction, RuleMatch, RuleProtocol, RuleSet};
pub use state::{QuicPolicy, StatsSnapshot};

use device::{ReaderHandle, TunDevice};
use platform::{AdapterHandle, Backend, BackendImpl, TunAdapter};
use state::{Shared, Stats};

/// Default UDP port treated as QUIC.
const DEFAULT_QUIC_PORT: u16 = 443;

/// Idle time (seconds) before ipstack force-closes an established TCP
/// connection with an RST. Raised from ipstack's 60s default, which silently
/// killed long-poll and websocket connections (Zoho Mail's push channel).
const TCP_SESSION_TIMEOUT_SECS: u64 = 15 * 60;

/// Builder for a [`TunRedirect`].
///
/// Created via [`TunRedirect::builder`].
pub struct TunRedirectBuilder {
    proxy_addr: SocketAddr,
    rules: Vec<Rule>,
    proxy_configs: Vec<ProxyConfig>,
    quic_port: u16,
    quic_policy: QuicPolicy,
    ipv6: bool,
    localhost_via_proxy: bool,
    log_cb: Option<LogCallback>,
    conn_cb: Option<ConnectionCallback>,
}

impl TunRedirectBuilder {
    fn new(proxy_addr: SocketAddr) -> Self {
        Self {
            proxy_addr,
            rules: Vec::new(),
            proxy_configs: Vec::new(),
            quic_port: DEFAULT_QUIC_PORT,
            quic_policy: QuicPolicy::Drop,
            ipv6: true,
            localhost_via_proxy: false,
            log_cb: None,
            conn_cb: None,
        }
    }

    /// Append a routing rule. Rules are evaluated in insertion order.
    pub fn add_rule(mut self, rule: Rule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Append several rules at once.
    pub fn add_rules(mut self, rules: impl IntoIterator<Item = Rule>) -> Self {
        self.rules.extend(rules);
        self
    }

    /// Register an upstream proxy configuration. The first one registered is
    /// the default used by `Proxy` rules that don't name a specific config.
    ///
    /// If none is registered, an HTTP proxy at the builder's address is used.
    pub fn proxy_config(mut self, config: ProxyConfig) -> Self {
        self.proxy_configs.push(config);
        self
    }

    /// Set the UDP port treated as QUIC (default 443).
    pub fn quic_port(mut self, port: u16) -> Self {
        self.quic_port = port;
        self
    }

    /// Choose whether QUIC is dropped (default) or allowed through.
    ///
    /// Dropping is strongly recommended: it forces clients onto TCP, which the
    /// MITM proxy inspects. [`QuicPolicy::Allow`] means HTTP/3 traffic is not
    /// inspected at all and block rules will not apply to it.
    pub fn quic_policy(mut self, policy: QuicPolicy) -> Self {
        self.quic_policy = policy;
        self
    }

    /// Enable or disable IPv6 interception (default enabled).
    ///
    /// When disabled, the adapter carries no IPv6 address or routes, so IPv6
    /// traffic continues to use the physical interface **uninspected**. Leave
    /// this on unless you are debugging.
    pub fn ipv6(mut self, enable: bool) -> Self {
        self.ipv6 = enable;
        self
    }

    /// Allow loopback destinations to be routed through the proxy. Disabled by
    /// default (loopback goes direct even if a `Proxy` rule matches).
    pub fn localhost_via_proxy(mut self, enable: bool) -> Self {
        self.localhost_via_proxy = enable;
        self
    }

    /// Register a log sink for human-readable diagnostics.
    pub fn on_log<F>(mut self, callback: F) -> Self
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        self.log_cb = Some(Box::new(callback));
        self
    }

    /// Register a per-connection callback, invoked once on each new flow.
    pub fn on_connection<F>(mut self, callback: F) -> Self
    where
        F: Fn(&ConnectionInfo) + Send + Sync + 'static,
    {
        self.conn_cb = Some(Box::new(callback));
        self
    }

    /// Validate the configuration and build a ready-to-start [`TunRedirect`].
    pub fn build(self) -> Result<TunRedirect> {
        // Synthesize a default HTTP proxy from the builder address if the caller
        // registered none.
        let mut proxy_configs = self.proxy_configs;
        if proxy_configs.is_empty() {
            proxy_configs.push(ProxyConfig::http(
                self.proxy_addr.ip().to_string(),
                self.proxy_addr.port(),
            ));
        }
        // Assign stable 1-based ids and validate.
        for (i, cfg) in proxy_configs.iter_mut().enumerate() {
            cfg.config_id = (i + 1) as u32;
            cfg.validate()?;
        }

        let shared = Arc::new(Shared {
            rules: RuleSet::new(&self.rules),
            proxy_configs,
            dns_cache: DnsCache::default(),
            localhost_via_proxy: self.localhost_via_proxy,
            quic_port: self.quic_port,
            quic_policy: self.quic_policy,
            current_pid: std::process::id(),
            // Populated at start(), before the adapter exists.
            iface: OnceLock::new(),
            stats: Stats::default(),
            log_cb: self.log_cb,
            conn_cb: self.conn_cb,
            running: AtomicBool::new(false),
        });

        Ok(TunRedirect {
            shared,
            ipv6: self.ipv6,
            running: Mutex::new(None),
        })
    }
}

/// A configured (and startable) transparent redirect engine.
pub struct TunRedirect {
    shared: Arc<Shared>,
    ipv6: bool,
    running: Mutex<Option<RunState>>,
}

/// Live resources held while the engine is running.
struct RunState {
    /// Shared with the watchdog so whichever of the two runs first tears the
    /// adapter down, exactly once.
    adapter: Arc<Mutex<Option<TunAdapter>>>,
    shutdown_tx: watch::Sender<bool>,
    watchdog: JoinHandle<()>,
}

impl TunRedirect {
    /// Begin building a redirect that sends matched traffic to `proxy_addr`
    /// (e.g. `"127.0.0.1:8080"`), the address of the local MITM proxy.
    pub fn builder(proxy_addr: impl AsRef<str>) -> Result<TunRedirectBuilder> {
        let input = proxy_addr.as_ref();
        let addr: SocketAddr = input.parse().map_err(|source| Error::InvalidAddress {
            input: input.to_string(),
            source,
        })?;
        Ok(TunRedirectBuilder::new(addr))
    }

    /// Access the DNS snoop cache (useful for diagnostics / metrics).
    pub fn dns_cache(&self) -> &DnsCache {
        &self.shared.dns_cache
    }

    /// Current flow counters.
    ///
    /// A rising [`StatsSnapshot::proxy_fallbacks`] means flows are reaching the
    /// internet without being inspected because the proxy was unreachable.
    pub fn stats(&self) -> StatsSnapshot {
        self.shared.snapshot()
    }

    /// Whether the engine is currently running.
    pub fn is_running(&self) -> bool {
        self.running.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Create the adapter, install routes, and begin intercepting.
    ///
    /// Requires administrator privileges; returns [`Error::NotElevated`] if the
    /// process is not elevated, leaving the machine's networking untouched.
    /// Must be called from within a Tokio runtime.
    pub async fn start(&self) -> Result<()> {
        if self
            .shared
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::AlreadyRunning);
        }

        match self.start_inner() {
            Ok(state) => {
                *self.running.lock().expect("running lock poisoned") = Some(state);
                Ok(())
            }
            Err(e) => {
                self.shared.running.store(false, Ordering::Release);
                Err(e)
            }
        }
    }

    fn start_inner(&self) -> Result<RunState> {
        // Discover the internet-facing NIC *before* our routes exist, so the
        // answer describes the real network rather than our own tunnel. Every
        // outbound socket is pinned to it; this is the loop guard.
        let iface = PhysicalInterface::discover();
        if iface.is_empty() {
            // No connectivity to begin with. Diverting traffic now would only
            // make a disconnected machine look broken in a new way.
            return Err(Error::netcfg(
                "discover_physical_interface",
                std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "no internet-facing interface found",
                ),
            ));
        }
        // Ignore a second set: `running` already guarantees one start at a time,
        // and the value would be identical anyway.
        let _ = self.shared.iface.set(iface);

        let tun = BackendImpl::create(self.ipv6, &iface)?;
        self.shared.log(format!(
            "adapter '{ADAPTER_NAME}' up: {TUN_IPV4} (mtu {TUN_MTU}); \
             outbound traffic pinned to interface v4={:?} v6={:?}",
            iface.v4_index, iface.v6_index
        ));

        let (device, reader) = TunDevice::new(tun.session()?)?;

        let mut cfg = IpStackConfig::default();
        cfg.mtu_unchecked(TUN_MTU);
        // ipstack's default TCP session timeout is 60s: any established
        // connection that carries no data for a full minute is force-closed
        // with an RST. That silently kills exactly the connections that must
        // stay quiet: long-polls (Zoho Mail's push channel re-polls every
        // ~30-60s), websockets without heartbeats, and ordinary keep-alives.
        // 15 minutes still reaps zombie connections while leaving every
        // realistic idle pattern alone.
        cfg.with_tcp_config({
            let mut tcp_config = TcpConfig::default();
            tcp_config.timeout = Duration::from_secs(TCP_SESSION_TIMEOUT_SECS);
            tcp_config
        });
        let stack = IpStack::new(cfg, device);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let netstack_task =
            tokio::spawn(netstack::run(stack, Arc::clone(&self.shared), shutdown_rx));

        let adapter = Arc::new(Mutex::new(Some(tun)));
        let watchdog = tokio::spawn(watchdog(
            netstack_task,
            reader,
            Arc::clone(&adapter),
            Arc::clone(&self.shared),
        ));

        Ok(RunState {
            adapter,
            shutdown_tx,
            watchdog,
        })
    }

    /// Stop intercepting: remove the routes, delete the adapter, and release
    /// every resource. Subsequent calls return [`Error::NotRunning`].
    pub async fn stop(&self) -> Result<()> {
        let state = {
            let mut guard = self.running.lock().expect("running lock poisoned");
            guard.take().ok_or(Error::NotRunning)?
        };

        self.shared.running.store(false, Ordering::Release);
        let _ = state.shutdown_tx.send(true);

        // The watchdog performs the actual teardown, whichever way the netstack
        // ended, so waiting for it is waiting for a restored routing table.
        if let Err(e) = state.watchdog.await {
            // The watchdog itself failed. Tear down here so we cannot possibly
            // leave the adapter in place.
            tracing::error!("teardown watchdog failed ({e}); removing adapter directly");
            if let Some(mut tun) = state.adapter.lock().ok().and_then(|mut g| g.take()) {
                tun.remove_routes();
                tun.shutdown_session();
            }
        }

        self.shared.log("stopped");
        Ok(())
    }
}

/// Supervise the netstack and guarantee teardown.
///
/// This runs on *every* exit path, not just a clean stop: if the netstack task
/// panics, the adapter still goes away and the machine still has internet. That
/// is the difference between a bug and an outage.
async fn watchdog(
    netstack_task: JoinHandle<()>,
    reader: ReaderHandle,
    adapter: Arc<Mutex<Option<TunAdapter>>>,
    shared: Arc<Shared>,
) {
    match netstack_task.await {
        Ok(()) => tracing::debug!("netstack task finished"),
        Err(e) if e.is_panic() => {
            tracing::error!("netstack PANICKED ({e}); tearing down tunnel to restore connectivity");
        }
        Err(e) => tracing::debug!("netstack task cancelled: {e}"),
    }

    // Dropping the adapter removes the routes, shuts the session down (which
    // unblocks the reader thread), and closes the adapter handle.
    if let Some(mut tun) = adapter.lock().ok().and_then(|mut g| g.take()) {
        tun.remove_routes();
        tun.shutdown_session();
        drop(tun);
    }

    // Join off the async executor: the reader thread is blocking.
    let _ = tokio::task::spawn_blocking(move || reader.join()).await;
    shared.log("tunnel torn down; routing restored");
}

impl Drop for TunRedirect {
    /// Best-effort synchronous teardown for callers that drop without stopping.
    ///
    /// This cannot await, so it removes the routes and adapter directly and
    /// aborts the supervisor. The reader thread exits on its own once the
    /// session is gone.
    fn drop(&mut self) {
        let Ok(mut guard) = self.running.lock() else {
            return;
        };
        let Some(state) = guard.take() else {
            return;
        };

        self.shared.running.store(false, Ordering::Release);
        let _ = state.shutdown_tx.send(true);

        if let Some(mut tun) = state.adapter.lock().ok().and_then(|mut g| g.take()) {
            tun.remove_routes();
            tun.shutdown_session();
        }
        state.watchdog.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_a_malformed_address() {
        // `TunRedirectBuilder` is not `Debug`, so match rather than unwrap_err.
        match TunRedirect::builder("not-an-address") {
            Err(Error::InvalidAddress { .. }) => {}
            other => panic!("expected InvalidAddress, got {:?}", other.err()),
        }
    }

    #[test]
    fn builder_synthesizes_a_proxy_config_from_the_listen_address() {
        let redirect = TunRedirect::builder("127.0.0.1:8080")
            .unwrap()
            .build()
            .unwrap();
        let cfg = redirect
            .shared
            .find_proxy_config(1)
            .expect("default config");
        assert_eq!(cfg.host(), "127.0.0.1");
        assert_eq!(cfg.port(), 8080);
        assert_eq!(cfg.config_id(), 1);
    }

    #[test]
    fn registered_proxy_configs_get_stable_ids() {
        let redirect = TunRedirect::builder("127.0.0.1:1")
            .unwrap()
            .proxy_config(ProxyConfig::http("127.0.0.1", 8080))
            .proxy_config(ProxyConfig::socks5("127.0.0.1", 1080))
            .build()
            .unwrap();
        assert_eq!(redirect.shared.find_proxy_config(1).unwrap().port(), 8080);
        assert_eq!(redirect.shared.find_proxy_config(2).unwrap().port(), 1080);
    }

    #[test]
    fn a_zero_port_proxy_config_is_rejected() {
        let built = TunRedirect::builder("127.0.0.1:1")
            .unwrap()
            .proxy_config(ProxyConfig::http("127.0.0.1", 0))
            .build();
        match built {
            Err(Error::Config(_)) => {}
            other => panic!("expected Config error, got {:?}", other.err()),
        }
    }

    #[test]
    fn quic_is_dropped_by_default() {
        let redirect = TunRedirect::builder("127.0.0.1:1")
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(redirect.shared.quic_policy, QuicPolicy::Drop);
        assert_eq!(redirect.shared.quic_port, 443);
    }

    /// IPv6 defaulting to off would silently reintroduce the bypass this
    /// rewrite exists to close.
    #[test]
    fn ipv6_is_enabled_by_default() {
        let redirect = TunRedirect::builder("127.0.0.1:1")
            .unwrap()
            .build()
            .unwrap();
        assert!(redirect.ipv6);
    }

    #[test]
    fn a_fresh_engine_is_not_running() {
        let redirect = TunRedirect::builder("127.0.0.1:1")
            .unwrap()
            .build()
            .unwrap();
        assert!(!redirect.is_running());
        assert_eq!(redirect.stats(), StatsSnapshot::default());
    }

    #[tokio::test]
    async fn stopping_an_idle_engine_reports_not_running() {
        let redirect = TunRedirect::builder("127.0.0.1:1")
            .unwrap()
            .build()
            .unwrap();
        assert!(matches!(redirect.stop().await, Err(Error::NotRunning)));
    }

    /// Dropping an engine that never started must not panic or touch the
    /// machine's routing.
    #[test]
    fn dropping_an_unstarted_engine_is_a_no_op() {
        let redirect = TunRedirect::builder("127.0.0.1:1")
            .unwrap()
            .build()
            .unwrap();
        drop(redirect);
    }
}
