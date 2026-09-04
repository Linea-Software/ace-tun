//! Shared, immutable-after-start engine state.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::callback::{ConnectionCallback, ConnectionInfo, LogCallback};
use crate::config::ProxyConfig;
use crate::dns::DnsCache;
use crate::platform::PhysicalInterface;
use crate::rule::RuleSet;

/// What to do with QUIC (UDP on [`Shared::quic_port`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicPolicy {
    /// Drop QUIC datagrams so clients fall back to TCP, which the MITM proxy
    /// inspects reliably. This is the default and the recommended setting.
    Drop,
    /// Let QUIC through untouched. Only sensible if you have accepted that
    /// HTTP/3 traffic is not inspected.
    Allow,
}

/// Counters for diagnostics. Cheap enough to update on every flow.
#[derive(Debug, Default)]
pub(crate) struct Stats {
    pub(crate) tcp_flows: AtomicU64,
    pub(crate) udp_flows: AtomicU64,
    pub(crate) blocked: AtomicU64,
    pub(crate) quic_dropped: AtomicU64,
    pub(crate) proxy_fallbacks: AtomicU64,
    pub(crate) group_dropped: AtomicU64,
    pub(crate) udp_send_errors: AtomicU64,
}

/// A snapshot of [`Stats`], returned by [`crate::TunRedirect::stats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatsSnapshot {
    /// TCP flows accepted from the tunnel.
    pub tcp_flows: u64,
    /// UDP flows accepted from the tunnel.
    pub udp_flows: u64,
    /// Flows dropped because a `Block` rule matched.
    pub blocked: u64,
    /// QUIC datagrams dropped to force a TCP fallback.
    pub quic_dropped: u64,
    /// Legacy-named counter for flows that could not reach their required
    /// proxy. Such flows are fail-closed and do not fall back to direct.
    pub proxy_fallbacks: u64,
    /// Multicast/broadcast flows dropped rather than relayed (mDNS, SSDP,
    /// LLMNR). Expect this to climb steadily on a busy LAN; it is normal.
    pub group_dropped: u64,
    /// Individual datagrams lost to a send error. Routine in small numbers —
    /// UDP is lossy — but a fast-rising count suggests socket-buffer pressure.
    pub udp_send_errors: u64,
}

pub(crate) struct Shared {
    pub(crate) rules: RuleSet,
    pub(crate) proxy_configs: Vec<ProxyConfig>,
    pub(crate) dns_cache: DnsCache,
    pub(crate) localhost_via_proxy: bool,
    /// UDP port treated as QUIC, normally 443.
    pub(crate) quic_port: u16,
    pub(crate) quic_policy: QuicPolicy,
    /// Our own PID. Flows owned by it always go direct, which is what keeps the
    /// engine's upstream traffic from re-entering the tunnel.
    pub(crate) current_pid: u32,
    /// The physical NIC that outbound sockets are pinned to. Discovered once,
    /// at start, before our own routes exist — see [`Shared::iface`].
    pub(crate) iface: OnceLock<PhysicalInterface>,
    pub(crate) stats: Stats,
    pub(crate) log_cb: Option<LogCallback>,
    pub(crate) conn_cb: Option<ConnectionCallback>,
    pub(crate) running: AtomicBool,
}

impl Shared {
    pub(crate) fn log(&self, msg: impl AsRef<str>) {
        let msg = msg.as_ref();
        tracing::debug!("{msg}");
        if let Some(cb) = &self.log_cb {
            cb(msg);
        }
    }

    /// The interface outbound sockets are pinned to.
    ///
    /// Before `start` has discovered one this is empty, which makes dials fall
    /// back to normal routing — correct, because there is no tunnel yet either.
    pub(crate) fn iface(&self) -> PhysicalInterface {
        self.iface.get().copied().unwrap_or_default()
    }

    pub(crate) fn report_connection(&self, info: &ConnectionInfo) {
        if let Some(cb) = &self.conn_cb {
            cb(info);
        }
    }

    /// Look up a registered proxy config by id, falling back to the first
    /// registered one when the rule did not name a specific config.
    pub(crate) fn find_proxy_config(&self, id: u32) -> Option<&ProxyConfig> {
        self.proxy_configs
            .iter()
            .find(|c| c.config_id() == id)
            .or_else(|| self.proxy_configs.first())
    }

    pub(crate) fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            tcp_flows: self.stats.tcp_flows.load(Ordering::Relaxed),
            udp_flows: self.stats.udp_flows.load(Ordering::Relaxed),
            blocked: self.stats.blocked.load(Ordering::Relaxed),
            quic_dropped: self.stats.quic_dropped.load(Ordering::Relaxed),
            proxy_fallbacks: self.stats.proxy_fallbacks.load(Ordering::Relaxed),
            group_dropped: self.stats.group_dropped.load(Ordering::Relaxed),
            udp_send_errors: self.stats.udp_send_errors.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
impl Shared {
    /// Build a minimal `Shared` for unit tests, with a physical interface
    /// present — the normal running state.
    pub(crate) fn new_for_test(rules: &[crate::rule::Rule], configs: Vec<ProxyConfig>) -> Self {
        let shared = Self::new_for_test_without_interface(rules, configs);
        shared
            .iface
            .set(PhysicalInterface {
                v4_index: Some(12),
                v6_index: Some(12),
            })
            .expect("iface is unset in a fresh fixture");
        shared
    }

    /// As [`Shared::new_for_test`], but with no interface discovered — the
    /// degraded state in which our own flows must be dropped rather than looped.
    pub(crate) fn new_for_test_without_interface(
        rules: &[crate::rule::Rule],
        configs: Vec<ProxyConfig>,
    ) -> Self {
        Self {
            rules: RuleSet::new(rules),
            proxy_configs: configs,
            dns_cache: DnsCache::default(),
            localhost_via_proxy: false,
            quic_port: 443,
            quic_policy: QuicPolicy::Drop,
            current_pid: std::process::id(),
            iface: OnceLock::new(),
            stats: Stats::default(),
            log_cb: None,
            conn_cb: None,
            running: AtomicBool::new(true),
        }
    }
}
