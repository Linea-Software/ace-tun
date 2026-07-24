//! Log and connection callback types.
//!
//! These mirror the `LogCallback` / `ConnectionCallback` hooks exposed by the
//! original ProxyBridge C DLL, but use owned Rust types instead of raw C
//! strings. Callbacks are stored as boxed closures so callers can capture
//! state (channels, counters, loggers) instead of relying on globals.

use std::net::IpAddr;

use crate::rule::RuleAction;

/// A log message sink. Invoked for human-readable diagnostic lines emitted by
/// the engine (equivalent to ProxyBridge's `LogCallback`).
pub type LogCallback = Box<dyn Fn(&str) + Send + Sync + 'static>;

/// Details about a single intercepted connection, passed to the
/// [`ConnectionCallback`] on the first packet (SYN) of a new flow.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Executable file name of the originating process (e.g. `chrome.exe`).
    pub process_name: String,
    /// Process id that owns the local endpoint.
    pub pid: u32,
    /// Original destination address the process tried to reach.
    pub dest_ip: IpAddr,
    /// Original destination port.
    pub dest_port: u16,
    /// The action the rule engine selected for this connection.
    pub action: RuleAction,
    /// Human-readable proxy description, e.g. `Proxy HTTP://127.0.0.1:8080`,
    /// `Direct`, or `Blocked`.
    pub proxy_info: String,
}

/// A connection sink. Invoked once per new intercepted flow (equivalent to
/// ProxyBridge's `ConnectionCallback`).
pub type ConnectionCallback = Box<dyn Fn(&ConnectionInfo) + Send + Sync + 'static>;
