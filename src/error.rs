//! Error and result types for `ace-tun`.

use std::net::AddrParseError;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur while configuring or running a [`crate::TunRedirect`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The supplied local proxy / listen address could not be parsed.
    #[error("invalid address '{input}': {source}")]
    InvalidAddress {
        /// The offending input string.
        input: String,
        /// The underlying parse error.
        #[source]
        source: AddrParseError,
    },

    /// A rule or proxy config was rejected during validation.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// No proxy configuration was supplied but a rule requested `Proxy`.
    #[error("no proxy configuration available for a Proxy rule")]
    MissingProxyConfig,

    /// `wintun.dll` could not be loaded (missing next to the executable, wrong
    /// architecture, …).
    #[error("failed to load wintun.dll: {0}")]
    WintunLoad(String),

    /// Creating or opening the WinTun adapter failed. Almost always either "not
    /// elevated" or "the WinTun driver could not be installed".
    #[error("failed to create WinTun adapter '{name}': {reason}")]
    AdapterCreate {
        /// Adapter name that was requested.
        name: String,
        /// Underlying wintun error text.
        reason: String,
    },

    /// Starting the adapter's ring-buffer session failed.
    #[error("failed to start WinTun session: {0}")]
    SessionStart(String),

    /// Assigning an address, route, or interface parameter failed.
    #[error("network configuration failed ({op}): {source}")]
    NetConfig {
        /// The operation that failed, e.g. `add_route(0.0.0.0/1)`.
        op: String,
        /// The underlying Win32 error.
        #[source]
        source: std::io::Error,
    },

    /// The process is not running elevated, which WinTun requires.
    #[error("administrator privileges are required to create a WinTun adapter")]
    NotElevated,

    /// The redirect engine is already running.
    #[error("tun redirect is already running")]
    AlreadyRunning,

    /// The redirect engine is not running.
    #[error("tun redirect is not running")]
    NotRunning,

    /// An underlying I/O error (socket bind, relay, …).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Convenience constructor for a configuration error.
    pub(crate) fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }

    /// Convenience constructor for a network-configuration error.
    pub(crate) fn netcfg(op: impl Into<String>, source: std::io::Error) -> Self {
        Error::NetConfig {
            op: op.into(),
            source,
        }
    }
}
