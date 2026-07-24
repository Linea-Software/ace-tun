//! Upstream proxy configuration.
//!
//! Ported from ProxyBridge's `PROXY_CONFIG` / `ProxyBridge_AddProxyConfig`.
//! A [`ProxyConfig`] describes the upstream proxy that `RuleAction::Proxy`
//! connections are relayed through — either an HTTP `CONNECT` proxy or a
//! SOCKS5 proxy (optionally authenticated).

/// Upstream proxy transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyType {
    /// HTTP forward proxy using the `CONNECT` verb to tunnel TCP.
    Http,
    /// SOCKS5 proxy (RFC 1928), optionally with username/password auth.
    Socks5,
}

/// Configuration for a single upstream proxy.
///
/// Build one with the [`ProxyConfig::http`] or [`ProxyConfig::socks5`]
/// constructors and hand it to
/// [`TunRedirectBuilder::proxy_config`](crate::TunRedirectBuilder::proxy_config).
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub(crate) config_id: u32,
    pub(crate) proxy_type: ProxyType,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    /// When `true`, the destination hostname (from the DNS-snoop cache) is sent
    /// to the proxy so it resolves DNS (`socks5h` / `CONNECT domain:port`).
    /// When `false`, the resolved IP literal is sent instead.
    pub(crate) send_domain_to_proxy: bool,
}

impl ProxyConfig {
    /// Create an HTTP `CONNECT` proxy configuration.
    pub fn http(host: impl Into<String>, port: u16) -> Self {
        Self {
            config_id: 0,
            proxy_type: ProxyType::Http,
            host: host.into(),
            port,
            username: None,
            password: None,
            send_domain_to_proxy: true,
        }
    }

    /// Create a SOCKS5 proxy configuration with no authentication.
    pub fn socks5(host: impl Into<String>, port: u16) -> Self {
        Self {
            config_id: 0,
            proxy_type: ProxyType::Socks5,
            host: host.into(),
            port,
            username: None,
            password: None,
            send_domain_to_proxy: true,
        }
    }

    /// Add username/password credentials.
    ///
    /// For HTTP this becomes a `Proxy-Authorization: Basic` header; for SOCKS5
    /// it enables the RFC 1929 username/password auth method.
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    /// Control whether the proxy resolves DNS (`true`, default) or whether the
    /// locally-resolved IP is sent instead (`false`).
    pub fn resolve_on_proxy(mut self, enable: bool) -> Self {
        self.send_domain_to_proxy = enable;
        self
    }

    /// This config's id (assigned by the builder; 0 until registered).
    pub fn config_id(&self) -> u32 {
        self.config_id
    }

    /// The proxy transport type.
    pub fn proxy_type(&self) -> ProxyType {
        self.proxy_type
    }

    /// The proxy host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The proxy port.
    pub fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn validate(&self) -> crate::Result<()> {
        if self.host.trim().is_empty() {
            return Err(crate::Error::config("proxy host must not be empty"));
        }
        if self.port == 0 {
            return Err(crate::Error::config("proxy port must not be zero"));
        }
        Ok(())
    }
}
