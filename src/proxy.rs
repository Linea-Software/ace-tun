//! Upstream proxy connectors.
//!
//! Ported from ProxyBridge's `http_connect` / `socks5_connect` /
//! `socks5_connect_domain`. Given a [`ProxyConfig`] and a destination, open a
//! TCP connection to the upstream proxy and negotiate a tunnel so the caller
//! can relay bytes transparently.

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{ProxyConfig, ProxyType};

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_AUTH_USERPASS: u8 = 0x02;

/// The destination a proxied connection ultimately targets.
#[derive(Debug, Clone)]
pub enum Target {
    /// A resolved IP literal.
    Ip(IpAddr, u16),
    /// A hostname (from the DNS-snoop cache) resolved by the proxy.
    Domain(String, u16),
}

impl Target {
    fn port(&self) -> u16 {
        match self {
            Target::Ip(_, p) | Target::Domain(_, p) => *p,
        }
    }

    fn host_string(&self) -> String {
        match self {
            Target::Ip(ip, _) => ip.to_string(),
            Target::Domain(h, _) => h.clone(),
        }
    }
}

/// Timeout for the full connect + proxy handshake.
pub(crate) const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Connect to the upstream proxy and open a tunnel to `dest`.
pub async fn connect_via_proxy(cfg: &ProxyConfig, dest: &Target) -> io::Result<TcpStream> {
    tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, connect_via_proxy_inner(cfg, dest))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream proxy connect timed out"))?
}

async fn connect_via_proxy_inner(cfg: &ProxyConfig, dest: &Target) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect((cfg.host.as_str(), cfg.port)).await?;
    stream.set_nodelay(true).ok();
    match cfg.proxy_type {
        ProxyType::Http => http_connect(&mut stream, cfg, dest).await?,
        ProxyType::Socks5 => socks5_connect(&mut stream, cfg, dest).await?,
    }
    Ok(stream)
}

// ── HTTP CONNECT ──────────────────────────────────────────────────────

async fn http_connect(stream: &mut TcpStream, cfg: &ProxyConfig, dest: &Target) -> io::Result<()> {
    let request = build_http_connect_request(
        &dest.host_string(),
        dest.port(),
        cfg.username.as_deref().zip(cfg.password.as_deref()),
    );
    stream.write_all(&request).await?;

    // Read until the double-CRLF that terminates HTTP headers. A single
    // read() may return a partial response; loop to accumulate.
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 512];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed during CONNECT",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
        if buf.len() > 65536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT response headers too large",
            ));
        }
    }
    let status = parse_http_status(&buf).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP CONNECT response")
    })?;
    if status != 200 {
        return Err(io::Error::other(format!(
            "HTTP CONNECT failed with status {status}"
        )));
    }
    Ok(())
}

/// Build a `CONNECT host:port HTTP/1.1` request, with optional Basic auth.
pub(crate) fn build_http_connect_request(
    host: &str,
    port: u16,
    auth: Option<(&str, &str)>,
) -> Vec<u8> {
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some((user, pass)) = auth {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    req.into_bytes()
}

/// Parse the numeric status code from an HTTP status line.
pub(crate) fn parse_http_status(response: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(response).ok()?;
    let line = text.lines().next()?;
    if !line.starts_with("HTTP/1.") {
        return None;
    }
    line.split_whitespace().nth(1)?.parse::<u16>().ok()
}

// ── SOCKS5 ────────────────────────────────────────────────────────────

async fn socks5_connect(
    stream: &mut TcpStream,
    cfg: &ProxyConfig,
    dest: &Target,
) -> io::Result<()> {
    let use_auth = cfg.username.is_some();

    // Greeting.
    stream.write_all(&build_socks5_greeting(use_auth)).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad SOCKS5 version",
        ));
    }

    match method[1] {
        SOCKS5_AUTH_NONE => {}
        SOCKS5_AUTH_USERPASS => {
            let (Some(user), Some(pass)) = (cfg.username.as_deref(), cfg.password.as_deref())
            else {
                return Err(io::Error::other("proxy requires auth but none configured"));
            };
            stream
                .write_all(&build_socks5_userpass(user, pass)?)
                .await?;
            let mut ok = [0u8; 2];
            stream.read_exact(&mut ok).await?;
            if ok[1] != 0x00 {
                return Err(io::Error::other("SOCKS5 authentication failed"));
            }
        }
        _ => return Err(io::Error::other("no acceptable SOCKS5 auth method")),
    }

    // CONNECT request.
    stream
        .write_all(&build_socks5_connect_request(dest)?)
        .await?;
    read_socks5_reply(stream).await
}

fn build_socks5_greeting(use_auth: bool) -> Vec<u8> {
    if use_auth {
        vec![SOCKS5_VERSION, 0x02, SOCKS5_AUTH_NONE, SOCKS5_AUTH_USERPASS]
    } else {
        vec![SOCKS5_VERSION, 0x01, SOCKS5_AUTH_NONE]
    }
}

fn build_socks5_userpass(user: &str, pass: &str) -> io::Result<Vec<u8>> {
    if user.len() > 255 || pass.len() > 255 {
        return Err(io::Error::other("SOCKS5 credential too long"));
    }
    let mut buf = Vec::with_capacity(3 + user.len() + pass.len());
    buf.push(0x01); // auth version
    buf.push(user.len() as u8);
    buf.extend_from_slice(user.as_bytes());
    buf.push(pass.len() as u8);
    buf.extend_from_slice(pass.as_bytes());
    Ok(buf)
}

fn build_socks5_connect_request(dest: &Target) -> io::Result<Vec<u8>> {
    let mut buf = vec![SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00];
    match dest {
        Target::Ip(IpAddr::V4(v4), _) => {
            buf.push(SOCKS5_ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        Target::Ip(IpAddr::V6(v6), _) => {
            buf.push(SOCKS5_ATYP_IPV6);
            buf.extend_from_slice(&v6.octets());
        }
        Target::Domain(host, _) => {
            if host.is_empty() || host.len() > 255 {
                return Err(io::Error::other("invalid SOCKS5 domain length"));
            }
            buf.push(SOCKS5_ATYP_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
        }
    }
    buf.extend_from_slice(&dest.port().to_be_bytes());
    Ok(buf)
}

async fn read_socks5_reply(stream: &mut TcpStream) -> io::Result<()> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != SOCKS5_VERSION || hdr[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5 CONNECT rejected (reply={})",
            hdr[1]
        )));
    }
    // Drain the variable-length BND.ADDR + BND.PORT by ATYP.
    let drain = match hdr[3] {
        SOCKS5_ATYP_IPV4 => 4 + 2,
        SOCKS5_ATYP_IPV6 => 16 + 2,
        SOCKS5_ATYP_DOMAIN => {
            let mut dlen = [0u8; 1];
            stream.read_exact(&mut dlen).await?;
            dlen[0] as usize + 2
        }
        _ => return Err(io::Error::other("unknown SOCKS5 ATYP in reply")),
    };
    let mut scratch = [0u8; 270];
    stream.read_exact(&mut scratch[..drain]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn http_connect_request_no_auth() {
        let req = build_http_connect_request("example.com", 443, None);
        let text = String::from_utf8(req).unwrap();
        assert!(text.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com:443\r\n"));
        assert!(!text.contains("Proxy-Authorization"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn http_connect_request_with_auth() {
        let req = build_http_connect_request("1.2.3.4", 80, Some(("user", "pass")));
        let text = String::from_utf8(req).unwrap();
        // base64("user:pass") == "dXNlcjpwYXNz"
        assert!(text.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    }

    #[test]
    fn http_status_parsing() {
        assert_eq!(
            parse_http_status(b"HTTP/1.1 200 Connection established\r\n"),
            Some(200)
        );
        assert_eq!(
            parse_http_status(b"HTTP/1.0 407 Proxy Auth Required\r\n"),
            Some(407)
        );
        assert_eq!(parse_http_status(b"garbage"), None);
    }

    #[test]
    fn socks5_greeting_bytes() {
        assert_eq!(build_socks5_greeting(false), vec![0x05, 0x01, 0x00]);
        assert_eq!(build_socks5_greeting(true), vec![0x05, 0x02, 0x00, 0x02]);
    }

    #[test]
    fn socks5_connect_request_ipv4() {
        let dest = Target::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let req = build_socks5_connect_request(&dest).unwrap();
        assert_eq!(
            req,
            vec![0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xBB]
        );
    }

    #[test]
    fn socks5_connect_request_domain() {
        let dest = Target::Domain("example.com".to_string(), 80);
        let req = build_socks5_connect_request(&dest).unwrap();
        assert_eq!(req[0..4], [0x05, 0x01, 0x00, 0x03]);
        assert_eq!(req[4], 11); // len("example.com")
        assert_eq!(&req[5..16], b"example.com");
        assert_eq!(&req[16..18], &[0x00, 0x50]); // port 80
    }

    #[test]
    fn socks5_userpass_bytes() {
        let buf = build_socks5_userpass("ab", "cde").unwrap();
        assert_eq!(buf, vec![0x01, 0x02, b'a', b'b', 0x03, b'c', b'd', b'e']);
    }

    #[test]
    fn socks5_connect_request_ipv6() {
        let dest = Target::Ip(IpAddr::V6("2001:db8::1".parse().unwrap()), 443);
        let req = build_socks5_connect_request(&dest).unwrap();
        assert_eq!(req[0..4], [0x05, 0x01, 0x00, 0x04]); // ATYP IPv6
        assert_eq!(
            &req[4..20],
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(&req[20..22], &[0x01, 0xBB]); // port 443
    }

    // ── Async integration tests against mock upstream proxies ──────────

    mod integration {
        use super::super::*;
        use super::*;
        use std::net::Ipv4Addr;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        /// Spawn a task that accepts one connection, applies `handler`, and
        /// returns the listener's bound port.
        async fn mock_proxy<F>(handler: F) -> u16
        where
            F: Fn(TcpStream) -> tokio::task::JoinHandle<()> + Send + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                handler(stream).await.unwrap();
            });
            port
        }

        // ── HTTP CONNECT mocks ────────────────────────────────────────

        #[tokio::test]
        async fn http_connect_success() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let n = s.read(&mut buf).await.unwrap();
                    let req = std::str::from_utf8(&buf[..n]).unwrap();
                    assert!(req.starts_with("CONNECT "));
                    s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                })
            })
            .await;
            let cfg = ProxyConfig::http("127.0.0.1", port);
            let dest = Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
            let stream = connect_via_proxy(&cfg, &dest).await.unwrap();
            assert!(stream.peer_addr().is_ok());
        }

        #[tokio::test]
        async fn http_connect_407_rejected() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf).await.unwrap();
                    s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                        .await
                        .unwrap();
                })
            })
            .await;
            let cfg = ProxyConfig::http("127.0.0.1", port);
            let dest = Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
            let err = connect_via_proxy(&cfg, &dest).await.unwrap_err();
            assert!(err.to_string().contains("407"), "expected 407 in: {err}");
        }

        #[tokio::test]
        async fn http_connect_malformed_status() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf).await.unwrap();
                    s.write_all(b"garbage response\r\n\r\n").await.unwrap();
                })
            })
            .await;
            let cfg = ProxyConfig::http("127.0.0.1", port);
            let dest = Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
            let err = connect_via_proxy(&cfg, &dest).await.unwrap_err();
            assert!(
                err.to_string().contains("invalid"),
                "expected invalid data: {err}"
            );
        }

        #[tokio::test]
        async fn http_connect_sends_basic_auth_header() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let n = s.read(&mut buf).await.unwrap();
                    let req = std::str::from_utf8(&buf[..n]).unwrap();
                    assert!(
                        req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"),
                        "missing auth header in:\n{req}"
                    );
                    s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                })
            })
            .await;
            let cfg = ProxyConfig::http("127.0.0.1", port).with_auth("user", "pass");
            let dest = Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
            connect_via_proxy(&cfg, &dest).await.unwrap();
        }

        #[tokio::test]
        async fn http_connect_no_auth_when_creds_unset() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let n = s.read(&mut buf).await.unwrap();
                    let req = std::str::from_utf8(&buf[..n]).unwrap();
                    assert!(
                        !req.contains("Proxy-Authorization"),
                        "unexpected auth header:\n{req}"
                    );
                    s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                })
            })
            .await;
            let cfg = ProxyConfig::http("127.0.0.1", port);
            let dest = Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
            connect_via_proxy(&cfg, &dest).await.unwrap();
        }

        /// Regression: the original `http_connect` did a single `read()` which
        /// would fail when a proxy dribbled bytes. Fixed by reading until
        /// `\r\n\r\n`. This test writes the response byte-by-byte with delays
        /// to guarantee the read-accumulation loop is exercised.
        #[tokio::test]
        async fn http_connect_partial_read() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf).await.unwrap();
                    // Dribble the response one byte at a time to force partial
                    // reads in the accumulation loop.
                    let response = b"HTTP/1.1 200 Connection established\r\n\r\n";
                    for &byte in response {
                        s.write_all(&[byte]).await.unwrap();
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                })
            })
            .await;
            let cfg = ProxyConfig::http("127.0.0.1", port);
            let dest = Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
            connect_via_proxy(&cfg, &dest).await.unwrap();
        }

        // ── SOCKS5 mocks ──────────────────────────────────────────────

        #[tokio::test]
        async fn socks5_no_auth_ipv4() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    // Greeting
                    let n = s.read(&mut buf).await.unwrap();
                    assert_eq!(&buf[..n], &[0x05, 0x01, 0x00]);
                    s.write_all(&[0x05, 0x00]).await.unwrap(); // no-auth chosen

                    // CONNECT request
                    let _n = s.read(&mut buf).await.unwrap();
                    // Verify it's a well-formed IPv4 CONNECT
                    assert_eq!(buf[0], 0x05);
                    assert_eq!(buf[1], 0x01); // CMD CONNECT
                    assert_eq!(buf[3], 0x01); // ATYP IPv4

                    // Reply: success, IPv4 BND.ADDR + BND.PORT
                    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
                    reply.extend_from_slice(&[127, 0, 0, 1]); // BND.ADDR
                    reply.extend_from_slice(&[0x00, 0x00]); // BND.PORT
                    s.write_all(&reply).await.unwrap();
                })
            })
            .await;
            let cfg = ProxyConfig::socks5("127.0.0.1", port);
            let dest = Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
            connect_via_proxy(&cfg, &dest).await.unwrap();
        }

        #[tokio::test]
        async fn socks5_no_auth_ipv6_reply() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf).await.unwrap(); // greeting
                    s.write_all(&[0x05, 0x00]).await.unwrap();
                    let _ = s.read(&mut buf).await.unwrap(); // connect request

                    // Reply with IPv6 ATYP → exercises the 16+2 drain path
                    let mut reply = vec![0x05, 0x00, 0x00, 0x04]; // ATYP IPv6
                    reply.extend_from_slice(&[0u8; 16]); // BND.ADDR
                    reply.extend_from_slice(&[0x00, 0x00]); // BND.PORT
                    s.write_all(&reply).await.unwrap();
                })
            })
            .await;
            let cfg = ProxyConfig::socks5("127.0.0.1", port);
            let dest = Target::Ip(IpAddr::V6("2001:db8::1".parse().unwrap()), 80);
            connect_via_proxy(&cfg, &dest).await.unwrap();
        }

        #[tokio::test]
        async fn socks5_no_auth_domain_reply() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf).await.unwrap(); // greeting
                    s.write_all(&[0x05, 0x00]).await.unwrap();
                    let _ = s.read(&mut buf).await.unwrap(); // connect request

                    // Reply with DOMAIN ATYP → exercises variable-length drain
                    let domain = b"proxy.local";
                    let mut reply = vec![0x05, 0x00, 0x00, 0x03]; // ATYP DOMAIN
                    reply.push(domain.len() as u8);
                    reply.extend_from_slice(domain);
                    reply.extend_from_slice(&[0x00, 0x00]); // BND.PORT
                    s.write_all(&reply).await.unwrap();
                })
            })
            .await;
            let cfg = ProxyConfig::socks5("127.0.0.1", port);
            let dest = Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
            connect_via_proxy(&cfg, &dest).await.unwrap();
        }

        #[tokio::test]
        async fn socks5_userpass_auth_success() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    // Greeting: should advertise both methods
                    let _n = s.read(&mut buf).await.unwrap();
                    assert_eq!(buf[0], 0x05);
                    assert_eq!(buf[1], 0x02); // 2 methods
                    // Choose user/pass
                    s.write_all(&[0x05, 0x02]).await.unwrap();

                    // Auth sub-negotiation
                    let _n = s.read(&mut buf).await.unwrap();
                    assert_eq!(buf[0], 0x01); // auth version
                    let ulen = buf[1] as usize;
                    let user = std::str::from_utf8(&buf[2..2 + ulen]).unwrap();
                    let plen = buf[2 + ulen] as usize;
                    let pass = std::str::from_utf8(&buf[3 + ulen..3 + ulen + plen]).unwrap();
                    assert_eq!(user, "alice");
                    assert_eq!(pass, "s3cret");
                    s.write_all(&[0x01, 0x00]).await.unwrap(); // auth success

                    // CONNECT request
                    let _ = s.read(&mut buf).await.unwrap();
                    // Reply success
                    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
                    reply.extend_from_slice(&[127, 0, 0, 1]);
                    reply.extend_from_slice(&[0x00, 0x00]);
                    s.write_all(&reply).await.unwrap();
                })
            })
            .await;
            let cfg = ProxyConfig::socks5("127.0.0.1", port).with_auth("alice", "s3cret");
            let dest = Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
            connect_via_proxy(&cfg, &dest).await.unwrap();
        }

        #[tokio::test]
        async fn socks5_auth_rejected() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf).await.unwrap(); // greeting
                    s.write_all(&[0x05, 0x02]).await.unwrap(); // choose user/pass
                    let _ = s.read(&mut buf).await.unwrap(); // auth attempt
                    s.write_all(&[0x01, 0x01]).await.unwrap(); // auth FAILURE
                })
            })
            .await;
            let cfg = ProxyConfig::socks5("127.0.0.1", port).with_auth("bad", "wrong");
            let dest = Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
            let err = connect_via_proxy(&cfg, &dest).await.unwrap_err();
            assert!(
                err.to_string().contains("authentication failed"),
                "expected auth failure: {err}"
            );
        }

        #[tokio::test]
        async fn socks5_connect_rejected() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf).await.unwrap(); // greeting
                    s.write_all(&[0x05, 0x00]).await.unwrap();
                    let _ = s.read(&mut buf).await.unwrap(); // connect request
                    // Reply: general SOCKS server failure (REP=0x01)
                    let mut reply = vec![0x05, 0x01, 0x00, 0x01];
                    reply.extend_from_slice(&[0, 0, 0, 0]);
                    reply.extend_from_slice(&[0x00, 0x00]);
                    s.write_all(&reply).await.unwrap();
                })
            })
            .await;
            let cfg = ProxyConfig::socks5("127.0.0.1", port);
            let dest = Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
            let err = connect_via_proxy(&cfg, &dest).await.unwrap_err();
            assert!(
                err.to_string().contains("rejected"),
                "expected CONNECT rejected: {err}"
            );
        }

        #[tokio::test]
        async fn socks5_bad_version_in_greeting() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf).await.unwrap();
                    // Reply with bad version
                    s.write_all(&[0x04, 0x00]).await.unwrap();
                })
            })
            .await;
            let cfg = ProxyConfig::socks5("127.0.0.1", port);
            let dest = Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
            let err = connect_via_proxy(&cfg, &dest).await.unwrap_err();
            assert!(
                err.to_string().contains("bad SOCKS5 version"),
                "expected bad version: {err}"
            );
        }

        #[tokio::test]
        async fn socks5_no_acceptable_auth_method() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf).await.unwrap();
                    // Choose method 0xFF (no acceptable methods)
                    s.write_all(&[0x05, 0xFF]).await.unwrap();
                })
            })
            .await;
            let cfg = ProxyConfig::socks5("127.0.0.1", port);
            let dest = Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
            let err = connect_via_proxy(&cfg, &dest).await.unwrap_err();
            assert!(
                err.to_string().contains("no acceptable"),
                "expected no acceptable auth: {err}"
            );
        }

        #[tokio::test]
        async fn socks5_domain_connect_sends_hostname() {
            let port = mock_proxy(|mut s| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf).await.unwrap(); // greeting
                    s.write_all(&[0x05, 0x00]).await.unwrap();

                    let _n = s.read(&mut buf).await.unwrap(); // connect request
                    assert_eq!(buf[3], 0x03); // ATYP DOMAIN
                    let dlen = buf[4] as usize;
                    let domain = std::str::from_utf8(&buf[5..5 + dlen]).unwrap();
                    assert_eq!(domain, "example.com");
                    let port_be = u16::from_be_bytes([buf[5 + dlen], buf[5 + dlen + 1]]);
                    assert_eq!(port_be, 80);

                    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
                    reply.extend_from_slice(&[127, 0, 0, 1]);
                    reply.extend_from_slice(&[0x00, 0x00]);
                    s.write_all(&reply).await.unwrap();
                })
            })
            .await;
            let cfg = ProxyConfig::socks5("127.0.0.1", port);
            let dest = Target::Domain("example.com".to_string(), 80);
            connect_via_proxy(&cfg, &dest).await.unwrap();
        }
    }
}
