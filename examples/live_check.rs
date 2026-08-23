//! End-to-end live check for the tunnel, independent of `mitm-proxy`.
//!
//! Run **elevated**:
//!
//! ```text
//! cargo run --example live_check
//! ```
//!
//! It stands up a minimal HTTP `CONNECT` proxy that blocks a hard-coded host
//! list and tunnels everything else, points a `TunRedirect` at it with
//! browser-scoped rules, and prints every decision plus a periodic stats line.
//! Ctrl+C tears the tunnel down.
//!
//! What to check while it runs:
//!
//! * `instagram.com` / `youtube.com` are blocked in a browser, **including**
//!   with QUIC enabled (`brave://flags` → Experimental QUIC protocol).
//! * `github.com` and `wikipedia.org` load normally and quickly.
//! * Both of the above hold over IPv6 (`https://ipv6.google.com` should load;
//!   an IPv6-only blocked host should not).
//! * After Ctrl+C, and again after a hard `taskkill /F`, the machine still has
//!   internet and `route print` shows no leftover `0.0.0.0/1` entry.

use std::sync::Arc;
use std::time::Duration;

use ace_tun::{ProxyConfig, Rule, RuleAction, RuleProtocol, TunRedirect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Hosts the stand-in proxy refuses to tunnel. Substring match, so this covers
/// `www.` and CDN subdomains too.
const BLOCKED: &[&str] = &["instagram.com", "youtube.com", "googlevideo.com"];

/// Browsers whose web traffic is routed through the stand-in proxy.
const BROWSERS: &[&str] = &[
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,ace_tun=debug".into()),
        )
        .init();

    // 1. Stand-in for mitm-proxy: a CONNECT proxy that blocks some hosts.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_port = listener.local_addr()?.port();
    tokio::spawn(run_block_proxy(listener));
    println!("blocking CONNECT proxy listening on 127.0.0.1:{proxy_port}");

    // 2. The tunnel, configured the way ace-engine configures it.
    let redirect = TunRedirect::builder(format!("127.0.0.1:{proxy_port}"))?
        .add_rule(Rule::new("ace-engine.exe;ace-app.exe;live_check.exe").action(RuleAction::Direct))
        .add_rule(
            Rule::new("*")
                .hosts("127.0.0.1;::1")
                .action(RuleAction::Direct),
        )
        .add_rule(
            Rule::new(BROWSERS.join(";"))
                .ports("80;443")
                .protocol(RuleProtocol::Tcp)
                .action(RuleAction::Proxy),
        )
        .add_rule(Rule::new("*").action(RuleAction::Direct))
        .proxy_config(ProxyConfig::http("127.0.0.1", proxy_port))
        .on_connection(|info| {
            println!(
                "  {:<16} pid={:<6} {}:{} -> {}",
                if info.process_name.is_empty() {
                    "<unknown>"
                } else {
                    &info.process_name
                },
                info.pid,
                info.dest_ip,
                info.dest_port,
                info.proxy_info,
            );
        })
        .build()?;

    match redirect.start().await {
        Ok(()) => println!("tunnel up — browse now; Ctrl+C to tear down"),
        Err(ace_tun::Error::NotElevated) => {
            eprintln!("error: run this as administrator/root (creating a virtual adapter needs privileges)");
            return Ok(());
        }
        Err(e) => {
            eprintln!("error: could not start the tunnel: {e}");
            return Err(e.into());
        }
    }

    // 3. Report until interrupted.
    let redirect = Arc::new(redirect);
    let reporter = Arc::clone(&redirect);
    let stats_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let s = reporter.stats();
            println!(
                "[stats] tcp={} udp={} blocked={} quic_dropped={} group_dropped={} \
                 udp_send_errors={} proxy_fallbacks={} dns_entries={}",
                s.tcp_flows,
                s.udp_flows,
                s.blocked,
                s.quic_dropped,
                s.group_dropped,
                s.udp_send_errors,
                s.proxy_fallbacks,
                reporter.dns_cache().len(),
            );
        }
    });

    tokio::signal::ctrl_c().await?;
    stats_task.abort();

    println!("tearing down...");
    redirect.stop().await?;
    println!("done — connectivity should be back to normal");
    Ok(())
}

/// Accept CONNECT requests, refuse the blocked hosts, tunnel the rest.
async fn run_block_proxy(listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            if let Err(e) = serve_connect(stream).await {
                eprintln!("  proxy connection failed: {e}");
            }
        });
    }
}

async fn serve_connect(mut client: TcpStream) -> std::io::Result<()> {
    // Read the request head. A CONNECT has no body, so one read is enough in
    // practice; this is a test harness, not a production parser.
    let mut buf = vec![0u8; 4096];
    let n = client.read(&mut buf).await?;
    let head = String::from_utf8_lossy(&buf[..n]).to_string();

    let Some(target) = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .map(str::to_owned)
    else {
        client
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
        return Ok(());
    };

    let host = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(&target);

    if BLOCKED.iter().any(|b| host.contains(b)) {
        println!("  BLOCKED {target}");
        client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
        return Ok(());
    }

    // Not blocked: tunnel it. This connection is owned by our own process, so
    // the tunnel sends it back out pinned to the physical NIC rather than
    // looping it.
    let mut upstream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            println!("  upstream {target} failed: {e}");
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
            return Ok(());
        }
    };

    client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}
