//! Outbound sockets pinned to the physical NIC.
//!
//! # Why this exists
//!
//! Once the TUN adapter owns the routing table, *every* socket in this process
//! would also route into the tunnel — including the ones we open to actually
//! reach the internet. That is an infinite loop: our own upstream connection
//! re-enters the netstack, which opens another upstream connection, and so on.
//!
//! The fix is a per-OS socket option (`IP_UNICAST_IF` on Windows/Linux,
//! `IP_BOUND_IF` on macOS — see [`crate::platform`]). It tells the OS to send
//! this socket's packets out of a specific interface, *bypassing the routing
//! table entirely*. We capture the internet-facing interface index once at
//! startup, before our routes exist (see
//! [`crate::platform::PhysicalInterface::discover`]), and pin every outbound
//! socket to it. Their packets never see the tunnel, so there is no loop, and
//! nothing has to know about which process or destination is involved.
//!
//! This is the same mechanism WireGuard's own client uses on each OS to keep
//! its UDP transport outside its own tunnel. The byte order of the index
//! differs per OS; the per-OS encoder lives in the platform module and is
//! unit-tested there, because getting it wrong silently pins the socket to a
//! nonexistent interface, which manifests as "all outbound traffic hangs".

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::platform::{pin_socket, set_send_buffer, PhysicalInterface};

/// How long to wait for a pinned outbound TCP connection to complete.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Send-buffer size requested for relay sockets.
const UDP_SEND_BUFFER: u32 = 512 * 1024;

/// Native handle of a tokio socket, for the per-OS pinning call.
#[cfg(target_os = "windows")]
fn raw_handle<T: std::os::windows::io::AsRawSocket>(socket: &T) -> u64 {
    socket.as_raw_socket()
}

/// Native handle of a tokio socket, for the per-OS pinning call.
#[cfg(not(target_os = "windows"))]
fn raw_handle<T: std::os::fd::AsRawFd>(socket: &T) -> i32 {
    socket.as_raw_fd()
}

/// Open a TCP connection to `dest` that bypasses the tunnel.
///
/// If no physical interface is known for `dest`'s family, the socket is left
/// unpinned and connected normally, so a machine we could not profile still
/// gets its traffic through. An unpinned socket owned by *this* process would
/// loop back into the tunnel, which is why
/// [`netstack::decide`](crate::netstack::decide) drops our own flows outright
/// in exactly that case rather than relying on this fallback.
pub(crate) async fn tcp(dest: SocketAddr, iface: &PhysicalInterface) -> io::Result<TcpStream> {
    let socket = if dest.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    if let Some(index) = iface.index_for(dest.ip()) {
        // A pin failure is not fatal — log-and-continue beats refusing to dial.
        if let Err(e) = pin_socket(raw_handle(&socket), index, dest.is_ipv6()) {
            tracing::warn!("could not pin outbound socket to interface {index}: {e}");
        }
    }

    let stream = tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(dest))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "outbound connect timed out"))??;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

/// Bind a UDP socket that bypasses the tunnel, for relaying a single flow.
///
/// The socket is bound to the wildcard address of `dest`'s family and then
/// connected, so it only exchanges datagrams with that one peer.
pub(crate) async fn udp(dest: SocketAddr, iface: &PhysicalInterface) -> io::Result<UdpSocket> {
    let bind: SocketAddr = if dest.is_ipv4() {
        "0.0.0.0:0".parse().expect("static addr")
    } else {
        "[::]:0".parse().expect("static addr")
    };

    let socket = UdpSocket::bind(bind).await?;

    if let Some(index) = iface.index_for(dest.ip())
        && let Err(e) = pin_socket(raw_handle(&socket), index, dest.is_ipv6())
    {
        tracing::warn!("could not pin outbound UDP socket to interface {index}: {e}");
    }

    // The OS defaults UDP sockets to a small send buffer and returns
    // WSAENOBUFS the moment it fills. Relaying a whole flow through one socket
    // makes that far more likely than it is for an ordinary application, so ask
    // for more headroom. Best-effort: if the kernel declines, the caller
    // tolerates the resulting send errors anyway.
    if let Err(e) = set_send_buffer(raw_handle(&socket), UDP_SEND_BUFFER) {
        tracing::debug!("could not raise UDP send buffer: {e}");
    }

    socket.connect(dest).await?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dialing with no known interface must still work (unpinned fallback).
    #[tokio::test]
    async fn unpinned_dial_still_connects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let iface = PhysicalInterface::default();
        assert!(iface.is_empty());
        let stream = tcp(addr, &iface)
            .await
            .expect("unpinned dial should connect");
        assert_eq!(stream.peer_addr().unwrap(), addr);
    }

    /// Pinning to a bogus interface index must not panic; the dial may fail,
    /// but it fails as an ordinary I/O error.
    #[tokio::test]
    async fn bogus_interface_index_does_not_panic() {
        let iface = PhysicalInterface {
            v4_index: Some(0xDEAD),
            v6_index: None,
        };
        let dest: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let _ = tcp(dest, &iface).await;
    }
}
