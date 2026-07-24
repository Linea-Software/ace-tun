//! Outbound sockets pinned to the physical NIC.
//!
//! # Why this exists
//!
//! Once the TUN adapter owns the routing table, *every* socket in this process
//! would also route into the tunnel — including the ones we open to actually
//! reach the internet. That is an infinite loop: our own upstream connection
//! re-enters the netstack, which opens another upstream connection, and so on.
//!
//! The fix is `IP_UNICAST_IF`. It tells Windows to send this socket's packets
//! out of a specific interface, *bypassing the routing table entirely*. We
//! capture the internet-facing interface index once at startup, before our
//! routes exist (see [`crate::netcfg::PhysicalInterface::discover`]), and pin
//! every outbound socket to it. Their packets never see the tunnel, so there is
//! no loop, and nothing has to know about which process or destination is
//! involved.
//!
//! This is the same mechanism WireGuard's Windows client uses to keep its own
//! UDP transport outside its own tunnel.
//!
//! ## The byte-order trap
//!
//! `IP_UNICAST_IF` takes the interface index in **network** byte order, while
//! `IPV6_UNICAST_IF` takes it in **host** byte order. This asymmetry is real,
//! documented, and easy to get wrong; getting it wrong silently pins the socket
//! to a nonexistent interface, which manifests as "all outbound traffic hangs".
//! [`unicast_if_value`] encodes the rule and is unit-tested.

use std::io;
use std::net::SocketAddr;
use std::os::windows::io::AsRawSocket;
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use windows::Win32::Networking::WinSock::{
    IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SO_SNDBUF, SOCKET, SOCKET_ERROR,
    SOL_SOCKET, setsockopt,
};

use crate::netcfg::PhysicalInterface;

/// How long to wait for a pinned outbound TCP connection to complete.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Encode an interface index for the `*_UNICAST_IF` socket option.
///
/// IPv4 wants network byte order, IPv6 wants host byte order. See the module
/// docs — this asymmetry is the single most common way to break this feature.
pub(crate) fn unicast_if_value(index: u32, is_ipv6: bool) -> u32 {
    if is_ipv6 { index } else { index.to_be() }
}

/// Apply `IP_UNICAST_IF` / `IPV6_UNICAST_IF` to a raw socket handle.
fn pin_socket(raw: u64, index: u32, is_ipv6: bool) -> io::Result<()> {
    let value = unicast_if_value(index, is_ipv6);
    let bytes = value.to_ne_bytes();
    let (level, optname) = if is_ipv6 {
        (IPPROTO_IPV6.0, IPV6_UNICAST_IF)
    } else {
        (IPPROTO_IP.0, IP_UNICAST_IF)
    };

    // SAFETY: `raw` is a live socket owned by the caller for the duration of
    // this call, and `bytes` is a 4-byte buffer as the option expects.
    let rc = unsafe { setsockopt(SOCKET(raw as usize), level, optname, Some(&bytes)) };
    if rc == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
        if let Err(e) = pin_socket(socket.as_raw_socket(), index, dest.is_ipv6()) {
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
        && let Err(e) = pin_socket(socket.as_raw_socket(), index, dest.is_ipv6())
    {
        tracing::warn!("could not pin outbound UDP socket to interface {index}: {e}");
    }

    // Windows defaults UDP sockets to a small send buffer and returns
    // WSAENOBUFS the moment it fills. Relaying a whole flow through one socket
    // makes that far more likely than it is for an ordinary application, so ask
    // for more headroom. Best-effort: if the kernel declines, the caller
    // tolerates the resulting send errors anyway.
    if let Err(e) = set_send_buffer(socket.as_raw_socket(), UDP_SEND_BUFFER) {
        tracing::debug!("could not raise UDP send buffer: {e}");
    }

    socket.connect(dest).await?;
    Ok(socket)
}

/// Send-buffer size requested for relay sockets.
const UDP_SEND_BUFFER: u32 = 512 * 1024;

/// Set `SO_SNDBUF` on a raw socket handle.
fn set_send_buffer(raw: u64, bytes: u32) -> io::Result<()> {
    let value = bytes.to_ne_bytes();
    // SAFETY: `raw` is a live socket owned by the caller for this call, and
    // `value` is the 4-byte integer `SO_SNDBUF` expects.
    let rc = unsafe { setsockopt(SOCKET(raw as usize), SOL_SOCKET, SO_SNDBUF, Some(&value)) };
    if rc == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4 takes the index in network byte order. On a little-endian host that
    /// means index 7 is encoded as 0x07000000.
    #[test]
    fn v4_unicast_if_is_network_order() {
        assert_eq!(unicast_if_value(7, false), 7u32.to_be());
        if cfg!(target_endian = "little") {
            assert_eq!(unicast_if_value(7, false), 0x0700_0000);
        }
    }

    /// IPv6 takes the index verbatim.
    #[test]
    fn v6_unicast_if_is_host_order() {
        assert_eq!(unicast_if_value(7, true), 7);
    }

    /// The two encodings must actually differ for a typical index, otherwise
    /// the test above would pass on a broken implementation.
    #[test]
    fn v4_and_v6_encodings_differ() {
        assert_ne!(unicast_if_value(12, false), unicast_if_value(12, true));
    }

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
