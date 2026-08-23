//! Windows socket pinning: `IP_UNICAST_IF` / `IPV6_UNICAST_IF`.
//!
//! Once the TUN adapter owns the routing table, *every* socket in this process
//! would also route into the tunnel — including the ones we open to actually
//! reach the internet. That is an infinite loop. The fix is
//! `IP_UNICAST_IF` / `IPV6_UNICAST_IF`, which tell Windows to send a socket's
//! packets out of a specific interface, *bypassing the routing table entirely*.
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
use std::net::IpAddr;

use windows::Win32::Networking::WinSock::{
    IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SO_SNDBUF, SOCKET, SOCKET_ERROR,
    SOL_SOCKET, setsockopt,
};

/// Encode an interface index for the Windows `*_UNICAST_IF` socket options.
///
/// IPv4 wants network byte order, IPv6 wants host byte order. See the module
/// docs — this asymmetry is the single most common way to break this feature.
pub(crate) fn unicast_if_value(index: u32, is_ipv6: bool) -> u32 {
    if is_ipv6 { index } else { index.to_be() }
}

/// Apply `IP_UNICAST_IF` / `IPV6_UNICAST_IF` to a raw socket handle.
///
/// The destination address is ignored on Windows; it exists so the portable
/// dialing code can hand the per-OS pinning the full picture (Linux needs it
/// to skip loopback destinations for `SO_BINDTODEVICE`).
pub(crate) fn pin_socket(raw: u64, index: u32, dest: IpAddr) -> io::Result<()> {
    let is_ipv6 = dest.is_ipv6();
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

/// Set `SO_SNDBUF` on a raw socket handle.
///
/// Windows defaults UDP sockets to a small send buffer and returns WSAENOBUFS
/// the moment it fills; relaying a whole flow through one socket makes that far
/// more likely than it is for an ordinary application.
pub(crate) fn set_send_buffer(raw: u64, bytes: u32) -> io::Result<()> {
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

    /// IPv6 takes the index verbatim (host order) on Windows.
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
}
