//! Linux socket pinning: `SO_BINDTODEVICE`.
//!
//! Once the TUN adapter owns the routing table, *every* socket in this process
//! would also route into the tunnel — including the ones we open to actually
//! reach the internet. That is an infinite loop. The fix is to bind each
//! outbound socket to the physical interface, bypassing the routing table.
//!
//! # Why `SO_BINDTODEVICE` and not `IP_UNICAST_IF`
//!
//! On Windows, `IP_UNICAST_IF` affects the *connect-time* route selection, so
//! the SYN never sees the tunnel. On Linux it does not: `tcp_v4_connect` (and
//! its IPv6 counterpart) route the SYN with `sk->sk_bound_dev_if`, which only
//! `SO_BINDTODEVICE` sets — `IP_UNICAST_IF` (`inet->uc_index`) is applied
//! later, on the packet-output path, after the route (and the source address)
//! were already chosen from the routing table. A Linux socket pinned with
//! `IP_UNICAST_IF` therefore still sends its SYN into the tunnel, and the
//! loop-guard dial re-enters the netstack forever (verified against kernel
//! 6.18 sources and live). `SO_BINDTODEVICE` sets `sk_bound_dev_if`, which the
//! connect-time lookup honours.
//!
//! Trade-offs: `SO_BINDTODEVICE` takes an interface *name* (resolved from the
//! discovered index) and requires `CAP_NET_RAW` — the privilege check
//! (`process::is_privileged`) requires it alongside `CAP_NET_ADMIN`. Loopback
//! destinations are never bound: the kernel's local table would reject an
//! `oif`-constrained lookup to 127.0.0.0/8, and loopback never enters the
//! tunnel anyway (the local table beats the split-defaults).

use std::ffi::CString;
use std::io;
use std::net::IpAddr;

/// The interface name for the loop-guard bind, resolved once per pin.
///
/// `SO_BINDTODEVICE` takes a name rather than an index; Linux caps names at
/// `IFNAMSIZ` (16), which any real interface satisfies.
fn interface_name(index: u32) -> io::Result<CString> {
    let mut buffer = [0i8; libc::IFNAMSIZ];
    // SAFETY: `buffer` is a live, correctly-sized local; if_indextoname writes
    // at most IFNAMSIZ bytes and NUL-terminates on success.
    let name = unsafe { libc::if_indextoname(index, buffer.as_mut_ptr()) };
    if name.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel wrote a NUL-terminated name into `buffer`.
    let name = unsafe { std::ffi::CStr::from_ptr(name) };
    Ok(CString::from(name))
}

/// Pin an outbound socket to a physical interface, bypassing the tunnel.
///
/// Loopback destinations are left alone (see module docs).
pub(crate) fn pin_socket(raw: i32, index: u32, dest: IpAddr) -> io::Result<()> {
    if dest.is_loopback() {
        return Ok(());
    }
    let name = interface_name(index)?;
    // SAFETY: `raw` is a live socket owned by the caller for the duration of
    // this call, and `name` is a NUL-terminated interface name.
    let rc = unsafe {
        libc::setsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr() as *const libc::c_void,
            name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set `SO_SNDBUF` on a raw socket fd.
///
/// The kernel defaults UDP sockets to a small send buffer and returns ENOBUFS
/// the moment it fills; relaying a whole flow through one socket makes that
/// far more likely than it is for an ordinary application.
pub(crate) fn set_send_buffer(raw: i32, bytes: u32) -> io::Result<()> {
    let value = bytes as libc::c_int;
    // SAFETY: `raw` is a live socket owned by the caller for this call, and
    // `value` is the 4-byte integer `SO_SNDBUF` expects.
    let rc = unsafe {
        libc::setsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Loopback destinations must never be bound: an `oif`-constrained lookup
    /// to 127.0.0.0/8 fails in the local table, and loopback traffic cannot
    /// enter the tunnel anyway.
    #[test]
    fn loopback_destinations_are_not_pinned() {
        // Pinning would fail (ENODEV for a bogus index), so a successful
        // no-op proves the loopback guard ran first.
        let result = pin_socket(-1, 0xDEAD, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(result.is_ok(), "loopback pin must be a no-op");
        let result = pin_socket(-1, 0xDEAD, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert!(result.is_ok(), "loopback pin must be a no-op");
    }

    /// A bogus interface index must surface as an error, not a silent no-op.
    #[test]
    fn bogus_interface_index_is_an_error() {
        let err = pin_socket(-1, 0xDEAD, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
            .expect_err("bogus index must fail");
        // ENXIO is what if_indextoname returns for an unknown index.
        assert_eq!(err.raw_os_error(), Some(libc::ENXIO));
    }
}
