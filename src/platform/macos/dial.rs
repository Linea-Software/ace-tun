//! macOS socket pinning: `IP_BOUND_IF` / `IPV6_BOUND_IF`.
//!
//! Once the TUN adapter owns the routing table, *every* socket in this
//! process would also route into the tunnel — including the ones we open to
//! actually reach the internet. That is an infinite loop. The fix is to bind
//! each outbound socket to the physical interface, bypassing the routing
//! table.
//!
//! # Why `IP_BOUND_IF` works here (and `IP_UNICAST_IF` does not on Linux)
//!
//! On macOS the connect-time address/route selection (`in_pcbladdr`) honours
//! the socket's bound interface (`inp_boundifp`, set by `IP_BOUND_IF`) by
//! constraining the route lookup with the interface scope, so the SYN never
//! sees the tunnel. On Linux the equivalent option is applied too late (see
//! `platform/linux/dial.rs`); macOS has no such gap.
//!
//! Both options take the plain interface index — a native `int` in **host
//! byte order for both families**, unlike Windows, where the v4 option wants
//! network order. Loopback destinations are left unpinned: loopback never
//! enters the tunnel anyway, and an interface-scoped lookup to 127/8 may be
//! rejected (the Linux kernel does; macOS needs a live check).

use std::io;
use std::net::IpAddr;

/// Pin an outbound socket to a physical interface, bypassing the tunnel.
///
/// Loopback destinations are left alone (see module docs).
pub(crate) fn pin_socket(raw: i32, index: u32, dest: IpAddr) -> io::Result<()> {
    if dest.is_loopback() {
        return Ok(());
    }
    let (level, option) = match dest {
        IpAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_BOUND_IF),
        IpAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF),
    };
    // The plain interface index in host byte order, for both families.
    let value = index as libc::c_int;
    // SAFETY: `raw` is a live socket owned by the caller for the duration of
    // this call, and `value` is the 4-byte integer the option expects.
    let rc = unsafe {
        libc::setsockopt(
            raw,
            level,
            option,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
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

    /// The option numbers are part of the macOS ABI and cannot drift.
    #[test]
    fn bound_if_option_numbers() {
        assert_eq!(libc::IP_BOUND_IF, 25);
        assert_eq!(libc::IPV6_BOUND_IF, 125);
    }

    /// Loopback destinations must never be bound: loopback traffic cannot
    /// enter the tunnel, and an interface-scoped lookup to 127.0.0.0/8 may
    /// be rejected.
    #[test]
    fn loopback_destinations_are_not_pinned() {
        // Pinning would fail (ENXIO for a bogus index), so a successful
        // no-op proves the loopback guard ran first.
        let result = pin_socket(-1, 0xDEAD, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(result.is_ok(), "loopback pin must be a no-op");
        let result = pin_socket(-1, 0xDEAD, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert!(result.is_ok(), "loopback pin must be a no-op");
    }
}
