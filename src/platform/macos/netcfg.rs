//! Interface addressing and routing: `SIOC*` ioctls for addresses and link
//! parameters, `/sbin/route` for forwarding entries.
//!
//! macOS has no netlink-style API. Addresses and link parameters go through
//! ioctls on a datagram control socket (the same mechanism `ifconfig` uses),
//! and forwarding entries through the `route` command — the same tool
//! WireGuard's macOS client relies on. `route`'s output and exit codes vary
//! across macOS versions, so it is wrapped in exactly one place, and the only
//! success criterion callers need is "the route is in the table".
//!
//! # Routing strategy
//!
//! We never touch the system's existing default route. Instead we add the two
//! halves of the address space as *more specific* routes pointing at the TUN
//! interface (see [`crate::platform::V4_SPLIT_DEFAULT`] /
//! [`crate::platform::V6_SPLIT_DEFAULT`]):
//!
//! * IPv4: `0.0.0.0/1` and `128.0.0.0/1`
//! * IPv6: `::/1` and `8000::/1`
//!
//! Longest-prefix match makes these win over any `0.0.0.0/0`, so traffic enters
//! the tunnel — but the original default route is still sitting there untouched.
//! Teardown is therefore just "delete our routes", and if we never get to run
//! teardown at all (SIGKILL) the routes die with the interface, because the
//! kernel drops forwarding entries whose interface disappears and a non-
//! persistent utun interface disappears when its last fd closes. That is what
//! makes hard-kill safe rather than merely unlikely to hurt.

use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::platform::PhysicalInterface;

/// Probe destinations used to discover the physical interface that currently
/// carries internet traffic. Any globally-routable address works; these are
/// simply well-known and stable.
const V4_PROBE: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const V6_PROBE: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);

/// `IN6_IFF_NODAD` from `<netinet6/in6_var.h>`: skip duplicate-address
/// detection. Meaningless on a point-to-point tunnel we own, and waiting for
/// it would add a visible startup delay.
const IN6_IFF_NODAD: libc::c_int = 0x0020;

/// BSD ioctl numbers pack direction (2 bits) | size (14 bits) | type (8 bits)
/// | number (8 bits). `_IOW` sets direction 1, `_IOWR` direction 3; the
/// struct sizes are: `ifreq` 32, `ifaliasreq` 64, `in6_ifaliasreq` 128; the
/// type character for interface ioctls is `'i'` (0x69). The values below are
/// pinned by tests so a transcription error cannot silently break addressing.
const SIOCAIFADDR: libc::c_ulong = 0x4040_691a; // _IOW('i', 26, ifaliasreq)
const SIOCAIFADDR_IN6: libc::c_ulong = 0x4080_691a; // _IOW('i', 26, in6_ifaliasreq)
const SIOCSIFMTU: libc::c_ulong = 0x4020_6934; // _IOW('i', 52, ifreq)
const SIOCGIFFLAGS: libc::c_ulong = 0xc020_6911; // _IOWR('i', 17, ifreq)
const SIOCSIFFLAGS: libc::c_ulong = 0x4020_6910; // _IOW('i', 16, ifreq)

/// `struct ifaliasreq` from `<netinet/in.h>` — the `SIOCAIFADDR` argument.
#[repr(C)]
struct IfAliasRequest {
    ifra_name: [libc::c_char; libc::IFNAMSIZ],
    ifra_addr: libc::sockaddr,
    ifra_broadaddr: libc::sockaddr,
    ifra_mask: libc::sockaddr,
}

/// `struct in6_ifaliasreq` from `<netinet6/in6_var.h>` — the
/// `SIOCAIFADDR_IN6` argument.
#[repr(C)]
struct In6AliasRequest {
    ifra_name: [libc::c_char; libc::IFNAMSIZ],
    ifra_addr: libc::sockaddr_in6,
    ifra_dstaddr: libc::sockaddr_in6,
    ifra_prefixmask: libc::sockaddr_in6,
    ifra_flags: libc::c_int,
    ifra_lifetime: libc::in6_addrlifetime,
}

/// The physical interface that internet traffic uses today, as discovered by
/// asking the routing table for the best route to a public address.
///
/// Captured *before* we install our own routes, so it keeps pointing at the
/// real NIC afterwards. This is what outbound sockets get pinned to and what
/// the multicast group routes point at.
pub(crate) fn discover_physical_interface() -> PhysicalInterface {
    PhysicalInterface {
        v4_index: best_route_index(IpAddr::V4(V4_PROBE)),
        v6_index: best_route_index(IpAddr::V6(V6_PROBE)),
    }
}

/// Ask the kernel which interface would carry traffic to `dest`, the
/// `route -n get` equivalent. A family with no route yields `None`.
fn best_route_index(dest: IpAddr) -> Option<u32> {
    let output = std::process::Command::new("/sbin/route")
        .args(["-n", "get"])
        .arg(dest.to_string())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let name = stdout.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("interface:").map(str::trim)
    })?;
    let cname = CString::new(name).ok()?;
    // SAFETY: `cname` is a live NUL-terminated interface name.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    (index != 0).then_some(index)
}

/// Assign a unicast address with the given on-link prefix length to `ifindex`.
pub(crate) fn add_address(ifindex: u32, addr: IpAddr, prefix_len: u8) -> io::Result<()> {
    match addr {
        IpAddr::V4(v4) => add_address_v4(ifindex, v4, prefix_len),
        IpAddr::V6(v6) => add_address_v6(ifindex, v6, prefix_len),
    }
}

/// Assign an IPv4 address via `SIOCAIFADDR`.
///
/// The broadcast slot carries the address itself: utun is point-to-point with
/// no peer, so there is no broadcast address to speak of and the kernel only
/// needs the slot initialised.
fn add_address_v4(ifindex: u32, addr: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
    let socket = control_socket(libc::AF_INET)?;
    let name = interface_name(ifindex)?;

    let mut request: IfAliasRequest = unsafe { std::mem::zeroed() };
    fill_if_name(&mut request.ifra_name, &name);
    request.ifra_addr = v4_sockaddr(addr);
    request.ifra_broadaddr = v4_sockaddr(addr);
    request.ifra_mask = v4_sockaddr(netmask_v4(prefix_len));

    // SAFETY: `request` is fully initialised above and outlives the call.
    let rc = unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            SIOCAIFADDR,
            &request as *const IfAliasRequest as *const libc::c_void,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Assign an IPv6 address via `SIOCAIFADDR_IN6`.
///
/// The address gets an infinite lifetime (a manually assigned address without
/// one may be treated as expired) and `IN6_IFF_NODAD` — see above.
fn add_address_v6(ifindex: u32, addr: Ipv6Addr, prefix_len: u8) -> io::Result<()> {
    let socket = control_socket(libc::AF_INET6)?;
    let name = interface_name(ifindex)?;

    let mut request: In6AliasRequest = unsafe { std::mem::zeroed() };
    fill_if_name(&mut request.ifra_name, &name);
    request.ifra_addr = v6_sockaddr(addr);
    request.ifra_prefixmask = v6_sockaddr(netmask_v6(prefix_len));
    request.ifra_flags = IN6_IFF_NODAD;
    request.ifra_lifetime = libc::in6_addrlifetime {
        ia6t_expire: 0,
        ia6t_preferred: 0,
        ia6t_vltime: u32::MAX,
        ia6t_pltime: u32::MAX,
    };

    // SAFETY: `request` is fully initialised above and outlives the call.
    let rc = unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            SIOCAIFADDR_IN6,
            &request as *const In6AliasRequest as *const libc::c_void,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set the MTU and bring the link up, preserving any existing flags.
pub(crate) fn set_link_mtu_and_up(ifindex: u32, mtu: u16) -> io::Result<()> {
    let socket = control_socket(libc::AF_INET)?;
    let name = interface_name(ifindex)?;

    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    fill_if_name(&mut request.ifr_name, &name);
    request.ifr_ifru.ifru_mtu = mtu as libc::c_int;
    // SAFETY: `request` is fully initialised above and outlives the call.
    if unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            SIOCSIFMTU,
            &request as *const libc::ifreq as *const libc::c_void,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }

    // Read-modify-write the flags so a fresh interface's existing bits
    // (IFF_POINTOPOINT, ...) survive.
    let mut flags: libc::ifreq = unsafe { std::mem::zeroed() };
    fill_if_name(&mut flags.ifr_name, &name);
    // SAFETY: `flags` is a live, correctly-sized buffer; SIOCGIFFLAGS fills
    // the flag bits into `ifru_flags`.
    if unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            SIOCGIFFLAGS,
            &mut flags as *mut libc::ifreq as *mut libc::c_void,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: SIOCGIFFLAGS just initialised the union field we read.
    unsafe {
        flags.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
    }
    // SAFETY: `flags` is fully initialised and outlives the call.
    if unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            SIOCSIFFLAGS,
            &flags as *const libc::ifreq as *const libc::c_void,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A forwarding-table entry we created and are responsible for removing.
///
/// Deletion matches on destination and prefix only, so a handle is
/// self-contained and survives the interface it pointed at (which is also
/// why a stale handle simply deletes "not in table").
#[derive(Clone, Copy)]
pub(crate) struct RouteHandle {
    /// Whether the route is IPv6; the family flag is explicit because `route`
    /// otherwise guesses from the destination literal.
    v6: bool,
    dest: IpAddr,
    prefix_len: u8,
}

/// Add a route for `dest/prefix_len` out of `ifindex`.
///
/// Routes are on-link (`-interface`, no gateway): the tunnel is
/// point-to-point, so there is no next hop to forward through.
pub(crate) fn add_route(ifindex: u32, dest: IpAddr, prefix_len: u8) -> io::Result<RouteHandle> {
    let name = interface_name(ifindex)?;
    let family_flag = if dest.is_ipv6() { "-inet6" } else { "-inet" };
    let destination = format!("{dest}/{prefix_len}");
    let output = std::process::Command::new("/sbin/route")
        .args(["-n", "add", family_flag])
        .arg(&destination)
        .arg("-interface")
        // SAFETY: `name` is a CString built from a kernel interface name, so
        // the bytes are valid UTF-8-ish; a non-UTF-8 name cannot occur.
        .arg(name.to_str().expect("interface name is ASCII"))
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Adding a route that is already in the table is not a failure.
        if output.status.code() == Some(1)
            && stderr.to_ascii_lowercase().contains("file exists")
        {
            // fall through — the route is present, which is the goal
        } else {
            return Err(route_error("add", &stderr));
        }
    }

    Ok(RouteHandle {
        v6: dest.is_ipv6(),
        dest,
        prefix_len,
    })
}

/// Remove a route previously added by [`add_route`].
///
/// A route that is already gone — because the interface was removed first, or
/// a network manager swept it up — is the desired end state, not a failure, so
/// "not in table" counts as success. Callers during teardown ignore errors
/// anyway.
pub(crate) fn delete_route(handle: &RouteHandle) -> io::Result<()> {
    let family_flag = if handle.v6 { "-inet6" } else { "-inet" };
    let destination = format!("{}/{}", handle.dest, handle.prefix_len);
    let output = std::process::Command::new("/sbin/route")
        .args(["-n", "delete", family_flag])
        .arg(&destination)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lower = stderr.to_ascii_lowercase();
        if lower.contains("not in table") || lower.contains("no such process") {
            Ok(())
        } else {
            Err(route_error("delete", &stderr))
        }
    } else {
        Ok(())
    }
}

/// Build an error carrying the `route` command's stderr, which is where its
/// diagnostics live.
fn route_error(verb: &str, stderr: &str) -> io::Error {
    io::Error::other(format!("route {verb} failed: {}", stderr.trim()))
}

/// A datagram socket to carry interface ioctls on.
///
/// IPv6 address ioctls go over an `AF_INET6` socket (matching what
/// `ifconfig` does for inet6); everything else over `AF_INET`.
fn control_socket(family: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: socket(2) with plain constants.
    let raw = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh fd with no other owner.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// The interface name for an index, e.g. `utun4`.
fn interface_name(index: u32) -> io::Result<CString> {
    let mut buffer = [0i8; libc::IFNAMSIZ];
    // SAFETY: `buffer` is a live, correctly-sized local; if_indextoname writes
    // at most IFNAMSIZ bytes and NUL-terminates on success.
    let name = unsafe { libc::if_indextoname(index, buffer.as_mut_ptr()) };
    if name.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel wrote a NUL-terminated name into `buffer`.
    Ok(CString::from(unsafe { std::ffi::CStr::from_ptr(name) }))
}

/// Copy a NUL-terminated interface name into an `ifreq`-style name field.
fn fill_if_name(slot: &mut [libc::c_char], name: &CString) {
    for (slot, byte) in slot.iter_mut().zip(name.as_bytes_with_nul()) {
        *slot = *byte as libc::c_char;
    }
}

/// A `sockaddr_in` with the address set and everything else zero, viewed as
/// the raw `sockaddr` an `ifaliasreq` carries.
fn v4_sockaddr(addr: Ipv4Addr) -> libc::sockaddr {
    let mut sockaddr: libc::sockaddr = unsafe { std::mem::zeroed() };
    sockaddr.sa_len = std::mem::size_of::<libc::sockaddr_in>() as libc::c_uchar;
    sockaddr.sa_family = libc::AF_INET as libc::sa_family_t;
    // The address sits in the first four bytes of `sa_data`, the position of
    // `sin_addr` inside `sockaddr_in`.
    let octets = addr.octets();
    for (slot, byte) in sockaddr.sa_data.iter_mut().take(4).zip(octets) {
        *slot = byte as libc::c_char;
    }
    sockaddr
}

/// A `sockaddr_in6` with the address set and everything else zero.
fn v6_sockaddr(addr: Ipv6Addr) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as libc::c_uchar,
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: addr.octets(),
        },
        sin6_scope_id: 0,
    }
}

/// The netmask for a prefix length, e.g. `/24` → `255.255.255.0`.
fn netmask_v4(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::from(u32::MAX << (32 - prefix_len))
    }
}

/// The netmask for an IPv6 prefix length, e.g. `/64` → `ffff:ffff:ffff:ffff::`.
fn netmask_v6(prefix_len: u8) -> Ipv6Addr {
    if prefix_len == 0 {
        Ipv6Addr::UNSPECIFIED
    } else {
        Ipv6Addr::from(u128::MAX << (128 - prefix_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ioctl numbers must match the `_IOW`/`_IOWR` encodings from the
    /// xnu headers; a transcription error would make every address
    /// assignment fail with ENOTTY in a way that is hard to diagnose.
    #[test]
    fn ioctl_numbers_match_header_encodings() {
        // _IOW('i', 26, ifaliasreq): size 64, type 'i' (0x69), nr 26.
        assert_eq!(SIOCAIFADDR, 0x4040_691a);
        // _IOW('i', 26, in6_ifaliasreq): size 128.
        assert_eq!(SIOCAIFADDR_IN6, 0x4080_691a);
        // _IOW('i', 52, ifreq): size 32.
        assert_eq!(SIOCSIFMTU, 0x4020_6934);
        // _IOWR('i', 17, ifreq): direction 3.
        assert_eq!(SIOCGIFFLAGS, 0xc020_6911);
        // _IOW('i', 16, ifreq).
        assert_eq!(SIOCSIFFLAGS, 0x4020_6910);
    }

    /// The address records must be exactly the sizes the kernel expects, or
    /// the ioctl copies the wrong number of bytes.
    #[test]
    fn ioctl_struct_sizes() {
        assert_eq!(std::mem::size_of::<IfAliasRequest>(), 64);
        assert_eq!(std::mem::size_of::<In6AliasRequest>(), 128);
    }

    #[test]
    fn v4_netmasks() {
        assert_eq!(netmask_v4(0), Ipv4Addr::UNSPECIFIED);
        assert_eq!(netmask_v4(1), Ipv4Addr::new(128, 0, 0, 0));
        assert_eq!(netmask_v4(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(netmask_v4(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn v6_netmasks() {
        assert_eq!(netmask_v6(0), Ipv6Addr::UNSPECIFIED);
        assert_eq!(netmask_v6(1), Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(
            netmask_v6(64),
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0)
        );
        assert_eq!(
            netmask_v6(128),
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)
        );
    }

    /// The v4 sockaddr must carry the address in the first four bytes of
    /// `sa_data` — the `sin_addr` position inside `sockaddr_in`.
    #[test]
    fn v4_sockaddr_embeds_address_at_sin_addr_offset() {
        let addr = Ipv4Addr::new(10, 63, 7, 1);
        let sockaddr = v4_sockaddr(addr);
        assert_eq!(sockaddr.sa_len, std::mem::size_of::<libc::sockaddr_in>() as u8);
        assert_eq!(sockaddr.sa_family, libc::AF_INET as libc::sa_family_t);
        assert_eq!(
            &sockaddr.sa_data[..4],
            &[10, 63, 7, 1],
            "address must sit at the sin_addr offset"
        );
    }

    /// The v6 sockaddr must carry the full 16-byte address.
    #[test]
    fn v6_sockaddr_embeds_address() {
        let addr = Ipv6Addr::new(0xfd00, 0x0ace, 7, 0, 0, 0, 0, 1);
        let sockaddr = v6_sockaddr(addr);
        assert_eq!(sockaddr.sin6_len, std::mem::size_of::<libc::sockaddr_in6>() as u8);
        assert_eq!(sockaddr.sin6_family, libc::AF_INET6 as libc::sa_family_t);
        assert_eq!(sockaddr.sin6_addr.s6_addr, addr.octets());
    }
}
