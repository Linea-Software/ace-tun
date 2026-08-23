//! Interface addressing and routing, via the IP Helper APIs.
//!
//! Everything here goes through `iphlpapi.dll` rather than shelling out to
//! `netsh`: it is synchronous, returns real error codes we can branch on, and
//! does not depend on the machine's UI language. `netsh` output parsing was the
//! main source of flakiness in comparable tools.
//!
//! # Routing strategy
//!
//! We never touch the system's existing default route. Instead we add the two
//! halves of the address space as *more specific* routes pointing at the TUN
//! adapter (see [`crate::platform::V4_SPLIT_DEFAULT`] /
//! [`crate::platform::V6_SPLIT_DEFAULT`]):
//!
//! * IPv4: `0.0.0.0/1` and `128.0.0.0/1`
//! * IPv6: `::/1` and `8000::/1`
//!
//! Longest-prefix match makes these win over any `0.0.0.0/0`, so traffic enters
//! the tunnel — but the original default route is still sitting there untouched.
//! Teardown is therefore just "delete our four routes", and if we never get to
//! run teardown at all (SIGKILL, bugcheck) the routes die with the adapter,
//! because Windows drops forwarding entries whose interface disappears and
//! WinTun destroys the adapter when the creating process's handle closes.
//! That is what makes hard-kill safe rather than merely unlikely to hurt.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2, GetBestRoute2,
    GetIpInterfaceEntry, IP_ADDRESS_PREFIX, InitializeIpForwardEntry,
    InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, SetIpInterfaceEntry,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0,
    IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual, MIB_IPPROTO_NETMGMT,
    SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};

/// Turn a `WIN32_ERROR` into a `Result`, treating `NO_ERROR` as success.
fn ok(code: WIN32_ERROR) -> io::Result<()> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code.0 as i32))
    }
}

/// As [`ok`], but `ERROR_OBJECT_ALREADY_EXISTS` also counts as success — adding
/// a route or address we already added is not a failure.
fn ok_idempotent(code: WIN32_ERROR) -> io::Result<()> {
    if code == ERROR_OBJECT_ALREADY_EXISTS {
        return Ok(());
    }
    ok(code)
}

/// Build a `SOCKADDR_INET` for `addr` with a zero port.
pub(crate) fn sockaddr_inet(addr: IpAddr) -> SOCKADDR_INET {
    let mut sa = SOCKADDR_INET::default();
    match addr {
        IpAddr::V4(v4) => {
            sa.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(v4.octets()),
                    },
                },
                sin_zero: [0; 8],
            };
        }
        IpAddr::V6(v6) => {
            sa.Ipv6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
                Anonymous: Default::default(),
            };
        }
    }
    sa
}

/// Ask the routing table which interface would carry traffic to `dest`.
///
/// Used by [`crate::platform::PhysicalInterface::discover`], which runs
/// *before* our own routes exist, so the answer describes the real network.
pub(crate) fn best_route_index(dest: IpAddr) -> Option<u32> {
    let dest_sa = sockaddr_inet(dest);
    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut best_src = SOCKADDR_INET::default();

    // SAFETY: all pointers reference live, correctly-typed locals; `GetBestRoute2`
    // only writes to `bestroute` / `bestsourceaddress`.
    let code = unsafe { GetBestRoute2(None, 0, None, &dest_sa, 0, &mut row, &mut best_src) };
    if code != NO_ERROR {
        return None;
    }
    Some(row.InterfaceIndex)
}

/// Assign a unicast address with the given on-link prefix length to `luid`.
///
/// `DadState` is forced to `Preferred` so the address is usable immediately:
/// duplicate address detection is meaningless on a point-to-point tunnel we
/// own, and waiting for it would add a visible startup delay.
pub(crate) fn add_address(luid: &NET_LUID_LH, addr: IpAddr, prefix_len: u8) -> io::Result<()> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: `row` is a live, correctly-typed local.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };

    row.InterfaceLuid = *luid;
    row.Address = sockaddr_inet(addr);
    row.OnLinkPrefixLength = prefix_len;
    row.DadState = IpDadStatePreferred;
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
    // Infinite lifetime; the address goes away with the adapter.
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;

    // SAFETY: `row` is fully initialised above and outlives the call.
    ok_idempotent(unsafe { CreateUnicastIpAddressEntry(&row) })
}

/// A forwarding-table entry we created and are responsible for removing.
///
/// No `Debug`: the inner row is a union whose inactive arms are uninitialised.
#[derive(Clone, Copy)]
pub(crate) struct RouteHandle(MIB_IPFORWARD_ROW2);

// SAFETY: `MIB_IPFORWARD_ROW2` is a plain C struct of integers and unions with
// no interior pointers, so moving it across threads is sound.
unsafe impl Send for RouteHandle {}
unsafe impl Sync for RouteHandle {}

/// Add a route for `dest/prefix_len` out of `luid`.
///
/// `metric` is the *route* metric; it is added to the interface metric to
/// produce the effective cost. We pass 0 and instead lower the interface metric
/// (see [`set_interface_metric`]) so the tunnel outranks the physical NIC even
/// when Windows has assigned that NIC an unusually low automatic metric.
pub(crate) fn add_route(
    luid: &NET_LUID_LH,
    dest: IpAddr,
    prefix_len: u8,
    metric: u32,
) -> io::Result<RouteHandle> {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: `row` is a live, correctly-typed local.
    unsafe { InitializeIpForwardEntry(&mut row) };

    row.InterfaceLuid = *luid;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr_inet(dest),
        PrefixLength: prefix_len,
    };
    // An all-zero next hop means "on-link": the tunnel is point-to-point, so
    // there is no gateway to forward through.
    row.NextHop = sockaddr_inet(match dest {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    });
    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;

    // SAFETY: `row` is fully initialised above and outlives the call.
    ok_idempotent(unsafe { CreateIpForwardEntry2(&row) })?;
    Ok(RouteHandle(row))
}

/// Remove a route previously added by [`add_route`].
///
/// Errors are returned but callers during teardown deliberately ignore them:
/// a route that is already gone (because the adapter was removed first) is the
/// desired end state, not a failure.
pub(crate) fn delete_route(handle: &RouteHandle) -> io::Result<()> {
    // SAFETY: the row was produced by a successful `CreateIpForwardEntry2` and
    // is a plain value with no dangling references.
    ok(unsafe { DeleteIpForwardEntry2(&handle.0) })
}

/// Force the interface metric for `luid` in `family`, disabling Windows'
/// automatic metric so our tunnel reliably outranks the physical NIC.
pub(crate) fn set_interface_metric(
    luid: &NET_LUID_LH,
    family: ADDRESS_FAMILY,
    metric: u32,
) -> io::Result<()> {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family,
        InterfaceLuid: *luid,
        ..Default::default()
    };

    // SAFETY: `row` has the two lookup keys set; the call fills in the rest.
    ok(unsafe { GetIpInterfaceEntry(&mut row) })?;

    row.UseAutomaticMetric = false;
    row.Metric = metric;
    // `SetIpInterfaceEntry` rejects a non-zero SitePrefixLength on IPv4 rows
    // that came straight out of `GetIpInterfaceEntry` — a documented quirk.
    if family == AF_INET {
        row.SitePrefixLength = 0;
    }

    // SAFETY: `row` was populated by the matching Get call.
    ok(unsafe { SetIpInterfaceEntry(&mut row) })
}

/// The address family constant for IPv4, re-exported so callers don't need the
/// `windows` crate in scope.
pub(crate) const FAMILY_V4: ADDRESS_FAMILY = AF_INET;
/// The address family constant for IPv6.
pub(crate) const FAMILY_V6: ADDRESS_FAMILY = AF_INET6;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_v4_roundtrips_family_and_address() {
        let sa = sockaddr_inet(IpAddr::V4(Ipv4Addr::new(10, 6, 7, 1)));
        // SAFETY: we just wrote the Ipv4 arm of the union.
        unsafe {
            assert_eq!(sa.si_family, AF_INET);
            assert_eq!(
                sa.Ipv4.sin_addr.S_un.S_addr,
                u32::from_ne_bytes([10, 6, 7, 1])
            );
        }
    }

    #[test]
    fn sockaddr_v6_roundtrips_family_and_address() {
        let addr = Ipv6Addr::new(0xfd00, 0xace, 7, 0, 0, 0, 0, 1);
        let sa = sockaddr_inet(IpAddr::V6(addr));
        // SAFETY: we just wrote the Ipv6 arm of the union.
        unsafe {
            assert_eq!(sa.si_family, AF_INET6);
            assert_eq!(sa.Ipv6.sin6_addr.u.Byte, addr.octets());
        }
    }
}
