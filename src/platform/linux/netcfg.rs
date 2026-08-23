//! Interface addressing and routing, via rtnetlink.
//!
//! Everything here goes through the rtnetlink socket (netlink-packet-route +
//! netlink-sys) rather than shelling out to `ip`: it is synchronous, returns
//! real error codes we can branch on, and does not depend on the machine's
//! locale. `ip` output parsing was the main source of flakiness in comparable
//! tools.
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
//! persistent TUN interface disappears when its last fd closes. That is what
//! makes hard-kill safe rather than merely unlikely to hurt.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::time::Duration;

use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable, NLM_F_ACK, NLM_F_CREATE,
    NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_route::address::{
    AddressAttribute, AddressHeaderFlag, AddressMessage, AddressScope,
};
use netlink_packet_route::link::{LinkAttribute, LinkFlag, LinkMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteFlag, RouteHeader, RouteMessage, RouteProtocol, RouteScope,
    RouteType,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::Socket;

use crate::platform::PhysicalInterface;

/// Probe destinations used to discover the physical interface that currently
/// carries internet traffic. Any globally-routable address works; these are
/// simply well-known and stable.
const V4_PROBE: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const V6_PROBE: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);

/// How long to wait for a netlink reply before giving up. A wedged kernel must
/// not hang engine startup forever.
const NETLINK_TIMEOUT: Duration = Duration::from_secs(2);

/// Netlink messages cannot exceed a page-based limit; 64 KiB is the largest
/// size any request we send can produce.
const RECEIVE_BUFFER: usize = 64 * 1024;

/// An empty receive buffer with the full netlink message size reserved.
///
/// `netlink_sys::Socket::recv` appends into a `bytes::BufMut`, so the buffer
/// must start empty (length 0) but pre-sized, or the datagram is truncated to
/// the spare capacity and lands past the slice we would read.
fn receive_buffer() -> Vec<u8> {
    Vec::with_capacity(RECEIVE_BUFFER)
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

/// Ask the kernel which interface would carry traffic to `dest`, the netlink
/// equivalent of `ip route get`. A family with no route yields `None`.
fn best_route_index(dest: IpAddr) -> Option<u32> {
    let mut netlink = Netlink::new().ok()?;

    let mut route = RouteMessage::default();
    route.header.address_family = family(dest);
    // The lookup flag makes the kernel answer with the winning route for
    // `dest` instead of a table dump.
    route.header.flags = vec![RouteFlag::LookupTable];
    route.attributes = vec![RouteAttribute::Destination(route_address(dest))];

    let mut request = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetRoute(route)),
    );
    request.header.flags = NLM_F_REQUEST;
    request.header.sequence_number = netlink.next_sequence();
    request.finalize();

    let mut buffer = vec![0u8; request.buffer_len()];
    request.serialize(&mut buffer);
    netlink.socket.send(&buffer, 0).ok()?;

    let mut receive = receive_buffer();
    loop {
        let received = netlink.socket.recv(&mut receive, 0).ok()?;
        let message = match NetlinkMessage::<RouteNetlinkMessage>::deserialize(&receive[..received])
        {
            Ok(m) => m,
            Err(_) => return None,
        };
        if message.header.sequence_number != request.header.sequence_number {
            continue;
        }
        match message.payload {
            // The kernel answers a `route get` lookup with an RTM_NEWROUTE
            // message (not RTM_GETROUTE), so both variants are handled.
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route))
            | NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetRoute(route)) => {
                for attribute in route.attributes {
                    if let RouteAttribute::Oif(ifindex) = attribute {
                        return Some(ifindex);
                    }
                }
            }
            NetlinkPayload::Done(_) => return None,
            NetlinkPayload::Error(error) if error.code.is_none() => return None,
            NetlinkPayload::Error(_) => return None,
            _ => {}
        }
    }
}

/// Assign a unicast address with the given on-link prefix length to `ifindex`.
pub(crate) fn add_address(ifindex: u32, addr: IpAddr, prefix_len: u8) -> io::Result<()> {
    let mut netlink = Netlink::new()?;

    let mut message = AddressMessage::default();
    message.header.family = family(addr);
    message.header.prefix_len = prefix_len;
    message.header.scope = AddressScope::Universe;
    message.header.index = ifindex;
    // IPv6 gets IFA_F_NODAD: duplicate address detection is meaningless on a
    // point-to-point tunnel we own, and waiting for it would add a visible
    // startup delay.
    message.header.flags = if addr.is_ipv6() {
        vec![AddressHeaderFlag::Nodad]
    } else {
        Vec::new()
    };
    // IPv4 carries the local address in IFA_LOCAL (and IFA_ADDRESS for the
    // peer, identical here); IPv6 has only IFA_ADDRESS.
    message.attributes = vec![AddressAttribute::Address(addr)];
    if addr.is_ipv4() {
        message.attributes.push(AddressAttribute::Local(addr));
    }

    let request = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(message)),
    );
    netlink
        .request_ack(request, NLM_F_CREATE | NLM_F_EXCL)
        .or_else(idempotent_already_exists)
}

/// Set the MTU and bring the link up in one round trip.
pub(crate) fn set_link_mtu_and_up(ifindex: u32, mtu: u16) -> io::Result<()> {
    let mut netlink = Netlink::new()?;

    let mut message = LinkMessage::default();
    message.header.interface_family = AddressFamily::Unspec;
    message.header.index = ifindex;
    // `change_mask` limits which flag bits the kernel changes; carrying only
    // `Up` there raises the link without touching anything else.
    message.header.flags = vec![LinkFlag::Up];
    message.header.change_mask = vec![LinkFlag::Up];
    message.attributes = vec![LinkAttribute::Mtu(mtu as u32)];

    let request = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(message)),
    );
    netlink.request_ack(request, 0)
}

/// A forwarding-table entry we created and are responsible for removing.
///
/// Deletion matches on the same identity the kernel keys routes by, so a
/// handle is self-contained and survives the interface it pointed at.
#[derive(Clone, Copy)]
pub(crate) struct RouteHandle {
    family: AddressFamily,
    dest: IpAddr,
    prefix_len: u8,
    ifindex: u32,
}

/// Add a route for `dest/prefix_len` out of `ifindex`.
///
/// Routes are on-link (`dev` only, no gateway): the tunnel is point-to-point,
/// so there is no next hop to forward through.
pub(crate) fn add_route(ifindex: u32, dest: IpAddr, prefix_len: u8) -> io::Result<RouteHandle> {
    let mut netlink = Netlink::new()?;

    let request = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route_message(
            family(dest), prefix_len, ifindex, dest,
        ))),
    );
    netlink
        .request_ack(request, NLM_F_CREATE | NLM_F_EXCL)
        .or_else(idempotent_already_exists)?;

    Ok(RouteHandle {
        family: family(dest),
        dest,
        prefix_len,
        ifindex,
    })
}

/// Remove a route previously added by [`add_route`].
///
/// A route that is already gone — because the interface was removed first, or
/// a network manager swept it up — is the desired end state, not a failure, so
/// `ESRCH` counts as success. Callers during teardown ignore errors anyway.
pub(crate) fn delete_route(handle: &RouteHandle) -> io::Result<()> {
    let mut netlink = Netlink::new()?;

    let request = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRoute(route_message(
            handle.family, handle.prefix_len, handle.ifindex, handle.dest,
        ))),
    );
    netlink.request_ack(request, 0).or_else(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::NotConnected
        ) {
            Ok(())
        } else {
            Err(error)
        }
    })
}

/// A unicast, on-link (`dev` only, no gateway) route in the main table, the
/// shape `ip route add <prefix> dev <if>` produces.
fn route_message(
    family: AddressFamily,
    prefix_len: u8,
    ifindex: u32,
    dest: IpAddr,
) -> RouteMessage {
    let mut message = RouteMessage::default();
    message.header.address_family = family;
    message.header.destination_prefix_length = prefix_len;
    message.header.table = RouteHeader::RT_TABLE_MAIN;
    message.header.protocol = RouteProtocol::Static;
    message.header.scope = RouteScope::Link;
    message.header.kind = RouteType::Unicast;
    message.attributes = vec![
        RouteAttribute::Destination(route_address(dest)),
        RouteAttribute::Oif(ifindex),
    ];
    message
}

/// Adding an address or route that already exists is not a failure.
fn idempotent_already_exists(error: io::Error) -> io::Result<()> {
    if error.kind() == io::ErrorKind::AlreadyExists {
        Ok(())
    } else {
        Err(error)
    }
}

/// The `AddressFamily` for an IP address.
fn family(addr: IpAddr) -> AddressFamily {
    match addr {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    }
}

/// The netlink `RouteAddress` encoding of an IP address.
fn route_address(addr: IpAddr) -> RouteAddress {
    match addr {
        IpAddr::V4(v4) => RouteAddress::Inet(v4),
        IpAddr::V6(v6) => RouteAddress::Inet6(v6),
    }
}

/// A synchronous rtnetlink socket with sequence numbers and ACK handling.
struct Netlink {
    socket: Socket,
    sequence: u32,
}

impl Netlink {
    fn new() -> io::Result<Self> {
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        socket.bind_auto()?;
        set_receive_timeout(&socket, NETLINK_TIMEOUT)?;
        Ok(Self {
            socket,
            sequence: 0,
        })
    }

    fn next_sequence(&mut self) -> u32 {
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        sequence
    }

    /// Send a request and wait for its ACK (or error).
    ///
    /// `extra_flags` are OR-ed into the request flags (e.g. `NLM_F_CREATE`).
    fn request_ack<I: NetlinkSerializable>(
        &mut self,
        mut request: NetlinkMessage<I>,
        extra_flags: u16,
    ) -> io::Result<()> {
        request.header.sequence_number = self.next_sequence();
        // Without NLM_F_ACK the kernel only replies on failure; the ACK is
        // what lets us wait for the operation to be committed.
        request.header.flags = NLM_F_REQUEST | NLM_F_ACK | extra_flags;
        request.finalize();

        let mut buffer = vec![0u8; request.buffer_len()];
        request.serialize(&mut buffer);
        self.socket.send(&buffer, 0)?;

        self.wait_for_ack(request.header.sequence_number)
    }

    /// Read messages until the ACK (or error) for `sequence` arrives.
    ///
    /// The kernel acknowledges with `NLMSG_ERROR` carrying code 0, which
    /// netlink-packet-core surfaces as an [`ErrorMessage`] with `code == None`.
    fn wait_for_ack(&mut self, sequence: u32) -> io::Result<()> {
        let mut receive = receive_buffer();
        loop {
            let received = self.socket.recv(&mut receive, 0)?;
            let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&receive[..received])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            if message.header.sequence_number != sequence {
                continue;
            }
            match message.payload {
                NetlinkPayload::Error(error) => match error.code {
                    None => return Ok(()),
                    Some(code) => return Err(io::Error::from_raw_os_error(-code.get())),
                },
                NetlinkPayload::Done(_) => return Ok(()),
                _ => continue,
            }
        }
    }
}

/// Bound the socket's receive wait so a silent kernel surfaces as an error
/// instead of a hang.
fn set_receive_timeout(socket: &Socket, duration: Duration) -> io::Result<()> {
    let timeout = libc::timeval {
        tv_sec: duration.as_secs() as libc::time_t,
        tv_usec: duration.subsec_micros() as libc::suseconds_t,
    };
    // SAFETY: `timeout` is a live, correctly-typed local; SO_RCVTIMEO copies
    // it into kernel memory.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
