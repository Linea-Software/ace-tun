//! TUN device lifecycle: create, address, route, and tear down.
//!
//! The device is an Apple utun interface owned by this process. Like the
//! Linux TUN interface it is non-persistent: closing the last fd destroys
//! it, which happens on normal drop *and* on abnormal termination (SIGKILL
//! closes fds for us). Because our routes point at the interface, they die
//! with it. That property is what makes the "hard-kill leaves the machine
//! online" requirement hold without a watchdog process — see
//! [`super::netcfg`] for the routing rationale.

use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::device::SessionHandle;
use crate::error::{Error, Result};
use crate::platform::{
    AdapterHandle, PhysicalInterface, TUN_IPV4, TUN_IPV4_PREFIX, TUN_IPV6, TUN_IPV6_PREFIX,
    TUN_MTU, V4_SPLIT_DEFAULT, V6_SPLIT_DEFAULT,
};

use super::netcfg::{self, RouteHandle};

/// Informational interface-name template.
///
/// macOS names utun interfaces `utun0`, `utun1`, … at creation time and the
/// name cannot be requested the way Linux accepts a template (there is no
/// `TUNSETIFF`; the kernel assigns the lowest free unit). This constant only
/// documents what the assigned names look like — the adapter logs the actual
/// name after creation.
pub const ADAPTER_NAME: &str = "utun%d";

/// The multicast prefixes, routed via the physical NIC so LAN discovery
/// (mDNS 5353, SSDP 1900, LLMNR 5355) never enters the tunnel. The split-
/// default routes below would otherwise cover them — macOS, like Linux, does
/// not auto-create a tunnel multicast route the way Windows does.
const MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 0);
const MULTICAST_V4_PREFIX: u8 = 4;
const MULTICAST_V6: Ipv6Addr = Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0);
const MULTICAST_V6_PREFIX: u8 = 8;

/// A live TUN adapter with addresses and routes installed.
pub(crate) struct TunAdapter {
    /// The fd owns the interface: closing it destroys the utun device and
    /// everything routed to it (the hard-kill safety property).
    fd: OwnedFd,
    /// Routes we installed, removed in reverse order of creation.
    routes: Vec<RouteHandle>,
}

impl TunAdapter {
    /// Create the device, assign addresses, bring it up, and install routes.
    ///
    /// The privilege check lives in [`Backend::create`] (see
    /// [`crate::platform::Backend`]); this function assumes it has passed.
    ///
    /// Routes are added last: until they exist, no traffic is diverted, so a
    /// failure partway through leaves the machine's networking untouched.
    pub(crate) fn create(ipv6: bool, iface: &PhysicalInterface) -> Result<Self> {
        let (fd, ifindex) = open_device()?;
        let mut adapter = Self {
            fd,
            routes: Vec::with_capacity(6),
        };

        netcfg::add_address(ifindex, IpAddr::V4(TUN_IPV4), TUN_IPV4_PREFIX)
            .map_err(|e| Error::netcfg("add_address(v4)", e))?;
        if ipv6 {
            netcfg::add_address(ifindex, IpAddr::V6(TUN_IPV6), TUN_IPV6_PREFIX)
                .map_err(|e| Error::netcfg("add_address(v6)", e))?;
        }
        netcfg::set_link_mtu_and_up(ifindex, TUN_MTU)
            .map_err(|e| Error::netcfg("set_link_mtu_and_up", e))?;

        // Multicast group routes via the physical NIC: LAN discovery traffic
        // keeps flowing on the real network instead of being pulled into the
        // tunnel (where the netstack drops group addresses).
        if let Some(physical) = iface.v4_index {
            adapter.install_route(physical, IpAddr::V4(MULTICAST_V4), MULTICAST_V4_PREFIX)?;
        }
        if ipv6
            && let Some(physical) = iface.v6_index
        {
            adapter.install_route(physical, IpAddr::V6(MULTICAST_V6), MULTICAST_V6_PREFIX)?;
        }

        for (net, prefix) in V4_SPLIT_DEFAULT {
            adapter.install_route(ifindex, IpAddr::V4(net), prefix)?;
        }
        if ipv6 {
            for (net, prefix) in V6_SPLIT_DEFAULT {
                adapter.install_route(ifindex, IpAddr::V6(net), prefix)?;
            }
        }

        Ok(adapter)
    }

    fn install_route(&mut self, ifindex: u32, dest: IpAddr, prefix: u8) -> Result<()> {
        let handle = netcfg::add_route(ifindex, dest, prefix)
            .map_err(|e| Error::netcfg(format!("add_route({dest}/{prefix})"), e))?;
        self.routes.push(handle);
        Ok(())
    }
}

impl AdapterHandle for TunAdapter {
    fn session(&self) -> io::Result<SessionHandle> {
        // The async device works on a dup so the adapter keeps the
        // authoritative fd — the interface's lifetime — while the device owns
        // an independent handle (dup shares the nonblocking file status).
        self.fd.try_clone()
    }

    fn shutdown_session(&self) {
        // There is no session to shut down on macOS; the fd stays open until
        // the adapter is dropped, and reads simply block (or return EAGAIN on
        // the nonblocking device fd).
    }

    fn remove_routes(&mut self) {
        for handle in self.routes.drain(..).rev() {
            if let Err(e) = netcfg::delete_route(&handle) {
                tracing::debug!("route removal returned {e} (already gone?)");
            }
        }
    }
}

impl Drop for TunAdapter {
    fn drop(&mut self) {
        self.remove_routes();
        // Closing `fd` destroys the interface and, with it, anything still
        // routed to it.
    }
}

/// Open a fresh utun interface through the `com.apple.net.utun_control`
/// kernel control, the same mechanism tun-rs and WireGuard use.
///
/// Returns the fd (which owns the interface's lifetime) and the
/// kernel-assigned interface index; the assigned name (`utunN`) is logged
/// here.
fn open_device() -> Result<(OwnedFd, u32)> {
    // SAFETY: socket(2) with plain constants.
    let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if raw < 0 {
        // SAFETY: `socket` just failed, so errno is set.
        let error = io::Error::last_os_error();
        return Err(if is_privilege_error(&error) {
            Error::NotElevated
        } else {
            Error::netcfg("socket(PF_SYSTEM)", error)
        });
    }
    // SAFETY: `raw` is a fresh fd with no other owner.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // Resolve the kernel control's id by name.
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    let control_name = b"com.apple.net.utun_control\0";
    for (slot, byte) in info.ctl_name.iter_mut().zip(control_name.iter()) {
        *slot = *byte as libc::c_char;
    }
    // SAFETY: `info` is fully initialised above and outlives the call;
    // CTLIOCGINFO fills in `ctl_id`.
    if unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::CTLIOCGINFO,
            &mut info as *mut libc::ctl_info as *mut libc::c_void,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        return Err(Error::netcfg("CTLIOCGINFO", error));
    }

    // Connect with unit 0: the kernel picks the lowest free utun unit, so a
    // leftover interface can never block startup.
    let address = libc::sockaddr_ctl {
        sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as libc::c_uchar,
        sc_family: libc::AF_SYSTEM as libc::c_uchar,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        sc_unit: 0,
        sc_reserved: [0; 5],
    };
    // SAFETY: `address` is a live, correctly-typed sockaddr of the right
    // length; connect copies it into kernel memory.
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            &address as *const libc::sockaddr_ctl as *const libc::sockaddr,
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } != 0
    {
        // SAFETY: `connect` just failed, so errno is set.
        let error = io::Error::last_os_error();
        return Err(if is_privilege_error(&error) {
            Error::NotElevated
        } else {
            Error::netcfg("connect(utun_control)", error)
        });
    }

    // Read back the assigned interface name ("utun4", ...).
    let mut name_buffer = [0u8; 64];
    let mut name_len: libc::socklen_t = name_buffer.len() as libc::socklen_t;
    // SAFETY: `name_buffer` is a live buffer of `name_len` bytes;
    // UTUN_OPT_IFNAME writes the NUL-terminated name into it.
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name_buffer.as_mut_ptr() as *mut libc::c_void,
            &mut name_len,
        )
    } != 0
    {
        return Err(Error::netcfg(
            "getsockopt(UTUN_OPT_IFNAME)",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: the kernel wrote a NUL-terminated name into `name_buffer`.
    let assigned = unsafe { std::ffi::CStr::from_ptr(name_buffer.as_ptr() as *const libc::c_char) }
        .to_string_lossy()
        .into_owned();
    if !assigned.starts_with("utun") {
        return Err(Error::netcfg(
            "UTUN_OPT_IFNAME",
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected utun interface name '{assigned}'"),
            ),
        ));
    }

    // The device must be nonblocking for the async wrapper.
    // SAFETY: `fd` is live; F_GETFL/F_SETFL take plain values.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(Error::netcfg(
            "fcntl(O_NONBLOCK)",
            io::Error::last_os_error(),
        ));
    }

    let name = CString::new(assigned.clone()).expect("kernel interface name has no NUL");
    // SAFETY: `name` is a live C string.
    let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if ifindex == 0 {
        return Err(Error::netcfg(
            "if_nametoindex",
            io::Error::last_os_error(),
        ));
    }

    tracing::debug!("utun device '{assigned}' up (ifindex {ifindex})");
    Ok((fd, ifindex))
}

/// A privilege failure from the utun setup — `EPERM` without root.
fn is_privilege_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
}
