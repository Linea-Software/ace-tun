//! TUN device lifecycle: create, address, route, and tear down.
//!
//! The device is owned by this process. The TUN interface is non-persistent:
//! the kernel destroys it when the last fd closes, which happens on normal
//! drop *and* on abnormal termination (SIGKILL closes fds for us). Because our
//! routes point at the interface, they die with it. That property is what
//! makes the "hard-kill leaves the machine online" requirement hold without a
//! watchdog process — see [`super::netcfg`] for the routing rationale.

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

/// Interface name template. The trailing `%d` makes the kernel assign
/// `ace0`, `ace1`, … so a leftover interface can never block startup.
pub const ADAPTER_NAME: &str = "ace%d";

/// The multicast prefixes, routed via the physical NIC so LAN discovery
/// (mDNS 5353, SSDP 1900, LLMNR 5355) never enters the tunnel. The split-
/// default routes below would otherwise cover them — Unix kernels do not
/// auto-create a tunnel multicast route the way Windows does.
const MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 0);
const MULTICAST_V4_PREFIX: u8 = 4;
const MULTICAST_V6: Ipv6Addr = Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0);
const MULTICAST_V6_PREFIX: u8 = 8;

/// `_IOW('T', 202, int)` — attach the fd to a TUN interface (`TUNSETIFF`).
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
/// `_IOW('T', 208, int)` — set the TUN offload mask (`TUNSETOFFLOAD`).
const TUNSETOFFLOAD: libc::c_ulong = 0x4004_54d0;

/// A live TUN adapter with addresses and routes installed.
pub(crate) struct TunAdapter {
    /// The fd owns the interface: closing it destroys the TUN device and
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
        // There is no session to shut down on Linux; the fd stays open until
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

/// Open `/dev/net/tun`, create the device node if it is missing (containers
/// often lack it), attach with `IFF_TUN | IFF_NO_PI`, and read back the
/// kernel-assigned interface index.
fn open_device() -> Result<(OwnedFd, u32)> {
    // Create the device node if missing. mknod needs CAP_MKNOD; errors are
    // ignored and the open below reports the real problem.
    if std::fs::metadata("/dev/net/tun").is_err() {
        let _ = std::fs::create_dir_all("/dev/net");
        // SAFETY: static NUL-terminated path; mode and device are plain
        // values.
        unsafe {
            libc::mknod(
                c"/dev/net/tun".as_ptr(),
                0o666 | libc::S_IFCHR,
                libc::makedev(10, 200),
            );
        }
    }

    // SAFETY: static NUL-terminated path; flags are plain values.
    let raw = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if raw < 0 {
        // SAFETY: `open` just failed, so errno is set.
        let error = io::Error::last_os_error();
        return Err(if is_privilege_error(&error) {
            Error::NotElevated
        } else {
            Error::netcfg("open(/dev/net/tun)", error)
        });
    }
    // SAFETY: `raw` is a fresh fd with no other owner.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: `request` is a live, zeroed ifreq; TUNSETIFF fills it with the
    // assigned interface name.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    let name = CString::new(ADAPTER_NAME).expect("static name has no NUL");
    for (slot, byte) in request.ifr_name.iter_mut().zip(name.as_bytes_with_nul()) {
        *slot = *byte as libc::c_char;
    }
    request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

    // SAFETY: `request` is fully initialised above and outlives the call.
    let rc = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            TUNSETIFF,
            &request as *const libc::ifreq as *const libc::c_void,
        )
    };
    if rc != 0 {
        let error = io::Error::last_os_error();
        return Err(if is_privilege_error(&error) {
            Error::NotElevated
        } else {
            Error::netcfg("TUNSETIFF", error)
        });
    }

    // A previous process may have left the TUN_F_* offload mask set on a
    // persistent interface. Without IFF_VNET_HDR we must clear it, or reads
    // return GSO aggregates as oversized single packets. No-op on a fresh
    // device; failure is logged, not fatal.
    // SAFETY: passing the address of a zero int; TUNSETOFFLOAD copies it.
    let zero = 0;
    unsafe {
        libc::ioctl(fd.as_raw_fd(), TUNSETOFFLOAD, &zero as *const libc::c_int);
    }

    // The device must be nonblocking for the async wrapper.
    // SAFETY: `fd` is live; F_GETFL/F_SETFL take plain values.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(Error::netcfg("fcntl(O_NONBLOCK)", io::Error::last_os_error()));
    }

    // SAFETY: the kernel wrote a NUL-terminated name into `request`.
    let assigned = unsafe { std::ffi::CStr::from_ptr(request.ifr_name.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let name = CString::new(assigned.clone()).expect("kernel interface name has no NUL");
    // SAFETY: `name` is a live C string.
    let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if ifindex == 0 {
        return Err(Error::netcfg(
            "if_nametoindex",
            io::Error::last_os_error(),
        ));
    }

    tracing::debug!("tun device '{assigned}' up (ifindex {ifindex})");
    Ok((fd, ifindex))
}

/// A privilege failure from the tun setup — `EPERM` without `CAP_NET_ADMIN`.
fn is_privilege_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
}
