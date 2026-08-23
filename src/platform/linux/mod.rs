//! Linux backend: `/dev/net/tun` device, rtnetlink addressing/routing, socket
//! pinning via `IP_UNICAST_IF` / `IPV6_UNICAST_IF` (network order for both
//! families), and sock_diag-based process attribution.
//!
//! Implemented in Phase 1 of the cross-platform migration; see
//! `docs/cross-platform-report.md`.

pub(crate) mod adapter;
pub(crate) mod dial;
pub(crate) mod netcfg;
pub(crate) mod process;

use crate::error::Result;
use crate::platform::{Backend, PhysicalInterface, ProcessTable};

/// The Linux implementation of the [`Backend`] seam.
pub struct LinuxBackend;

/// The Linux implementation of the [`ProcessTable`] seam.
pub struct LinuxProcessTable;

impl Backend for LinuxBackend {
    type Adapter = adapter::TunAdapter;

    fn create_privileged(ipv6: bool, iface: &PhysicalInterface) -> Result<Self::Adapter> {
        adapter::TunAdapter::create(ipv6, iface)
    }

    fn discover_physical_interface() -> PhysicalInterface {
        netcfg::discover_physical_interface()
    }

    fn is_privileged() -> bool {
        process::is_privileged()
    }
}

impl ProcessTable for LinuxProcessTable {
    fn resolve_pid(local: std::net::SocketAddr, remote: std::net::SocketAddr, is_udp: bool) -> Option<u32> {
        process::resolve_pid(local, remote, is_udp)
    }

    fn process_name(pid: u32) -> Option<String> {
        process::process_name(pid)
    }
}
