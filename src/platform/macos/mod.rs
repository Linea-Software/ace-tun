//! macOS backend: utun device (with the 4-byte AF header shim), ioctl-based
//! addressing, `route`-command routing, `IP_BOUND_IF` / `IPV6_BOUND_IF`
//! pinning, and sysctl `pcblist_n` process attribution.
//!
//! Implemented in Phase 2 of the cross-platform migration; see
//! `docs/cross-platform-report.md`.

pub(crate) mod adapter;
pub(crate) mod dial;
pub(crate) mod netcfg;
pub(crate) mod process;

use crate::error::Result;
use crate::platform::{Backend, PhysicalInterface, ProcessTable};

/// The macOS implementation of the [`Backend`] seam.
pub(crate) struct MacosBackend;

/// The macOS implementation of the [`ProcessTable`] seam.
pub(crate) struct MacosProcessTable;

impl Backend for MacosBackend {
    type Adapter = adapter::TunAdapter;

    fn create_privileged(ipv6: bool) -> Result<Self::Adapter> {
        adapter::TunAdapter::create(ipv6)
    }

    fn discover_physical_interface() -> PhysicalInterface {
        netcfg::discover_physical_interface()
    }

    fn is_privileged() -> bool {
        process::is_privileged()
    }
}

impl ProcessTable for MacosProcessTable {
    fn resolve_pid(local_ip: std::net::IpAddr, local_port: u16, is_udp: bool) -> Option<u32> {
        process::resolve_pid(local_ip, local_port, is_udp)
    }

    fn process_name(pid: u32) -> Option<String> {
        process::process_name(pid)
    }
}
