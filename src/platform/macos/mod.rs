//! macOS backend: utun device (with the 4-byte AF header shim), ioctl-based
//! addressing, `route`-command routing, `IP_BOUND_IF` / `IPV6_BOUND_IF`
//! pinning, and sysctl `pcblist_n` process attribution.
//!
//! Implemented in Phase 2 of the cross-platform migration; see
//! `docs/cross-platform-report.md`. The code compiles for both Apple targets
//! but has not been exercised on real hardware from the development
//! environment — see report §8.4 for what needs a macOS machine.

pub(crate) mod adapter;
pub(crate) mod dial;
pub(crate) mod netcfg;
pub(crate) mod process;

use std::net::SocketAddr;

use crate::error::Result;
use crate::platform::{Backend, PhysicalInterface, ProcessTable};

/// The macOS implementation of the [`Backend`] seam.
pub struct MacosBackend;

/// The macOS implementation of the [`ProcessTable`] seam.
pub struct MacosProcessTable;

impl Backend for MacosBackend {
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

impl ProcessTable for MacosProcessTable {
    fn resolve_pid(local: SocketAddr, remote: SocketAddr, is_udp: bool) -> Option<u32> {
        process::resolve_pid(local, remote, is_udp)
    }

    fn process_name(pid: u32) -> Option<String> {
        process::process_name(pid)
    }
}
