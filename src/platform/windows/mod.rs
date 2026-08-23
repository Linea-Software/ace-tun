//! Windows backend: WinTun adapter, IP Helper addressing/routing, socket
//! pinning via `IP_UNICAST_IF` / `IPV6_UNICAST_IF`, and owner-PID tables for
//! process attribution.

pub(crate) mod adapter;
pub(crate) mod dial;
pub(crate) mod netcfg;
pub(crate) mod process;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::Result;
use crate::platform::{Backend, PhysicalInterface, ProcessTable};

/// Probe destinations used to discover the physical interface that currently
/// carries internet traffic. Any globally-routable address works; these are
/// simply well-known and stable.
const V4_PROBE: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const V6_PROBE: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);

/// The Windows implementation of the [`Backend`] seam.
pub struct WindowsBackend;

/// The Windows implementation of the [`ProcessTable`] seam.
pub struct WindowsProcessTable;

impl Backend for WindowsBackend {
    type Adapter = adapter::TunAdapter;

    fn create_privileged(ipv6: bool) -> Result<Self::Adapter> {
        adapter::TunAdapter::create(ipv6)
    }

    fn discover_physical_interface() -> PhysicalInterface {
        PhysicalInterface {
            v4_index: netcfg::best_route_index(IpAddr::V4(V4_PROBE)),
            v6_index: netcfg::best_route_index(IpAddr::V6(V6_PROBE)),
        }
    }

    fn is_privileged() -> bool {
        adapter::is_elevated()
    }
}

impl ProcessTable for WindowsProcessTable {
    fn resolve_pid(local_ip: IpAddr, local_port: u16, is_udp: bool) -> Option<u32> {
        process::resolve_pid(local_ip, local_port, is_udp)
    }

    fn process_name(pid: u32) -> Option<String> {
        process::process_name(pid)
    }
}
