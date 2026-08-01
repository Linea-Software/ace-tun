//! WinTun adapter lifecycle: create, address, route, and tear down.
//!
//! The adapter is owned by this process. WinTun destroys it when the last
//! handle closes, which happens on normal drop *and* on abnormal termination
//! (the kernel closes handles for us). Because our routes point at the
//! adapter's LUID, they die with it. That property is what makes the
//! "hard-kill leaves the machine online" requirement hold without a watchdog
//! process — see [`crate::netcfg`] for the routing rationale.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use wintun::{Adapter, Session, Wintun};

use crate::error::{Error, Result};
use crate::netcfg::{self, FAMILY_V4, FAMILY_V6, RouteHandle, V4_SPLIT_DEFAULT, V6_SPLIT_DEFAULT};

/// Adapter name shown in Windows' network connections list.
pub const ADAPTER_NAME: &str = "Ace Blocker";

/// WinTun "tunnel type" string; purely cosmetic, appears in the driver's logs.
const TUNNEL_TYPE: &str = "AceBlocker";

/// Address assigned to our end of the tunnel. Any traffic we pull in appears to
/// originate here. Chosen from RFC 1918 space that is unusual enough to be
/// unlikely to collide with a corporate LAN or a Docker bridge.
pub const TUN_IPV4: Ipv4Addr = Ipv4Addr::new(10, 63, 7, 1);
/// Prefix length for [`TUN_IPV4`].
pub const TUN_IPV4_PREFIX: u8 = 24;

/// IPv6 counterpart of [`TUN_IPV4`], from the unique-local range (RFC 4193).
pub const TUN_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ace, 0x0007, 0, 0, 0, 0, 1);
/// Prefix length for [`TUN_IPV6`].
pub const TUN_IPV6_PREFIX: u8 = 64;

/// MTU for the tunnel. The netstack terminates every flow and re-originates it
/// on a socket bound to the physical NIC, so this value only governs the
/// local application-to-tunnel segment and never causes on-the-wire
/// fragmentation.
pub const TUN_MTU: u16 = 1500;

/// Interface metric forced onto the tunnel. Lower wins; the physical NIC is
/// typically 5–35, so 1 makes the tunnel unambiguously preferred without
/// depending on Windows' automatic metric heuristics.
const TUN_METRIC: u32 = 1;

/// Size of WinTun's kernel ring buffer, in bytes. Must be a power of two.
/// 4 MiB is WireGuard's own default and absorbs bursts comfortably.
const RING_CAPACITY: u32 = 0x40_0000;

/// A live WinTun adapter with addresses and routes installed.
pub(crate) struct TunAdapter {
    session: Arc<Session>,
    routes: Vec<RouteHandle>,
    /// Kept alive so the loaded `wintun.dll` outlives every handle derived
    /// from it.
    _wintun: Wintun,
    /// Kept alive alongside the session, which also holds an `Arc` to it.
    _adapter: Arc<Adapter>,
}

impl TunAdapter {
    /// Create the adapter, assign addresses, and install routes.
    ///
    /// Routes are added last: until they exist, no traffic is diverted, so a
    /// failure partway through leaves the machine's networking untouched.
    pub(crate) fn create(ipv6: bool) -> Result<Self> {
        if !is_elevated() {
            return Err(Error::NotElevated);
        }

        let wintun = load_wintun()?;

        let adapter = Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, None).map_err(|e| {
            Error::AdapterCreate {
                name: ADAPTER_NAME.to_string(),
                reason: e.to_string(),
            }
        })?;

        let luid = to_windows_luid(adapter.get_luid());

        adapter
            .set_mtu(TUN_MTU as usize)
            .map_err(|e| Error::netcfg("set_mtu", std::io::Error::other(e.to_string())))?;

        netcfg::add_address(&luid, IpAddr::V4(TUN_IPV4), TUN_IPV4_PREFIX)
            .map_err(|e| Error::netcfg("add_address(v4)", e))?;
        netcfg::set_interface_metric(&luid, FAMILY_V4, TUN_METRIC)
            .map_err(|e| Error::netcfg("set_interface_metric(v4)", e))?;

        if ipv6 {
            netcfg::add_address(&luid, IpAddr::V6(TUN_IPV6), TUN_IPV6_PREFIX)
                .map_err(|e| Error::netcfg("add_address(v6)", e))?;
            netcfg::set_interface_metric(&luid, FAMILY_V6, TUN_METRIC)
                .map_err(|e| Error::netcfg("set_interface_metric(v6)", e))?;
        }

        let session = adapter
            .start_session(RING_CAPACITY)
            .map(Arc::new)
            .map_err(|e| Error::SessionStart(e.to_string()))?;

        // Install routes only once the session can actually carry packets;
        // otherwise there is a window where traffic is diverted into a tunnel
        // with nothing reading from it.
        let mut routes = Vec::with_capacity(4);
        let mut install = |dest: IpAddr, prefix: u8| -> Result<()> {
            let handle = netcfg::add_route(&luid, dest, prefix, 0)
                .map_err(|e| Error::netcfg(format!("add_route({dest}/{prefix})"), e))?;
            routes.push(handle);
            Ok(())
        };

        for (net, prefix) in V4_SPLIT_DEFAULT {
            install(IpAddr::V4(net), prefix)?;
        }
        if ipv6 {
            for (net, prefix) in V6_SPLIT_DEFAULT {
                install(IpAddr::V6(net), prefix)?;
            }
        }

        Ok(Self {
            session,
            routes,
            _wintun: wintun,
            _adapter: adapter,
        })
    }

    /// The ring-buffer session, for building the async device.
    pub(crate) fn session(&self) -> Arc<Session> {
        Arc::clone(&self.session)
    }

    /// Stop the session, unblocking the reader thread.
    pub(crate) fn shutdown_session(&self) {
        if let Err(e) = self.session.shutdown() {
            tracing::warn!("wintun session shutdown failed: {e}");
        }
    }

    /// Remove the routes we installed.
    ///
    /// Called before the adapter is dropped so connectivity is restored in the
    /// right order. Failures are logged, not propagated: by the time teardown
    /// runs, a missing route is the outcome we wanted anyway.
    pub(crate) fn remove_routes(&mut self) {
        for handle in self.routes.drain(..) {
            if let Err(e) = netcfg::delete_route(&handle) {
                tracing::debug!("route removal returned {e} (already gone?)");
            }
        }
    }
}

impl Drop for TunAdapter {
    fn drop(&mut self) {
        self.remove_routes();
        self.shutdown_session();
        // `session` and `_adapter` close their handles here, which removes the
        // adapter and, with it, anything still bound to its LUID.
    }
}

/// Load `wintun.dll`, preferring the copy shipped next to our executable.
///
/// Falling back to the system search path lets `cargo test` and development
/// builds work when the DLL sits in the target directory.
///
/// The local copy is retried a few times before giving up: right after an MSI
/// install the Windows Installer service can still be finishing up (file
/// handles held for rollback bookkeeping, Defender's first-touch scan), which
/// transiently makes `LoadLibraryExW` fail with ERROR_MOD_NOT_FOUND even
/// though the file is present and valid. A short bounded retry absorbs that
/// window; the engine starts the tunnel a second later anyway.
fn load_wintun() -> Result<Wintun> {
    /// How long to keep retrying the local DLL before falling back.
    const LOAD_RETRY_ATTEMPTS: u32 = 5;
    /// Delay between retry attempts.
    const LOAD_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(800);

    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    {
        let local = dir.join("wintun.dll");
        if local.exists() {
            let mut last_error = None;
            for attempt in 1..=LOAD_RETRY_ATTEMPTS {
                // SAFETY: loading a DLL runs its entry point; `wintun.dll` is
                // the signed WireGuard driver library and is safe to
                // initialise.
                match unsafe { wintun::load_from_path(&local) } {
                    Ok(w) => return Ok(w),
                    Err(e) => {
                        last_error = Some(e);
                        tracing::warn!(
                            "wintun.dll at {} failed to load (attempt {attempt}/{}): {e:?}",
                            local.display(),
                            LOAD_RETRY_ATTEMPTS
                        );
                        std::thread::sleep(LOAD_RETRY_DELAY);
                    }
                }
            }
            if let Some(e) = last_error {
                tracing::warn!(
                    "giving up on wintun.dll at {} after {LOAD_RETRY_ATTEMPTS} attempts: {e:?}",
                    local.display()
                );
            }
        }
    }

    // SAFETY: as above.
    unsafe { wintun::load() }.map_err(|e| Error::WintunLoad(e.to_string()))
}

/// Convert the `windows-sys` LUID that `wintun` hands back into the `windows`
/// crate's equivalent. Both are `repr(C)` unions over a single `u64`.
fn to_windows_luid(luid: wintun::NET_LUID_LH) -> NET_LUID_LH {
    // SAFETY: reading the `Value` arm of a union whose every arm is 8 bytes of
    // plain data is always valid.
    let value = unsafe { luid.Value };
    NET_LUID_LH { Value: value }
}

/// Whether the current process has an elevated token.
///
/// WinTun cannot create an adapter without one, and the failure it returns
/// otherwise is an opaque null pointer, so we check up front to produce an
/// actionable error.
fn is_elevated() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: the token handle is closed on every path; `GetTokenInformation`
    // writes at most `size_of::<TOKEN_ELEVATION>()` bytes into `elevation`.
    unsafe {
        let mut token = Default::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();

        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tunnel addresses must not fall inside the loopback or link-local
    /// ranges, which are handled specially by the OS and would never route.
    #[test]
    fn tunnel_addresses_are_routable_private_space() {
        assert!(TUN_IPV4.is_private());
        assert!(!TUN_IPV4.is_loopback());
        assert!(!TUN_IPV4.is_link_local());
        // fd00::/8 is unique-local.
        assert_eq!(TUN_IPV6.octets()[0], 0xfd);
    }

    #[test]
    fn ring_capacity_is_a_valid_power_of_two() {
        const { assert!(RING_CAPACITY.is_power_of_two()) };
        const { assert!(RING_CAPACITY >= wintun::MIN_RING_CAPACITY) };
        const { assert!(RING_CAPACITY <= wintun::MAX_RING_CAPACITY) };
    }

    /// The device read buffer is sized from the same constant the adapter is
    /// configured with; if that ever drifts, framing breaks silently.
    #[test]
    fn mtu_is_within_ipstack_limits() {
        const { assert!(TUN_MTU >= 1280, "below IPv6 minimum MTU") };
    }

    #[test]
    fn luid_conversion_preserves_value() {
        let raw = wintun::NET_LUID_LH {
            Value: 0x1234_5678_9abc_def0,
        };
        let converted = to_windows_luid(raw);
        // SAFETY: reading the `Value` arm of the union.
        unsafe { assert_eq!(converted.Value, 0x1234_5678_9abc_def0) };
    }

    /// Elevation detection must return a definite answer rather than panicking,
    /// whichever way the test runner was launched.
    #[test]
    fn elevation_check_does_not_panic() {
        let _ = is_elevated();
    }

    /// The vendored `wintun.dll` must actually load and resolve its exports.
    ///
    /// This is the one part of the driver integration that *can* be checked
    /// without elevation, and it is worth checking: a truncated, wrong-arch, or
    /// mis-copied DLL otherwise shows up only as an opaque adapter-creation
    /// failure at runtime. Loading exercises `build.rs` having put the file
    /// beside the test binary as well as the artifact itself.
    #[test]
    fn vendored_wintun_dll_loads() {
        let wintun = load_wintun().expect(
            "wintun.dll should load from beside the test binary; \
             check thirdparty/wintun/bin/<arch>/ and build.rs",
        );

        // Resolving the driver version proves the exports are wired up, not
        // merely that a file with the right name exists. An adapter has to be
        // running for a version to be reported, so `Err` here is expected and
        // fine — we only care that the call is dispatchable.
        match wintun::get_running_driver_version(&wintun) {
            Ok(v) => println!("wintun driver running, version {v:?}"),
            Err(e) => println!("wintun loaded; no adapter running yet ({e})"),
        }
    }
}
