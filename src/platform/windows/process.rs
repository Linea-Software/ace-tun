//! Process resolution: map a local `(ip, port)` endpoint to the owning PID and
//! executable name.
//!
//! Ported from ProxyBridge's `get_process_id_from_connection` /
//! `get_process_id_from_udp_connection` (via `GetExtendedTcpTable` /
//! `GetExtendedUdpTable`) and `get_process_name_from_pid` (via `OpenProcess` +
//! `QueryFullProcessImageNameW`).

// The table-class enums (`TCP_TABLE_CLASS` / `UDP_TABLE_CLASS`) are passed
// through a shared `i32` closure param and transmuted back at each call site;
// the two differ so a single annotated target type cannot be given.
#![allow(clippy::missing_transmute_annotations)]

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

/// Convert an IP-Helper table `dwLocalPort` field (network byte order stored in
/// the low 16 bits) to a host-order port. Equivalent to `ntohs((UINT16)field)`.
#[inline]
fn table_port_to_host(dw_local_port: u32) -> u16 {
    ((dw_local_port & 0xFFFF) as u16).swap_bytes()
}

/// Key an IPv4 address the same way the IP-Helper table stores `dwLocalAddr`
/// (the four address octets in memory order).
#[inline]
fn ipv4_table_key(ip: Ipv4Addr) -> u32 {
    u32::from_le_bytes(ip.octets())
}

/// Resolve the PID that owns the given local endpoint, or `None` if not found.
pub fn resolve_pid(local_ip: IpAddr, local_port: u16, is_udp: bool) -> Option<u32> {
    match local_ip {
        IpAddr::V4(v4) => {
            if is_udp {
                resolve_pid_udp_v4(v4, local_port).or_else(|| resolve_pid_tcp_v4(v4, local_port))
            } else {
                resolve_pid_tcp_v4(v4, local_port)
            }
        }
        IpAddr::V6(v6) => {
            if is_udp {
                resolve_pid_udp_v6(v6, local_port).or_else(|| resolve_pid_tcp_v6(v6, local_port))
            } else {
                resolve_pid_tcp_v6(v6, local_port)
            }
        }
    }
}

/// Fetch a variable-length IP-Helper owner-PID table into a byte buffer.
///
/// `fetch` is called twice: once with a null pointer to size the buffer and
/// once to fill it. Returns the raw bytes on success.
fn fetch_table<F>(family: u16, table_class: i32, mut fetch: F) -> Option<Vec<u8>>
where
    F: FnMut(Option<*mut c_void>, *mut u32, u32, i32) -> u32,
{
    let mut size: u32 = 0;
    let rc = fetch(None, &mut size, family as u32, table_class);
    if rc != ERROR_INSUFFICIENT_BUFFER.0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = fetch(
        Some(buf.as_mut_ptr() as *mut c_void),
        &mut size,
        family as u32,
        table_class,
    );
    if rc != NO_ERROR.0 {
        return None;
    }
    Some(buf)
}

fn resolve_pid_tcp_v4(ip: Ipv4Addr, port: u16) -> Option<u32> {
    let buf = fetch_table(
        AF_INET.0,
        TCP_TABLE_OWNER_PID_ALL.0,
        |ptr, size, af, class| unsafe {
            GetExtendedTcpTable(
                ptr,
                size,
                false,
                af,
                std::mem::transmute::<i32, _>(class),
                0,
            )
        },
    )?;
    let key = ipv4_table_key(ip);
    // SAFETY: buffer was filled by GetExtendedTcpTable with this exact layout.
    unsafe {
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        for row in rows {
            if row.dwLocalAddr == key && table_port_to_host(row.dwLocalPort) == port {
                return Some(row.dwOwningPid);
            }
        }
    }
    None
}

fn resolve_pid_udp_v4(ip: Ipv4Addr, port: u16) -> Option<u32> {
    let buf = fetch_table(
        AF_INET.0,
        UDP_TABLE_OWNER_PID.0,
        |ptr, size, af, class| unsafe {
            GetExtendedUdpTable(
                ptr,
                size,
                false,
                af,
                std::mem::transmute::<i32, _>(class),
                0,
            )
        },
    )?;
    let key = ipv4_table_key(ip);
    // SAFETY: buffer was filled by GetExtendedUdpTable with this exact layout.
    unsafe {
        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        // Exact match first, then INADDR_ANY (0.0.0.0) bound sockets.
        for row in rows {
            if row.dwLocalAddr == key && table_port_to_host(row.dwLocalPort) == port {
                return Some(row.dwOwningPid);
            }
        }
        for row in rows {
            if row.dwLocalAddr == 0 && table_port_to_host(row.dwLocalPort) == port {
                return Some(row.dwOwningPid);
            }
        }
    }
    None
}

fn resolve_pid_tcp_v6(ip: Ipv6Addr, port: u16) -> Option<u32> {
    let buf = fetch_table(
        AF_INET6.0,
        TCP_TABLE_OWNER_PID_ALL.0,
        |ptr, size, af, class| unsafe {
            GetExtendedTcpTable(
                ptr,
                size,
                false,
                af,
                std::mem::transmute::<i32, _>(class),
                0,
            )
        },
    )?;
    let octets = ip.octets();
    // SAFETY: buffer was filled by GetExtendedTcpTable with this exact layout.
    unsafe {
        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        for row in rows {
            if row.ucLocalAddr == octets && table_port_to_host(row.dwLocalPort) == port {
                return Some(row.dwOwningPid);
            }
        }
    }
    None
}

fn resolve_pid_udp_v6(ip: Ipv6Addr, port: u16) -> Option<u32> {
    let buf = fetch_table(
        AF_INET6.0,
        UDP_TABLE_OWNER_PID.0,
        |ptr, size, af, class| unsafe {
            GetExtendedUdpTable(
                ptr,
                size,
                false,
                af,
                std::mem::transmute::<i32, _>(class),
                0,
            )
        },
    )?;
    let octets = ip.octets();
    let any = [0u8; 16];
    // SAFETY: buffer was filled by GetExtendedUdpTable with this exact layout.
    unsafe {
        let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        for row in rows {
            if (row.ucLocalAddr == octets || row.ucLocalAddr == any)
                && table_port_to_host(row.dwLocalPort) == port
            {
                return Some(row.dwOwningPid);
            }
        }
    }
    None
}

/// Resolve the full executable path for a PID and return it.
pub fn process_path(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    // SAFETY: handle is checked and always closed before returning.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 260];
        let mut len = buf.len() as u32;
        let res = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(handle);
        if res.is_err() || len == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// Resolve the executable *file name* (basename) for a PID, e.g. `chrome.exe`.
pub fn process_name(pid: u32) -> Option<String> {
    process_path(pid).map(|p| file_name(&p).to_string())
}

/// Extract the file name from a Windows or Unix path.
pub fn file_name(path: &str) -> &str {
    let last = path.rfind(['\\', '/']).map(|i| i + 1).unwrap_or(0);
    &path[last..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_file_name() {
        assert_eq!(
            file_name(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            "chrome.exe"
        );
        assert_eq!(file_name("/usr/bin/firefox"), "firefox");
        assert_eq!(file_name("notepad.exe"), "notepad.exe");
        assert_eq!(file_name(""), "");
    }

    #[test]
    fn port_conversion_is_ntohs() {
        // Port 443 in network order is 0x01BB; stored in low bytes as bytes
        // [0x01, 0xBB]; read as LE u16 that is 0xBB01; swap -> 0x01BB = 443.
        let net_le = u16::from_le_bytes([0x01, 0xBB]) as u32;
        assert_eq!(table_port_to_host(net_le), 443);
        let net_le = u16::from_le_bytes([0x00, 0x50]) as u32; // 80
        assert_eq!(table_port_to_host(net_le), 80);
    }

    #[test]
    fn ipv4_key_matches_memory_order() {
        // 192.168.1.10 octets in memory -> LE u32.
        let ip = Ipv4Addr::new(192, 168, 1, 10);
        assert_eq!(ipv4_table_key(ip), u32::from_le_bytes([192, 168, 1, 10]));
    }

    #[test]
    fn resolve_own_process_smoke() {
        // The current process is guaranteed to be resolvable by PID.
        let pid = std::process::id();
        let name = process_name(pid);
        assert!(name.is_some(), "should resolve current process name");
    }

    #[test]
    fn resolve_pid_for_live_sockets() {
        let own_pid = std::process::id();

        // TCP — bind a listener on loopback:0, resolve, then drop.
        let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind TcpListener");
        let tcp_local = tcp_listener
            .local_addr()
            .expect("local_addr for TcpListener");
        let tcp_port = tcp_local.port();

        let tcp_pid = resolve_pid(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            tcp_port,
            false, // TCP
        );
        assert_eq!(
            tcp_pid,
            Some(own_pid),
            "TCP listener on 127.0.0.1:{tcp_port} should resolve to PID {own_pid}",
        );
        drop(tcp_listener);

        // UDP — bind a socket on loopback:0, resolve, then drop.
        let udp_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UdpSocket");
        let udp_local = udp_socket.local_addr().expect("local_addr for UdpSocket");
        let udp_port = udp_local.port();

        let udp_pid = resolve_pid(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            udp_port,
            true, // UDP
        );
        assert_eq!(
            udp_pid,
            Some(own_pid),
            "UDP socket on 127.0.0.1:{udp_port} should resolve to PID {own_pid}",
        );
        drop(udp_socket);
    }
}
