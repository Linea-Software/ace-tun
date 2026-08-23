//! Process resolution on macOS: map a flow's endpoints to the owning PID via
//! the `net.inet.*.pcblist_n` sysctl tables.
//!
//! # How attribution works
//!
//! The kernel exports every protocol control block through the
//! `net.inet.tcp.pcblist_n` / `net.inet.udp.pcblist_n` sysctls — the same
//! tables `lsof -i` reads. Each dump starts with a fixed header
//! (`struct xinpgen`), followed by one `xinpcb_n` + `xsocket_n` record pair
//! per socket:
//!
//! * the **PCB record** carries the socket's family, local and foreign
//!   addresses and ports (`in_pcb.h`, `#pragma pack(4)`);
//! * the **socket record** carries `so_last_pid` — the PID of the most
//!   recent process to touch the socket, which for a freshly-opened flow is
//!   its owner (`socketvar.h`, `#pragma pack(4)`).
//!
//! Both records are variable-length (`xi_len` / `xso_len`-prefixed), so a
//! future OS can grow them without breaking the walk. The field offsets used
//! here are pinned by the compile-time assertions below, transcribed from
//! the macOS 14 xnu headers. The `pcblist_n` sysctls exist on macOS ≥ 10.15;
//! on older kernels the query fails and attribution returns `None` (the
//! engine fails open).
//!
//! The dump is a snapshot of the whole table — expensive relative to a
//! Windows table dump — so results are cached per endpoint for a short TTL,
//! like the Linux backend.

use std::collections::HashMap;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// How long endpoint→PID results are trusted before re-querying.
const CACHE_TTL: Duration = Duration::from_millis(250);

/// `INP_IPV6` from `<netinet/in_pcb.h>`: set in `inp_vflag` for v6 sockets.
const INP_IPV6: u8 = 0x2;

/// Field offsets and sizes within `struct xinpcb_n`
/// (`bsd/netinet/in_pcb.h`, `#pragma pack(4)`), as shipped in macOS 14.
/// The parser reads raw bytes at these offsets; the mirror struct below
/// pins them at compile time.
const XINPCB_OFFSET_LEN: usize = 0; // xi_len: u32
const XINPCB_OFFSET_FPORT: usize = 16; // inp_fport: u16, network order
const XINPCB_OFFSET_LPORT: usize = 18; // inp_lport: u16, network order
const XINPCB_OFFSET_VFLAG: usize = 44; // inp_vflag: u8
const XINPCB_OFFSET_FADDR: usize = 48; // inp_dependfaddr: 16 bytes
const XINPCB_OFFSET_LADDR: usize = 64; // inp_dependladdr: 16 bytes
const XINPCB_RECORD_LEN: usize = 100; // sizeof(struct xinpcb_n)

/// Field offsets within `struct xsocket_n` (`bsd/sys/socketvar.h`,
/// `#pragma pack(4)`).
const XSOCKET_OFFSET_LEN: usize = 0; // xso_len: u32
const XSOCKET_OFFSET_LAST_PID: usize = 68; // so_last_pid: pid_t
const XSOCKET_RECORD_LEN: usize = 104; // sizeof(struct xsocket_n)

/// Minimum size of the `struct xinpgen` header.
const XINGPEN_LEN: usize = 24;

/// Rust mirrors of the two record layouts, used only to pin the offsets
/// above at compile time. The parser itself reads raw bytes, so it can
/// never alias or misalign.
///
/// The address unions are declared as `[u32; 4]` because the C unions
/// contain `u32` members (alignment 4); a plain `[u8; 16]` would align to 1
/// and shift every following field.
#[repr(C, packed(4))]
#[derive(Clone, Copy)]
struct XinpcbN {
    xi_len: u32,
    xi_kind: u32,
    xi_inpp: u64,
    inp_fport: u16,
    inp_lport: u16,
    inp_ppcb: u64,
    inp_gencnt: u64,
    inp_flags: i32,
    inp_flow: u32,
    inp_vflag: u8,
    inp_ip_ttl: u8,
    inp_ip_p: u8,
    inp_dependfaddr: [u32; 4],
    inp_dependladdr: [u32; 4],
    inp4_ip_tos: u8,
    inp6_hlim: u8,
    inp6_cksum: i32,
    inp6_ifindex: u16,
    inp6_hops: i16,
    inp_flowhash: u32,
    inp_flags2: u32,
}

/// Rust mirror of `struct xsocket_n` (see [`XinpcbN`]).
#[repr(C, packed(4))]
#[derive(Clone, Copy)]
struct XsocketN {
    xso_len: u32,
    xso_kind: u32,
    xso_so: u64,
    so_type: i16,
    so_options: u32,
    so_linger: i16,
    so_state: i16,
    so_pcb: u64,
    xso_protocol: i32,
    xso_family: i32,
    so_qlen: i16,
    so_incqlen: i16,
    so_qlimit: i16,
    so_timeo: i16,
    so_error: u16,
    so_pgid: i32,
    so_oobmark: u32,
    so_uid: u32,
    so_last_pid: i32,
    so_e_pid: i32,
    so_gencnt: u64,
    so_flags: u32,
    so_flags1: u32,
    so_usecount: i32,
    so_retaincnt: i32,
    xso_filter_flags: u32,
}

/// Transcribe the offsets from the xnu headers: if the mirror structs drift
/// from the offsets the parser reads, this fails the build.
const _: () = {
    use std::mem::{offset_of, size_of};
    assert!(offset_of!(XinpcbN, xi_len) == XINPCB_OFFSET_LEN);
    assert!(offset_of!(XinpcbN, inp_fport) == XINPCB_OFFSET_FPORT);
    assert!(offset_of!(XinpcbN, inp_lport) == XINPCB_OFFSET_LPORT);
    assert!(offset_of!(XinpcbN, inp_vflag) == XINPCB_OFFSET_VFLAG);
    assert!(offset_of!(XinpcbN, inp_dependfaddr) == XINPCB_OFFSET_FADDR);
    assert!(offset_of!(XinpcbN, inp_dependladdr) == XINPCB_OFFSET_LADDR);
    assert!(size_of::<XinpcbN>() == XINPCB_RECORD_LEN);
    assert!(offset_of!(XsocketN, xso_len) == XSOCKET_OFFSET_LEN);
    assert!(offset_of!(XsocketN, so_last_pid) == XSOCKET_OFFSET_LAST_PID);
    assert!(size_of::<XsocketN>() == XSOCKET_RECORD_LEN);
};

/// Whether the current process is root — the privilege utun creation needs.
///
/// Unlike Linux there are no file capabilities to query, and unlike Windows
/// there is no token to inspect: `geteuid() == 0` is the whole story.
pub(crate) fn is_privileged() -> bool {
    // SAFETY: plain uid query.
    unsafe { libc::geteuid() == 0 }
}

/// Resolve the PID that owns the flow's local endpoint, or `None` if not
/// found. `remote` is the flow's destination — the owning socket's peer.
pub(crate) fn resolve_pid(local: SocketAddr, remote: SocketAddr, is_udp: bool) -> Option<u32> {
    let now = Instant::now();
    let key = EndpointKey {
        ip: local.ip(),
        port: local.port(),
        is_udp,
    };

    {
        let cache = CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((pid, cached_at)) = cache.endpoints.get(&key)
            && now.duration_since(*cached_at) < CACHE_TTL
        {
            return Some(*pid);
        }
    }

    let table = pcblist_table(is_udp)?;
    let pid = scan_pcblist(&table, local, remote);

    if let Some(pid) = pid {
        let mut cache = CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.endpoints.insert(key, (pid, now));
        Some(pid)
    } else {
        None
    }
}

/// Resolve the executable *file name* for a PID, e.g. `chrome` — the
/// kernel's short process name (`pbi_comm`), which never carries a `.exe`
/// suffix; rule matching normalises both sides (see `crate::rule`).
pub(crate) fn process_name(pid: u32) -> Option<String> {
    // SAFETY: `info` is a live, correctly-sized buffer; proc_pidinfo fills
    // it when the process exists and returns its length on success.
    let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdshortinfo>() };
    let written = unsafe {
        libc::proc_pidinfo(
            pid as libc::pid_t,
            libc::PROC_PIDT_SHORTBSDINFO,
            0,
            &mut info as *mut libc::proc_bsdshortinfo as *mut std::ffi::c_void,
            std::mem::size_of::<libc::proc_bsdshortinfo>() as libc::c_int,
        )
    };
    if written != std::mem::size_of::<libc::proc_bsdshortinfo>() as libc::c_int {
        return None;
    }
    // `pbi_comm` is a fixed `MAXCOMLEN`-byte field, not guaranteed
    // NUL-terminated; take everything up to the first NUL.
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            info.pbsi_comm.as_ptr() as *const u8,
            info.pbsi_comm.len(),
        )
    };
    let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(bytes.len());
    let name = std::str::from_utf8(&bytes[..end]).ok()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Fetch one `pcblist_n` table, sized by the kernel first.
///
/// The size-then-fetch dance exists because the table grows between the two
/// calls; `sysctlbyname` truncates to the buffer we give it, which is fine —
/// a slightly stale snapshot is exactly what the per-endpoint cache absorbs.
fn pcblist_table(is_udp: bool) -> Option<Vec<u8>> {
    let name = if is_udp {
        "net.inet.udp.pcblist_n"
    } else {
        "net.inet.tcp.pcblist_n"
    };
    let name = CString::new(name).ok()?;

    // SAFETY: `name` is live; NULL oldp with a zeroed length queries the size.
    let mut length: libc::size_t = 0;
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || length == 0 {
        // ENOENT on macOS < 10.15: fail open (no attribution).
        return None;
    }

    let mut table = vec![0u8; length];
    // SAFETY: `table` is a live buffer of `length` bytes; the kernel copies
    // at most that many and reports the actual size in `length`.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            table.as_mut_ptr() as *mut libc::c_void,
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    table.truncate(length);
    Some(table)
}

/// A candidate match: the owning PID and how specifically the record matched.
struct Candidate {
    pid: u32,
    /// 3 = full four-tuple (connected socket), 2 = specific local endpoint,
    /// 1 = wildcard bind.
    specificity: u8,
}

/// Walk a `pcblist_n` table and return the PID of the socket that owns the
/// flow's local endpoint, preferring the most specific match.
///
/// A listening socket and its accepted children share a local endpoint, so
/// the remote endpoint is what tells them apart: the connected child scores
/// above the listener it hangs off.
fn scan_pcblist(table: &[u8], local: SocketAddr, remote: SocketAddr) -> Option<u32> {
    // Skip the `struct xinpgen` header, whose first field is its own size.
    let mut offset = read_u32_le(table, XINPCB_OFFSET_LEN)? as usize;
    if offset < XINGPEN_LEN {
        return None;
    }

    let mut best: Option<Candidate> = None;
    while let Some((inpcb_end, socket_end)) = next_record_pair(table, offset) {
        if let Some(candidate) = score_record(
            &table[offset..inpcb_end],
            &table[inpcb_end..socket_end],
            local,
            remote,
        ) && best.as_ref().is_none_or(|best| candidate.specificity > best.specificity)
        {
            best = Some(candidate);
        }
        offset = socket_end;
    }
    best.map(|candidate| candidate.pid)
}

/// Bounds of the next `xinpcb_n` + `xsocket_n` record pair, or `None` at the
/// end of the table (or on malformed data — a truncated dump is treated like
/// the end of a valid one).
fn next_record_pair(table: &[u8], offset: usize) -> Option<(usize, usize)> {
    let inpcb_len = read_u32_le(table, offset)? as usize;
    // The record must at least contain the fields we read; current kernels
    // ship records larger than this, and the walk advances by the *declared*
    // length either way.
    if inpcb_len < XINPCB_OFFSET_LADDR + 16 {
        return None;
    }
    let inpcb_end = offset.checked_add(inpcb_len)?;
    if inpcb_end > table.len() {
        return None;
    }
    let socket_len = read_u32_le(table, inpcb_end)? as usize;
    if socket_len < XSOCKET_OFFSET_LAST_PID + 4 {
        return None;
    }
    let socket_end = inpcb_end.checked_add(socket_len)?;
    if socket_end > table.len() {
        return None;
    }
    Some((inpcb_end, socket_end))
}

/// Extract the endpoints from one PCB/socket record pair and score it against
/// the queried flow; `None` means the record is not this flow's socket.
fn score_record(
    inpcb: &[u8],
    socket: &[u8],
    local: SocketAddr,
    remote: SocketAddr,
) -> Option<Candidate> {
    // Family gate: a v4 flow never matches a v6 socket.
    let is_v6 = inpcb.get(XINPCB_OFFSET_VFLAG)? & INP_IPV6 != 0;
    if is_v6 != local.is_ipv6() {
        return None;
    }

    // Ports are stored in network byte order in the PCB.
    let local_port = read_u16_be(inpcb, XINPCB_OFFSET_LPORT)?;
    let foreign_port = read_u16_be(inpcb, XINPCB_OFFSET_FPORT)?;
    if local_port != local.port() {
        return None;
    }
    let local_addr = read_address(inpcb, XINPCB_OFFSET_LADDR, is_v6)?;
    let foreign_addr = read_address(inpcb, XINPCB_OFFSET_FADDR, is_v6)?;

    // Match specificity mirrors the Linux fallback chain: a connected socket
    // is identified by the full four-tuple, a specific bind by local
    // endpoint, and a wildcard bind by port alone.
    let connected = foreign_port != 0 && !foreign_addr.is_unspecified();
    let specificity = if connected
        && local_addr == local.ip()
        && foreign_addr == remote.ip()
        && foreign_port == remote.port()
    {
        3
    } else if !local_addr.is_unspecified() && local_addr == local.ip() {
        2
    } else if local_addr.is_unspecified() {
        1
    } else {
        return None;
    };

    let pid = read_i32_le(socket, XSOCKET_OFFSET_LAST_PID)?;
    if pid <= 0 {
        // Kernel-owned sockets have no owner; nothing to attribute.
        return None;
    }
    Some(Candidate {
        pid: pid as u32,
        specificity,
    })
}

/// Read a 16-byte address from the record at `offset`, as v4 (last four
/// bytes of the 4-in-6 union slot) or v6 (all sixteen).
fn read_address(record: &[u8], offset: usize, is_v6: bool) -> Option<IpAddr> {
    if is_v6 {
        let octets: [u8; 16] = record.get(offset..offset + 16)?.try_into().ok()?;
        Some(IpAddr::V6(Ipv6Addr::from(octets)))
    } else {
        // `inp46_local` is `struct in_addr_4in6`: three padding u32s followed
        // by the 4-byte v4 address.
        let octets: [u8; 4] = record.get(offset + 12..offset + 16)?.try_into().ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(octets)))
    }
}

/// Read a native (little-endian) u32, as all record lengths are.
fn read_u32_le(record: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = record.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Read a network-order u16 (a PCB port).
fn read_u16_be(record: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = record.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

/// Read a native (little-endian) i32 (a PID).
fn read_i32_le(record: &[u8], offset: usize) -> Option<i32> {
    let bytes: [u8; 4] = record.get(offset..offset + 4)?.try_into().ok()?;
    Some(i32::from_le_bytes(bytes))
}

/// Cache key: the flow's local endpoint.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct EndpointKey {
    ip: IpAddr,
    port: u16,
    is_udp: bool,
}

/// Endpoint→PID cache with a short TTL (see module docs).
struct ProcessCache {
    endpoints: HashMap<EndpointKey, (u32, Instant)>,
}

static CACHE: LazyLock<Mutex<ProcessCache>> = LazyLock::new(|| {
    Mutex::new(ProcessCache {
        endpoints: HashMap::new(),
    })
});

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one PCB/socket record pair with the endpoints and PID given,
    /// writing every field at the *literal* offsets from the xnu headers —
    /// independent of the parser's own constants.
    fn record_pair(
        pid: u32,
        local_addr: [u8; 16],
        local_port: u16,
        foreign_addr: [u8; 16],
        foreign_port: u16,
        is_v6: bool,
    ) -> Vec<u8> {
        let mut inpcb = vec![0u8; XINPCB_RECORD_LEN];
        inpcb[0..4].copy_from_slice(&(XINPCB_RECORD_LEN as u32).to_le_bytes());
        inpcb[16..18].copy_from_slice(&foreign_port.to_be_bytes());
        inpcb[18..20].copy_from_slice(&local_port.to_be_bytes());
        inpcb[44] = if is_v6 { 0x2 } else { 0x1 };
        // Foreign address union at 48, local at 64; a v4 address sits in the
        // last four bytes of its 4-in-6 slot.
        write_address(&mut inpcb, 48, &foreign_addr, is_v6);
        write_address(&mut inpcb, 64, &local_addr, is_v6);

        let mut socket = vec![0u8; XSOCKET_RECORD_LEN];
        socket[0..4].copy_from_slice(&(XSOCKET_RECORD_LEN as u32).to_le_bytes());
        socket[68..72].copy_from_slice(&(pid as i32).to_le_bytes());
        inpcb.extend_from_slice(&socket);
        inpcb
    }

    /// Copy a 16-byte address into a record at `offset`, honouring the
    /// 4-in-6 slot for v4.
    fn write_address(record: &mut [u8], offset: usize, addr: &[u8; 16], is_v6: bool) {
        if is_v6 {
            record[offset..offset + 16].copy_from_slice(addr);
        } else {
            record[offset + 12..offset + 16].copy_from_slice(&addr[12..16]);
        }
    }

    /// A table with one record: a connected v4 TCP socket owned by pid 4242.
    fn connected_v4_table() -> Vec<u8> {
        let mut table = vec![0u8; XINGPEN_LEN];
        table[0..4].copy_from_slice(&(XINGPEN_LEN as u32).to_le_bytes());
        table.extend(record_pair(
            4242,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 63, 7, 1],
            12345,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8],
            443,
            false,
        ));
        table
    }

    #[test]
    fn connected_v4_socket_is_attributed() {
        let table = connected_v4_table();
        let local: SocketAddr = "10.63.7.1:12345".parse().unwrap();
        let remote: SocketAddr = "8.8.8.8:443".parse().unwrap();
        assert_eq!(scan_pcblist(&table, local, remote), Some(4242));
    }

    #[test]
    fn connected_v6_socket_is_attributed() {
        let local_addr = [0xfd, 0, 0x0a, 0xce, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let foreign_addr = [0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88];
        let mut table = vec![0u8; XINGPEN_LEN];
        table[0..4].copy_from_slice(&(XINGPEN_LEN as u32).to_le_bytes());
        table.extend(record_pair(777, local_addr, 443, foreign_addr, 53, true));

        let local: SocketAddr = "[fd00:ace:7::1]:443".parse().unwrap();
        let remote: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
        assert_eq!(scan_pcblist(&table, local, remote), Some(777));
    }

    #[test]
    fn wrong_remote_does_not_match() {
        let table = connected_v4_table();
        let local: SocketAddr = "10.63.7.1:12345".parse().unwrap();
        let remote: SocketAddr = "1.1.1.1:443".parse().unwrap();
        assert_eq!(scan_pcblist(&table, local, remote), None);
    }

    /// A listener and its accepted child share a local endpoint; the child
    /// (full four-tuple) must win over the listener (local-only), regardless
    /// of table order.
    #[test]
    fn accepted_child_beats_listener() {
        let mut table = vec![0u8; XINGPEN_LEN];
        table[0..4].copy_from_slice(&(XINGPEN_LEN as u32).to_le_bytes());
        // Listener first: pid 9001, port 8080, no peer.
        table.extend(record_pair(
            9001,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 63, 7, 1],
            8080,
            [0; 16],
            0,
            false,
        ));
        // Accepted child: pid 9002, same local endpoint, peer 9.9.9.9:80.
        table.extend(record_pair(
            9002,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 63, 7, 1],
            8080,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9],
            80,
            false,
        ));

        let local: SocketAddr = "10.63.7.1:8080".parse().unwrap();
        let remote: SocketAddr = "9.9.9.9:80".parse().unwrap();
        assert_eq!(scan_pcblist(&table, local, remote), Some(9002));
    }

    /// A wildcard-bind socket matches any flow on its port (specificity 1).
    #[test]
    fn wildcard_bind_matches_by_port() {
        let mut table = vec![0u8; XINGPEN_LEN];
        table[0..4].copy_from_slice(&(XINGPEN_LEN as u32).to_le_bytes());
        table.extend(record_pair(
            31337,
            [0; 16],
            5353,
            [0; 16],
            0,
            false,
        ));

        let local: SocketAddr = "10.1.2.3:5353".parse().unwrap();
        let remote: SocketAddr = "224.0.0.251:5353".parse().unwrap();
        assert_eq!(scan_pcblist(&table, local, remote), Some(31337));
    }

    /// A flow of one family never matches a socket of the other.
    #[test]
    fn family_mismatch_does_not_match() {
        let mut table = vec![0u8; XINGPEN_LEN];
        table[0..4].copy_from_slice(&(XINGPEN_LEN as u32).to_le_bytes());
        // v4 socket...
        table.extend(record_pair(
            4242,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 63, 7, 1],
            12345,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8],
            443,
            false,
        ));
        // ...queried as v6.
        let local: SocketAddr = "[fd00:ace:7::1]:12345".parse().unwrap();
        let remote: SocketAddr = "[2001:4860:4860::8888]:443".parse().unwrap();
        assert_eq!(scan_pcblist(&table, local, remote), None);
    }

    /// A socket with no owner (`so_last_pid` = 0) attributes nothing.
    #[test]
    fn ownerless_socket_is_not_attributed() {
        let mut table = vec![0u8; XINGPEN_LEN];
        table[0..4].copy_from_slice(&(XINGPEN_LEN as u32).to_le_bytes());
        table.extend(record_pair(0, [0; 16], 9999, [0; 16], 0, false));
        let local: SocketAddr = "10.0.0.1:9999".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:9999".parse().unwrap();
        assert_eq!(scan_pcblist(&table, local, remote), None);
    }

    /// Truncated or malformed tables must not panic; they attribute nothing.
    #[test]
    fn malformed_tables_do_not_panic() {
        let local: SocketAddr = "10.0.0.1:9999".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:9999".parse().unwrap();

        // Empty.
        assert_eq!(scan_pcblist(&[], local, remote), None);
        // Header only.
        assert_eq!(scan_pcblist(&[0u8; XINGPEN_LEN], local, remote), None);
        // Header claiming a huge size.
        let mut header = vec![0u8; XINGPEN_LEN];
        header[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(scan_pcblist(&header, local, remote), None);
        // Records cut off mid-way.
        let mut table = connected_v4_table();
        table.truncate(table.len() - 20);
        assert_eq!(scan_pcblist(&table, local, remote), None);
    }

    /// Byte-order helpers must match the record encodings: lengths and PIDs
    /// native (little-endian), ports network order.
    #[test]
    fn byte_order_helpers() {
        assert_eq!(read_u32_le(&42u32.to_le_bytes(), 0), Some(42));
        assert_eq!(read_u16_be(&443u16.to_be_bytes(), 0), Some(443));
        assert_eq!(read_i32_le(&(-5i32).to_le_bytes(), 0), Some(-5));
        assert_eq!(read_u32_le(&[1, 2], 0), None);
    }
}
