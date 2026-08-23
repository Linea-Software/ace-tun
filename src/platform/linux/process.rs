//! Process resolution on Linux: map a local `(ip, port)` endpoint to the
//! owning PID and executable name.
//!
//! # How attribution works
//!
//! The kernel exposes per-socket information over `NETLINK_SOCK_DIAG` — the
//! same mechanism `ss` uses. A query filtered to one local endpoint returns
//! the socket's *inode*. The inode is then mapped to a PID by walking every
//! `/proc/<pid>/fd` symlink looking for `socket:[<inode>]` — again, exactly
//! what `ss -p` does.
//!
//! Both steps are expensive relative to a Windows table dump, so results are
//! cached: the endpoint→PID answer for ~250 ms (a flow is attributed once, at
//! open, and repeated lookups hit the cache), and the inode→PID map is
//! rebuilt on any miss — a fresh scan cannot miss a socket that exists at
//! query time, so staleness never hides a live flow.
//!
//! `/proc/net/tcp` is *not* a substitute for the sock_diag query: it exposes
//! the socket's UID, not its PID.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_REQUEST};
use netlink_packet_sock_diag::{
    constants::{AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP},
    inet::{InetRequest, InetResponse, SocketId, StateFlags},
    SockDiagMessage,
};
use netlink_sys::protocols::NETLINK_SOCK_DIAG;
use netlink_sys::Socket;

/// How long endpoint→PID results are trusted before re-querying.
const CACHE_TTL: Duration = Duration::from_millis(250);

/// How long to wait for a sock_diag reply before giving up.
const NETLINK_TIMEOUT: Duration = Duration::from_secs(2);

/// Netlink messages cannot exceed a page-based limit; 64 KiB is the largest
/// size any response we handle can produce.
const RECEIVE_BUFFER: usize = 64 * 1024;

/// An empty receive buffer with the full netlink message size reserved.
///
/// `netlink_sys::Socket::recv` appends into a `bytes::BufMut`, so the buffer
/// must start empty (length 0) but pre-sized, or the datagram is truncated to
/// the spare capacity and lands past the slice we would read.
fn receive_buffer() -> Vec<u8> {
    Vec::with_capacity(RECEIVE_BUFFER)
}

/// Whether the current process holds the capabilities creating and running
/// the tunnel requires: `CAP_NET_ADMIN` for the TUN device, and `CAP_NET_RAW`
/// for the `SO_BINDTODEVICE` loop guard (see [`super::dial`]).
///
/// A non-root process can hold them via file capabilities, so query the
/// capability set rather than the uid; if the query itself fails (old kernel,
/// seccomp filter), fall back to "root".
pub(crate) fn is_privileged() -> bool {
    const CAP_NET_ADMIN: u32 = 12;
    const CAP_NET_RAW: u32 = 13;

    /// `struct __user_cap_header_struct` from `linux/capability.h`; the `libc`
    /// crate does not expose the capget family.
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    /// `struct __user_cap_data_struct` from `linux/capability.h`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    fn has_capability(data: &[CapData; 2], cap: u32) -> bool {
        let word = (cap / 32) as usize;
        let bit = 1u32 << (cap % 32);
        data[word].effective & bit != 0
    }

    // SAFETY: both structs are plain integers matching the kernel ABI; capget
    // writes at most two `CapData` entries for VERSION_3.
    unsafe {
        let mut header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        let rc = libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        );
        if rc == 0 {
            has_capability(&data, CAP_NET_ADMIN) && has_capability(&data, CAP_NET_RAW)
        } else {
            libc::geteuid() == 0
        }
    }
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

    let inode = query_socket_inode(local, remote, is_udp)?;
    let pid = inode_to_pid(inode);

    if let Some(pid) = pid {
        let mut cache = CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.endpoints.insert(key, (pid, now));
        Some(pid)
    } else {
        None
    }
}

/// Resolve the executable *file name* for a PID, e.g. `chrome`.
pub(crate) fn process_name(pid: u32) -> Option<String> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let name = comm.trim();
    if !name.is_empty() {
        return Some(name.to_string());
    }
    // Fall back to the executable basename for processes whose comm is empty
    // or unreadable.
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    exe.file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

/// Ask the kernel for the socket inode behind the flow's endpoints.
///
/// The socket-id fields have a per-protocol orientation, and the kernel
/// hashes sockets differently depending on their state, so each protocol
/// tries a small sequence of queries:
///
/// * **TCP** — the *send* orientation names the local endpoint in
///   `sport`/`src`. Established sockets are hashed by the full four-tuple, so
///   the first query carries the flow's remote endpoint too; listeners are
///   hashed by (local address, port), so the fallbacks drop the remote part
///   and then the address.
/// * **UDP** — the kernel's `udp_dump_one` calls `__udp4_lib_lookup` with the
///   request's fields in the *receive* orientation: it hashes on
///   `dport`/`dst` and scores `sk_dport == sport` plus `sk_rcv_saddr == src`
///   ("src and dst are swapped for historical reasons", `udp_diag.c`).
///   Connected sockets are hashed by (remote address, local port); unconnected
///   ones by (local address, local port).
fn query_socket_inode(local: SocketAddr, remote: SocketAddr, is_udp: bool) -> Option<u64> {
    let family = if local.is_ipv4() { AF_INET } else { AF_INET6 };
    let protocol = if is_udp { IPPROTO_UDP } else { IPPROTO_TCP };
    let local_address = local.ip();
    let local_port = local.port();
    let remote_address = remote.ip();
    let remote_port = remote.port();

    if is_udp {
        // Connected socket: hashed by (remote address, local port).
        query_one(
            family,
            protocol,
            SocketId {
                source_port: remote_port,
                destination_port: local_port,
                source_address: local_address,
                destination_address: remote_address,
                interface_id: 0,
                cookie: [0xff; 8],
            },
        )
        .or_else(|| {
            // Unconnected socket: hashed by (local address, local port).
            query_one(
                family,
                protocol,
                SocketId {
                    source_port: 0,
                    destination_port: local_port,
                    source_address: local_address,
                    destination_address: local_address,
                    interface_id: 0,
                    cookie: [0xff; 8],
                },
            )
        })
        .or_else(|| {
            // Wildcard-bound socket: hashed under the unspecified address.
            query_one(
                family,
                protocol,
                SocketId {
                    source_port: 0,
                    destination_port: local_port,
                    source_address: wildcard(local_address),
                    destination_address: wildcard(local_address),
                    interface_id: 0,
                    cookie: [0xff; 8],
                },
            )
        })
    } else {
        // Established client socket: hashed by the full four-tuple.
        query_one(
            family,
            protocol,
            SocketId {
                source_port: local_port,
                destination_port: remote_port,
                source_address: local_address,
                destination_address: remote_address,
                interface_id: 0,
                cookie: [0xff; 8],
            },
        )
        .or_else(|| {
            // Listening socket: hashed by (local address, local port).
            query_one(
                family,
                protocol,
                SocketId {
                    source_port: local_port,
                    destination_port: 0,
                    source_address: local_address,
                    destination_address: wildcard(local_address),
                    interface_id: 0,
                    cookie: [0xff; 8],
                },
            )
        })
        .or_else(|| {
            // Wildcard-bound listener: hashed under the unspecified address.
            query_one(
                family,
                protocol,
                SocketId {
                    source_port: local_port,
                    destination_port: 0,
                    source_address: wildcard(local_address),
                    destination_address: wildcard(local_address),
                    interface_id: 0,
                    cookie: [0xff; 8],
                },
            )
        })
    }
}

/// One sock_diag round trip for a specific socket id.
fn query_one(family: u8, protocol: u8, socket_id: SocketId) -> Option<u64> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG).ok()?;
    socket.bind_auto().ok()?;
    set_receive_timeout(&socket, NETLINK_TIMEOUT).ok()?;

    let request = InetRequest {
        family,
        protocol,
        // No extended info; the fixed response header is all we need.
        extensions: netlink_packet_sock_diag::inet::ExtensionFlags::empty(),
        states: StateFlags::all(),
        socket_id,
    };

    let mut message = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::InnerMessage(SockDiagMessage::InetRequest(request)),
    );
    message.header.sequence_number = 1;
    message.header.flags = NLM_F_REQUEST;
    message.finalize();

    let mut buffer = vec![0u8; message.buffer_len()];
    message.serialize(&mut buffer);
    socket.send(&buffer, 0).ok()?;

    let mut receive = receive_buffer();
    loop {
        let received = socket.recv(&mut receive, 0).ok()?;
        let parsed = NetlinkMessage::<SockDiagMessage>::deserialize(&receive[..received]).ok()?;
        if parsed.header.sequence_number != message.header.sequence_number {
            continue;
        }
        match parsed.payload {
            // The kernel answers either with the socket record or with
            // ENOENT; both terminate the loop.
            NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                return inode_of(response);
            }
            NetlinkPayload::Error(_) => return None,
            _ => {}
        }
    }
}

/// Pull the inode out of a sock_diag response, skipping zero inodes.
fn inode_of(response: Box<InetResponse>) -> Option<u64> {
    let inode = u64::from(response.header.inode);
    if inode == 0 {
        None
    } else {
        Some(inode)
    }
}

/// Map a socket inode to a PID by scanning `/proc/<pid>/fd` symlinks.
///
/// The cached map is reused for hits; any miss triggers a fresh scan. A socket
/// that exists at query time cannot be absent from a scan taken at that same
/// moment, so a miss-and-rescan always terminates correctly — the cache only
/// ever makes the common case cheaper, never less accurate.
fn inode_to_pid(inode: u64) -> Option<u32> {
    let mut cache = CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(pid) = cache
        .inodes
        .as_ref()
        .and_then(|(map, _)| map.get(&inode).copied())
    {
        return Some(pid);
    }
    cache.inodes = Some((scan_socket_inodes(), Instant::now()));
    cache
        .inodes
        .as_ref()
        .and_then(|(map, _)| map.get(&inode).copied())
}

/// Build a socket-inode → PID map by walking every process's fd table.
///
/// This is the same walk `ss -p` performs. Unreadable entries (permission
/// denied on another user's fd, races with process exit) are skipped.
fn scan_socket_inodes() -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let Some(inode) = socket_inode_of(&target.to_string_lossy()) else {
                continue;
            };
            map.entry(inode).or_insert(pid);
        }
    }
    map
}

/// Parse `socket:[<inode>]` out of an fd symlink target.
fn socket_inode_of(link_target: &str) -> Option<u64> {
    let rest = link_target.strip_prefix("socket:[")?;
    rest.strip_suffix(']')?.parse().ok()
}

/// The wildcard address of the same family as `ip`.
fn wildcard(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
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

/// Cache key: the local endpoint of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct EndpointKey {
    ip: IpAddr,
    port: u16,
    is_udp: bool,
}

/// Caches for attribution results.
#[derive(Default)]
struct ProcessCache {
    /// Endpoint → (PID, when it was resolved). TTL'd so repeated lookups of a
    /// live flow never touch the kernel twice.
    endpoints: HashMap<EndpointKey, (u32, Instant)>,
    /// Socket inode → PID map from the last `/proc` walk. Rebuilt on miss.
    inodes: Option<(HashMap<u64, u32>, Instant)>,
}

static CACHE: LazyLock<Mutex<ProcessCache>> =
    LazyLock::new(|| Mutex::new(ProcessCache::default()));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_socket_symlink_targets() {
        assert_eq!(socket_inode_of("socket:[123456]"), Some(123456));
        assert_eq!(socket_inode_of("socket:[0]"), Some(0));
        assert_eq!(socket_inode_of("/usr/bin/foo"), None);
        assert_eq!(socket_inode_of("socket:[abc]"), None);
        assert_eq!(socket_inode_of(""), None);
    }

    #[test]
    fn wildcard_address_matches_family() {
        assert_eq!(
            wildcard(IpAddr::V4(Ipv4Addr::new(10, 63, 7, 1))),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(
            wildcard(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        );
    }

    /// The current process's own sockets must resolve to our own PID, and its
    /// name must come back non-empty. Listener, established TCP, and UDP
    /// sockets are all exercised because their kernel hash-table placement
    /// (and therefore the sock_diag query shape) differs.
    #[test]
    fn resolves_own_process_for_live_sockets() {
        let own_pid = std::process::id();
        let remote: SocketAddr = "0.0.0.0:0".parse().expect("static addr");

        // Listening TCP socket: hashed by (local address, local port).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind TcpListener");
        let local = listener.local_addr().expect("local_addr");
        let pid = resolve_pid(local, remote, false);
        assert_eq!(pid, Some(own_pid), "TCP listener should resolve to our PID");

        // Established TCP socket: hashed by the full four-tuple. The accept
        // side must be live or the connect fails.
        let accepted = std::thread::spawn(move || listener.accept().expect("accept"));
        let client = std::net::TcpStream::connect(local).expect("connect");
        let client_local = client.local_addr().expect("local_addr");
        let client_remote = client.peer_addr().expect("peer_addr");
        let pid = resolve_pid(client_local, client_remote, false);
        assert_eq!(
            pid,
            Some(own_pid),
            "established TCP socket should resolve to our PID"
        );
        drop(client);
        drop(accepted.join());

        // Unconnected UDP socket: hashed by (local address, local port).
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UdpSocket");
        let local = socket.local_addr().expect("local_addr");
        let pid = resolve_pid(local, remote, true);
        assert_eq!(pid, Some(own_pid), "UDP socket should resolve to our PID");

        // Connected UDP socket: hashed by (remote address, local port).
        let sink = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sink");
        let sink_addr = sink.local_addr().expect("local_addr");
        socket.connect(sink_addr).expect("udp connect");
        let pid = resolve_pid(local, sink_addr, true);
        assert_eq!(
            pid,
            Some(own_pid),
            "connected UDP socket should resolve to our PID"
        );
        drop(socket);
        drop(sink);

        let name = process_name(own_pid);
        assert!(name.is_some(), "should resolve current process name");
    }
}
