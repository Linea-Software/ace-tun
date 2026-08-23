//! An async IP-packet device: one IP packet per read/write, the framing
//! `ipstack` expects.
//!
//! The backend differs per OS:
//!
//! * **Windows** — WinTun's read side is a blocking wait on a kernel event,
//!   which cannot be polled from an async context. One dedicated OS thread
//!   blocks in `receive_blocking` and forwards each packet over a bounded
//!   channel. Back-pressure is handled by the channel: when it fills, the
//!   reader thread parks, WinTun's ring fills behind it, and the driver drops
//!   packets — which is exactly how a real NIC behaves under load. The write
//!   side needs no thread: `allocate_send_packet` is non-blocking, and a full
//!   send ring means "drop this packet", which TCP recovers from by
//!   retransmitting.
//! * **Linux / macOS** — the device fd is set nonblocking and wrapped in
//!   [`tokio::io::unix::AsyncFd`]; reads and writes happen on the reactor
//!   thread directly, so no reader thread exists at all.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The backend's packet-device handle, as produced by
/// [`AdapterHandle::session`](crate::platform::AdapterHandle).
///
/// Each platform feeds its native session type into [`TunDevice::new`]; the
/// device contract (one IP packet per read/write) is identical everywhere.
#[cfg(target_os = "windows")]
pub(crate) type SessionHandle = std::sync::Arc<wintun::Session>;

/// The backend's packet-device handle, as produced by
/// [`AdapterHandle::session`](crate::platform::AdapterHandle).
///
/// On Unix this is a dup of the adapter's fd; the adapter keeps the
/// authoritative copy, which is what owns the interface's lifetime.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) type SessionHandle = std::os::fd::OwnedFd;

/// utun datagrams are prefixed with a 4-byte protocol-family header
/// (`AF_INET` = 2 / `AF_INET6` = 30 as a big-endian u32 — the same encoding
/// tun-rs uses; xnu's `utun_input` byte-swaps it back with `ntohl`).
#[cfg(target_os = "macos")]
const AF_HEADER_LEN: usize = 4;

#[cfg(target_os = "windows")]
mod imp {
    use super::*;

    use tokio::sync::mpsc;

    /// How many packets may sit between the reader thread and the netstack.
    ///
    /// Deep enough to absorb a scheduling hiccup, shallow enough that a stalled
    /// netstack sheds load promptly instead of accumulating latency.
    const READ_QUEUE_DEPTH: usize = 1024;

    /// An async, framed IP-packet device backed by a WinTun session.
    pub(crate) struct TunDevice {
        session: SessionHandle,
        rx: mpsc::Receiver<Vec<u8>>,
    }

    impl TunDevice {
        /// Start the reader thread and wrap `session` as an async device.
        ///
        /// The returned [`ReaderHandle`] must be joined during teardown;
        /// dropping it without stopping the session leaks the thread until the
        /// session is shut down elsewhere.
        pub(crate) fn new(session: SessionHandle) -> io::Result<(Self, ReaderHandle)> {
            let (tx, rx) = mpsc::channel(READ_QUEUE_DEPTH);
            let reader_session = std::sync::Arc::clone(&session);

            let thread = std::thread::Builder::new()
                .name("ace-tun-reader".into())
                .spawn(move || {
                    loop {
                        // `receive_blocking` returns Err once the session is
                        // shut down, which is how teardown unblocks this thread.
                        let packet = match reader_session.receive_blocking() {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::debug!("tun reader stopping: {e}");
                                break;
                            }
                        };
                        if tx.blocking_send(packet.bytes().to_vec()).is_err() {
                            // Receiver dropped: the netstack is gone.
                            break;
                        }
                    }
                })?;

            Ok((Self { session, rx }, ReaderHandle(thread)))
        }
    }

    /// Join handle for the blocking reader thread.
    pub(crate) struct ReaderHandle(std::thread::JoinHandle<()>);

    impl ReaderHandle {
        /// Wait for the reader thread to exit. The caller must have shut the
        /// session down first, or this blocks forever.
        pub(crate) fn join(self) {
            let _ = self.0.join();
        }
    }

    impl AsyncRead for TunDevice {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(packet)) => {
                    let room = buf.remaining();
                    if packet.len() > room {
                        // Only reachable if the caller's buffer is smaller than
                        // the adapter MTU, which would corrupt framing. We
                        // configure both from the same constant, so treat it as
                        // a bug.
                        tracing::warn!(
                            "dropping {}-byte packet: read buffer holds only {room}",
                            packet.len()
                        );
                        // Nothing was written; ask to be polled again.
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    buf.put_slice(&packet);
                    Poll::Ready(Ok(()))
                }
                // Channel closed: the reader thread exited, so the device is
                // EOF.
                Poll::Ready(None) => Poll::Ready(Ok(())),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl AsyncWrite for TunDevice {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let len = match u16::try_from(buf.len()) {
                Ok(0) => return Poll::Ready(Ok(0)),
                Ok(n) => n,
                Err(_) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "packet exceeds 65535 bytes",
                    )));
                }
            };

            match self.session.allocate_send_packet(len) {
                Ok(mut packet) => {
                    packet.bytes_mut().copy_from_slice(buf);
                    self.session.send_packet(packet);
                }
                Err(e) => {
                    // Send ring full (or shutting down). Dropping is the
                    // correct device behaviour; reporting an error here would
                    // tear down the whole netstack over transient congestion.
                    tracing::trace!("dropping outbound packet: {e}");
                }
            }
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            // WinTun sends as soon as `send_packet` returns; there is no buffer
            // to flush.
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    use std::os::fd::AsRawFd;

    use tokio::io::unix::AsyncFd;

    /// Largest possible IP packet (IPv4 length field is 16 bits).
    const MAX_PACKET: usize = 65_535;

    /// An async, framed IP-packet device backed by a nonblocking TUN fd.
    ///
    /// Each read returns exactly one IP packet (`IFF_NO_PI` framing); each
    /// write consumes one whole packet.
    pub(crate) struct TunDevice {
        fd: AsyncFd<SessionHandle>,
        /// Scratch buffer for one packet; `poll_read` copies out of it.
        packet: Box<[u8]>,
    }

    impl TunDevice {
        /// Wrap a nonblocking device fd as an async device.
        ///
        /// No reader thread is needed: `AsyncFd` polls the fd on the reactor.
        pub(crate) fn new(fd: SessionHandle) -> io::Result<(Self, ReaderHandle)> {
            let device = Self {
                fd: AsyncFd::new(fd)?,
                packet: vec![0u8; MAX_PACKET].into_boxed_slice(),
            };
            Ok((device, ReaderHandle))
        }
    }

    /// Unix devices need no reader thread; kept for the uniform contract.
    pub(crate) struct ReaderHandle;

    impl ReaderHandle {
        /// Nothing to join.
        pub(crate) fn join(self) {}
    }

    impl AsyncRead for TunDevice {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            // Split the borrows so the readiness guard and the scratch buffer
            // can be used together.
            let this = self.get_mut();
            let fd = &this.fd;
            let packet = &mut this.packet;

            loop {
                let mut guard = match fd.poll_read_ready(cx) {
                    Poll::Ready(Ok(guard)) => guard,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };

                match guard.try_io(|inner| {
                    // SAFETY: `packet` is a live buffer; the fd is nonblocking.
                    let received = unsafe {
                        libc::read(
                            inner.get_ref().as_raw_fd(),
                            packet.as_mut_ptr() as *mut libc::c_void,
                            packet.len(),
                        )
                    };
                    if received < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(received as usize)
                    }
                }) {
                    Ok(Ok(received)) => {
                        let room = buf.remaining();
                        if received > room {
                            // Only reachable if the caller's buffer is smaller
                            // than the device MTU, which would corrupt framing.
                            tracing::warn!(
                                "dropping {received}-byte packet: read buffer holds only {room}"
                            );
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        buf.put_slice(&packet[..received]);
                        return Poll::Ready(Ok(()));
                    }
                    Ok(Err(e)) => return Poll::Ready(Err(e)),
                    // `try_io` only reports WouldBlock here; loop and poll the
                    // readiness again.
                    Err(_would_block) => continue,
                }
            }
        }
    }

    impl AsyncWrite for TunDevice {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if buf.len() > MAX_PACKET {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "packet exceeds 65535 bytes",
                )));
            }

            let fd = &self.fd;
            loop {
                let mut guard = match fd.poll_write_ready(cx) {
                    Poll::Ready(Ok(guard)) => guard,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };

                match guard.try_io(|inner| {
                    // SAFETY: `buf` is a live slice; the fd is nonblocking. The
                    // kernel writes a whole packet or nothing.
                    let written = unsafe {
                        libc::write(
                            inner.get_ref().as_raw_fd(),
                            buf.as_ptr() as *const libc::c_void,
                            buf.len(),
                        )
                    };
                    if written < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(written as usize)
                    }
                }) {
                    Ok(Ok(written)) => return Poll::Ready(Ok(written)),
                    Ok(Err(e)) => return Poll::Ready(Err(e)),
                    Err(_would_block) => continue,
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            // A TUN write is a direct syscall; there is no buffer to flush.
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    use std::os::fd::AsRawFd;

    use tokio::io::unix::AsyncFd;

    /// Largest possible IP packet (IPv4 length field is 16 bits).
    const MAX_PACKET: usize = 65_535;

    /// An async, framed IP-packet device backed by a nonblocking utun fd.
    ///
    /// Each read returns the 4-byte AF header followed by exactly one IP
    /// packet; each write consumes one packet with the header prepended.
    pub(crate) struct TunDevice {
        fd: AsyncFd<SessionHandle>,
        /// Scratch buffer for one AF header + one packet; `poll_read` copies
        /// the packet (sans header) out of it.
        packet: Box<[u8]>,
    }

    impl TunDevice {
        /// Wrap a nonblocking device fd as an async device.
        ///
        /// No reader thread is needed: `AsyncFd` polls the fd on the reactor.
        pub(crate) fn new(fd: SessionHandle) -> io::Result<(Self, ReaderHandle)> {
            let device = Self {
                fd: AsyncFd::new(fd)?,
                packet: vec![0u8; AF_HEADER_LEN + MAX_PACKET].into_boxed_slice(),
            };
            Ok((device, ReaderHandle))
        }
    }

    /// Unix devices need no reader thread; kept for the uniform contract.
    pub(crate) struct ReaderHandle;

    impl ReaderHandle {
        /// Nothing to join.
        pub(crate) fn join(self) {}
    }

    impl AsyncRead for TunDevice {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            // Split the borrows so the readiness guard and the scratch buffer
            // can be used together.
            let this = self.get_mut();
            let fd = &this.fd;
            let packet = &mut this.packet;

            loop {
                let mut guard = match fd.poll_read_ready(cx) {
                    Poll::Ready(Ok(guard)) => guard,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };

                match guard.try_io(|inner| {
                    // SAFETY: `packet` is a live buffer; the fd is nonblocking.
                    // utun delivers the AF header and the packet as one
                    // datagram, so a single read sees both.
                    let received = unsafe {
                        libc::read(
                            inner.get_ref().as_raw_fd(),
                            packet.as_mut_ptr() as *mut libc::c_void,
                            packet.len(),
                        )
                    };
                    if received < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(received as usize)
                    }
                }) {
                    Ok(Ok(received)) => {
                        if received < AF_HEADER_LEN {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "utun read shorter than its AF header",
                            )));
                        }
                        // Strip the AF header; the family bytes are not
                        // needed, the IP version inside the packet decides.
                        let packet = &packet[AF_HEADER_LEN..received];
                        let room = buf.remaining();
                        if packet.len() > room {
                            // Only reachable if the caller's buffer is smaller
                            // than the device MTU, which would corrupt framing.
                            tracing::warn!(
                                "dropping {}-byte packet: read buffer holds only {room}",
                                packet.len()
                            );
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        buf.put_slice(packet);
                        return Poll::Ready(Ok(()));
                    }
                    Ok(Err(e)) => return Poll::Ready(Err(e)),
                    // `try_io` only reports WouldBlock here; loop and poll the
                    // readiness again.
                    Err(_would_block) => continue,
                }
            }
        }
    }

    impl AsyncWrite for TunDevice {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if buf.len() > MAX_PACKET {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "packet exceeds 65535 bytes",
                )));
            }
            if buf.len() < AF_HEADER_LEN {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "packet too short to carry an IP version",
                )));
            }

            // The kernel routes the packet by the family in the header, so it
            // must match the IP version inside the packet.
            let family = match buf[0] >> 4 {
                4 => libc::AF_INET as u32,
                6 => libc::AF_INET6 as u32,
                _ => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "packet is neither IPv4 nor IPv6",
                    )));
                }
            };
            // Big-endian on the wire: xnu's `utun_input` byte-swaps the
            // header with `ntohl` before comparing.
            let header = family.to_be_bytes();
            let iovecs = [
                libc::iovec {
                    iov_base: header.as_ptr() as *mut libc::c_void,
                    iov_len: header.len(),
                },
                libc::iovec {
                    iov_base: buf.as_ptr() as *mut libc::c_void,
                    iov_len: buf.len(),
                },
            ];

            let fd = &self.fd;
            loop {
                let mut guard = match fd.poll_write_ready(cx) {
                    Poll::Ready(Ok(guard)) => guard,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };

                match guard.try_io(|inner| {
                    // SAFETY: both iovecs reference live memory for the
                    // duration of the call; the fd is nonblocking. utun
                    // consumes the whole datagram or nothing.
                    let written = unsafe {
                        libc::writev(
                            inner.get_ref().as_raw_fd(),
                            iovecs.as_ptr(),
                            iovecs.len() as libc::c_int,
                        )
                    };
                    if written < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(written as usize)
                    }
                }) {
                    Ok(Ok(written)) => {
                        // The kernel never accepts a partial datagram, so the
                        // header bytes are counted in `written`; the caller
                        // wants the packet length.
                        return Poll::Ready(Ok(written.saturating_sub(AF_HEADER_LEN)));
                    }
                    Ok(Err(e)) => return Poll::Ready(Err(e)),
                    Err(_would_block) => continue,
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            // A TUN write is a direct syscall; there is no buffer to flush.
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}

pub(crate) use imp::{ReaderHandle, TunDevice};
