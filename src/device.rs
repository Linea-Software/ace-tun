//! An async IP-packet device on top of WinTun's blocking ring-buffer session.
//!
//! WinTun's read side is a blocking wait on a kernel event, which cannot be
//! polled from an async context. We therefore run one dedicated OS thread that
//! blocks in `receive_blocking` and forwards each packet over a bounded
//! channel. Back-pressure is handled by the channel: when it fills, the reader
//! thread parks, WinTun's ring fills behind it, and the driver drops packets —
//! which is exactly how a real NIC behaves under load.
//!
//! The write side needs no thread: `allocate_send_packet` is non-blocking, and
//! a full send ring means "drop this packet", which TCP recovers from by
//! retransmitting.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use wintun::Session;

/// The backend's packet-device handle, as produced by
/// [`AdapterHandle::session`](crate::platform::AdapterHandle).
///
/// Each platform feeds its native session type into [`TunDevice::new`]; the
/// device contract (one IP packet per read/write) is identical everywhere.
#[cfg(target_os = "windows")]
pub(crate) type SessionHandle = Arc<Session>;

/// How many packets may sit between the reader thread and the netstack.
///
/// Deep enough to absorb a scheduling hiccup, shallow enough that a stalled
/// netstack sheds load promptly instead of accumulating latency.
const READ_QUEUE_DEPTH: usize = 1024;

/// An async, framed IP-packet device backed by a WinTun session.
///
/// Each `poll_read` yields exactly one IP packet and each `poll_write` consumes
/// exactly one, which is the framing `ipstack` expects.
pub(crate) struct TunDevice {
    session: SessionHandle,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl TunDevice {
    /// Start the reader thread and wrap `session` as an async device.
    ///
    /// The returned [`ReaderHandle`] must be joined during teardown; dropping
    /// it without stopping the session leaks the thread until the session is
    /// shut down elsewhere.
    pub(crate) fn new(session: SessionHandle) -> io::Result<(Self, ReaderHandle)> {
        let (tx, rx) = mpsc::channel(READ_QUEUE_DEPTH);
        let reader_session = Arc::clone(&session);

        let thread = std::thread::Builder::new()
            .name("ace-tun-reader".into())
            .spawn(move || {
                loop {
                    // `receive_blocking` returns Err once the session is shut
                    // down, which is how teardown unblocks this thread.
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
                    // Only reachable if the caller's buffer is smaller than the
                    // adapter MTU, which would corrupt framing. We configure
                    // both from the same constant, so treat it as a bug.
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
            // Channel closed: the reader thread exited, so the device is EOF.
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
                // Send ring full (or shutting down). Dropping is the correct
                // device behaviour; reporting an error here would tear down the
                // whole netstack over transient congestion.
                tracing::trace!("dropping outbound packet: {e}");
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // WinTun sends as soon as `send_packet` returns; there is no buffer to
        // flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
