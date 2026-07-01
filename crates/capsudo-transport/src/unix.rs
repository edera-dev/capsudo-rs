//! Local transport over an `AF_UNIX` `SOCK_STREAM` socket.
//!
//! This is the "fast path": file descriptors passed to [`Transport::send`] ride
//! as real `SCM_RIGHTS` ancillary data, exactly as the C implementation does, so
//! the daemon's child ends up sharing the client's actual terminal/pipes.

use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use capsudo_proto::{Header, Message};
use nix::cmsg_space;
use nix::sys::socket::{
    getsockopt, recvmsg, sendmsg, sockopt, ControlMessage, ControlMessageOwned, MsgFlags,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::{UnixListener as TokioUnixListener, UnixStream};

use crate::error::{Result, TransportError};
use crate::traits::{ControlSender, FdSpec, Listener, PeerCred, Received, Transport};

/// Maximum number of descriptors we will receive with a single message. The
/// protocol only ever delegates the three stdio descriptors.
const MAX_SCM_FDS: usize = 3;

/// A capsudo [`Transport`] backed by a connected Unix-domain stream socket.
pub struct UnixTransport {
    stream: UnixStream,
}

impl UnixTransport {
    /// Wraps an already-connected tokio [`UnixStream`].
    pub fn new(stream: UnixStream) -> UnixTransport {
        UnixTransport { stream }
    }

    /// Connects to a capsudo daemon listening at `path`.
    pub async fn connect(path: impl AsRef<Path>) -> Result<UnixTransport> {
        let stream = UnixStream::connect(path).await?;
        Ok(UnixTransport::new(stream))
    }

    /// Wraps an inherited connected socket descriptor (e.g. capsudod's stdin
    /// when chained behind an authenticating front-end).
    pub fn from_fd(fd: OwnedFd) -> Result<UnixTransport> {
        let std_stream = std::os::unix::net::UnixStream::from(fd);
        std_stream.set_nonblocking(true)?;
        Ok(UnixTransport::new(UnixStream::from_std(std_stream)?))
    }

    /// Reclaims the underlying stream — used to hand the live socket to another
    /// process after reading just the first message from it.
    pub fn into_inner(self) -> UnixStream {
        self.stream
    }

    /// Reads one message header, capturing any `SCM_RIGHTS` descriptors that
    /// arrive with it. Returns `Ok(None)` on a clean EOF at a frame boundary.
    async fn recv_header(&mut self) -> Result<Option<(Header, Vec<OwnedFd>)>> {
        let fd = self.stream.as_raw_fd();
        let mut hdr = [0u8; Header::SIZE];
        let mut filled = 0usize;
        let mut owned: Vec<OwnedFd> = Vec::new();

        while filled < Header::SIZE {
            self.stream.readable().await?;

            let res = self.stream.try_io(Interest::READABLE, || {
                let mut cmsg = cmsg_space!([RawFd; MAX_SCM_FDS]);
                let mut iov = [IoSliceMut::new(&mut hdr[filled..])];
                let msg = recvmsg::<()>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty())
                    .map_err(io::Error::from)?;

                let mut got: Vec<RawFd> = Vec::new();
                for cmsg in msg.cmsgs().map_err(io::Error::from)? {
                    if let ControlMessageOwned::ScmRights(rfds) = cmsg {
                        got.extend_from_slice(&rfds);
                    }
                }
                Ok((msg.bytes, got))
            });

            match res {
                Ok((0, _)) => {
                    if filled == 0 && owned.is_empty() {
                        return Ok(None);
                    }
                    return Err(TransportError::UnexpectedEof);
                }
                Ok((n, got)) => {
                    filled += n;
                    // SAFETY: each RawFd was just installed into our process by
                    // the kernel via SCM_RIGHTS; we take sole ownership.
                    for raw in got {
                        owned.push(unsafe { OwnedFd::from_raw_fd(raw) });
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(Some((Header::decode(&hdr)?, owned)))
    }
}

#[async_trait]
impl Transport for UnixTransport {
    async fn send(&mut self, msg: &Message, fds: &[FdSpec<'_>]) -> Result<()> {
        let buf = msg.encode();
        let fd = self.stream.as_raw_fd();
        let mut offset = 0usize;

        if !fds.is_empty() {
            // The local transport ships the descriptors themselves; direction is
            // irrelevant once the peer holds the real fd.
            let raw: Vec<RawFd> = fds.iter().map(|s| s.fd.as_raw_fd()).collect();

            // The ancillary descriptors ride with the first sendmsg. A short
            // write is possible; the remainder is sent below without ancillary,
            // since the kernel delivers the fds with the first byte.
            loop {
                self.stream.writable().await?;
                let res = self.stream.try_io(Interest::WRITABLE, || {
                    let iov = [IoSlice::new(&buf[offset..])];
                    let cmsgs = [ControlMessage::ScmRights(&raw)];
                    sendmsg::<()>(fd, &iov, &cmsgs, MsgFlags::empty(), None)
                        .map_err(io::Error::from)
                });
                match res {
                    Ok(n) => {
                        offset += n;
                        break;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e.into()),
                }
            }
        }

        if offset < buf.len() {
            self.stream.write_all(&buf[offset..]).await?;
        }

        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<Received>> {
        let (header, fds) = match self.recv_header().await? {
            Some(v) => v,
            None => return Ok(None),
        };

        let mut payload = vec![0u8; header.len as usize];
        if header.len > 0 {
            self.stream.read_exact(&mut payload).await.map_err(|e| {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    TransportError::UnexpectedEof
                } else {
                    TransportError::Io(e)
                }
            })?;
        }

        Ok(Some(Received {
            message: Message::new(header.field_type, payload),
            fds,
        }))
    }

    fn peer_cred(&self) -> Option<PeerCred> {
        let creds = getsockopt(&self.stream, sockopt::PeerCredentials).ok()?;
        Some(PeerCred {
            pid: creds.pid(),
            uid: creds.uid(),
            gid: creds.gid(),
        })
    }

    fn peer_secontext(&self) -> Option<Vec<u8>> {
        let fd = self.stream.as_raw_fd();
        let mut buf = vec![0u8; 4096];
        let mut len = buf.len() as libc::socklen_t;

        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERSEC,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return None;
        }

        buf.truncate(len as usize);
        // The context is NUL-terminated; drop it.
        if buf.last() == Some(&0) {
            buf.pop();
        }
        (!buf.is_empty()).then_some(buf)
    }

    fn control_sender(&self) -> Option<Box<dyn ControlSender>> {
        // A dup writes to the same socket independently of the receiving path.
        // Safe here because the only post-handshake writes are winsize updates;
        // the main task only reads.
        let fd = nix::unistd::dup(&self.stream).ok()?;
        Some(Box::new(UnixControlSender { fd: Arc::new(fd) }))
    }
}

/// Sends control messages over a dup of the connection's socket via a blocking
/// write (messages are small and infrequent).
struct UnixControlSender {
    fd: Arc<OwnedFd>,
}

#[async_trait]
impl ControlSender for UnixControlSender {
    async fn send_control(&self, msg: Message) -> Result<()> {
        let buf = msg.encode();
        let fd = self.fd.clone();
        tokio::task::spawn_blocking(move || -> io::Result<()> {
            let mut offset = 0;
            while offset < buf.len() {
                match nix::unistd::write(fd.as_fd(), &buf[offset..]) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) => offset += n,
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(e) => return Err(io::Error::from(e)),
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| TransportError::Other(format!("control send task failed: {e}")))??;
        Ok(())
    }
}

/// A [`Listener`] that accepts capsudo connections on a Unix-domain socket.
///
/// On [`bind`](UnixListener::bind) the socket's ownership and permission bits
/// are set — these are the access-control mechanism: whoever can `connect()`
/// holds the capability.
pub struct UnixListener {
    inner: TokioUnixListener,
}

impl UnixListener {
    /// Binds and listens at `path`, applying optional ownership and a
    /// permission mode. Any pre-existing socket at `path` is removed first.
    pub fn bind(
        path: impl AsRef<Path>,
        uid: Option<u32>,
        gid: Option<u32>,
        mode: u32,
    ) -> Result<UnixListener> {
        let path = path.as_ref();

        // Mirror the C implementation: unlink a stale socket before binding.
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }

        let inner = TokioUnixListener::bind(path)?;

        if uid.is_some() || gid.is_some() {
            std::os::unix::fs::chown(path, uid, gid)?;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;

        Ok(UnixListener { inner })
    }

    /// Waits for and accepts the next connection as a concrete
    /// [`UnixTransport`], for callers that need Unix-specific abilities
    /// (peer credentials, reclaiming the socket via
    /// [`into_inner`](UnixTransport::into_inner)).
    pub async fn accept_unix(&mut self) -> Result<UnixTransport> {
        let (stream, _addr) = self.inner.accept().await?;
        Ok(UnixTransport::new(stream))
    }
}

#[async_trait]
impl Listener for UnixListener {
    async fn accept(&mut self) -> Result<Box<dyn Transport>> {
        Ok(Box::new(self.accept_unix().await?))
    }
}
