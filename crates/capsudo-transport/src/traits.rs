use std::os::fd::{BorrowedFd, OwnedFd};

use async_trait::async_trait;
use capsudo_proto::Message;

use crate::error::Result;

/// A message received from a transport, together with any file descriptors
/// that accompanied it.
///
/// On a local Unix transport the descriptors arrived as real `SCM_RIGHTS`
/// ancillary data. On a non-local transport they are *simulated*: the transport
/// hands back local pipe/socket ends that proxy to multiplexed streams on the
/// far side. The receiver cannot tell the difference, which is the entire point
/// — `capsudod` dups whatever it gets onto the child's stdio either way.
pub struct Received {
    /// The decoded protocol message.
    pub message: Message,
    /// File descriptors delivered out-of-band with this message (owned by us).
    pub fds: Vec<OwnedFd>,
}

/// Peer credentials, where the transport can establish them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCred {
    /// Peer process id.
    pub pid: i32,
    /// Peer user id.
    pub uid: u32,
    /// Peer group id.
    pub gid: u32,
}

/// A bidirectional, message-oriented capsudo channel that can also convey file
/// descriptors out-of-band.
///
/// This is the seam that makes capsudo-rs portable across an Edera zone
/// boundary: `capsudo` (client) and `capsudod` (daemon) are written entirely
/// against this trait and never name a concrete socket type. Swapping a local
/// Unix socket for a cross-zone IDM channel is a matter of constructing a
/// different `Transport`.
#[async_trait]
pub trait Transport: Send {
    /// Sends one message, optionally carrying file descriptors out-of-band.
    ///
    /// Passing a non-empty `fds` is a request to *delegate those descriptors to
    /// the peer*. How that is realized is the transport's business (real
    /// `SCM_RIGHTS` vs. simulated streams).
    async fn send(&mut self, msg: &Message, fds: &[BorrowedFd<'_>]) -> Result<()>;

    /// Receives the next message, or `Ok(None)` on a clean end-of-stream.
    async fn recv(&mut self) -> Result<Option<Received>>;

    /// Best-effort peer credentials, if the transport can supply them.
    ///
    /// Returns `None` for transports where the notion does not apply (e.g. a
    /// cross-zone channel terminates locally and the originating principal is
    /// conveyed differently).
    fn peer_cred(&self) -> Option<PeerCred> {
        None
    }

    /// Best-effort peer security context (e.g. an SELinux label), if available.
    fn peer_secontext(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Accepts inbound capsudo connections, yielding a [`Transport`] per peer.
///
/// Object-safe by design: a daemon holds a `Box<dyn Listener>` and does not
/// care whether connections arrive on a Unix socket or an IDM endpoint.
#[async_trait]
pub trait Listener: Send {
    /// Waits for and accepts the next connection.
    async fn accept(&mut self) -> Result<Box<dyn Transport>>;
}
