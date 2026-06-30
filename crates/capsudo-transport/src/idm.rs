//! Cross-zone transport stub, shaped like Edera Protect IDM.
//!
//! Edera Protect runs workloads in isolated *zones*; IDM (inter-zone
//! messaging) gives two zones a reliable, ordered, byte-oriented channel — but
//! no shared file descriptors and no shared `AF_UNIX` namespace. That is
//! precisely the environment [`MuxTransport`](crate::mux::MuxTransport) was
//! built for: it turns a bare byte channel into a capsudo transport, emulating
//! descriptor passing with stream multiplexing.
//!
//! This module is a thin stand-in that uses TCP as the byte channel so the
//! cross-zone path can be exercised on one host. Dropping in the real IDM
//! transport is a matter of replacing the TCP connect/accept below with the IDM
//! channel's open/accept — everything above the byte channel is unchanged,
//! because [`MuxTransport::new`](crate::mux::MuxTransport::new) accepts any
//! `AsyncRead + AsyncWrite`.
//!
//! A capsudo *proxy* bridging zones is then just: accept a local `AF_UNIX`
//! connection in zone A, open an IDM channel to zone B, and shuttle capsudo
//! frames between them. The local side keeps using real `SCM_RIGHTS`; the IDM
//! side multiplexes; the daemon in zone B is none the wiser.

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

use crate::error::Result;
use crate::mux::{MuxTransport, Side};
use crate::traits::{Listener, Transport};

/// Connects to a capsudo daemon reachable over the (stubbed) IDM channel and
/// returns a multiplexing transport for it.
pub async fn connect(addr: impl ToSocketAddrs) -> Result<MuxTransport> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;
    Ok(MuxTransport::new(stream, Side::Dialer))
}

/// Accepts capsudo connections arriving over the (stubbed) IDM channel.
pub struct IdmListener {
    inner: TcpListener,
}

impl IdmListener {
    /// Binds the IDM endpoint at `addr`.
    pub async fn bind(addr: impl ToSocketAddrs) -> Result<IdmListener> {
        let inner = TcpListener::bind(addr).await?;
        Ok(IdmListener { inner })
    }

    /// The bound local address (useful when binding to an ephemeral port).
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self.inner.local_addr()?)
    }
}

#[async_trait]
impl Listener for IdmListener {
    async fn accept(&mut self) -> Result<Box<dyn Transport>> {
        let (stream, _peer) = self.inner.accept().await?;
        stream.set_nodelay(true)?;
        Ok(Box::new(MuxTransport::new(stream, Side::Listener)))
    }
}
