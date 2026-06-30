//! A multiplexing transport that *simulates* `SCM_RIGHTS` over any plain byte
//! channel.
//!
//! This is what lets capsudo cross an Edera zone boundary. File descriptors
//! cannot travel over a cross-zone link, so instead of shipping a descriptor,
//! [`MuxTransport`] opens a logical *stream* for it and pumps its bytes inside
//! the same channel that carries control messages. The receiving end fabricates
//! a local socket pair, hands one end out as if it had arrived over
//! `SCM_RIGHTS`, and bridges the other end to the stream. Neither `capsudo` nor
//! `capsudod` can tell that the descriptor it holds is a stand-in — which is
//! exactly the point: the same session logic runs over a local socket or a
//! remote channel without change.
//!
//! ```text
//!  client real stdout fd                          child stdout (socketpair end)
//!        ^                                                   |
//!        | write                                            | write
//!   [sender pump] <--- StreamData(id) --- channel <--- [recv pump] <--- read
//! ```
//!
//! The channel underneath is any `AsyncRead + AsyncWrite`: a TCP socket, an
//! in-process duplex pipe, or an Edera IDM ring. See [`crate::idm`] for the
//! IDM-shaped wrapper.

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use capsudo_proto::{Header, Message};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use crate::error::{Result, TransportError};
use crate::traits::{FdDir, FdSpec, Received, Transport};

const KIND_CONTROL: u8 = 1;
const KIND_FDS: u8 = 2;
const KIND_STREAM_DATA: u8 = 3;
const KIND_STREAM_CLOSE: u8 = 4;

const MUX_HEADER: usize = 9;
const PUMP_BUF: usize = 16 * 1024;
const CHANNEL_DEPTH: usize = 64;

/// Which half of a connection an endpoint is, used to partition the stream-id
/// space so the two ends never allocate colliding ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The connecting side (allocates even stream ids).
    Dialer,
    /// The accepting side (allocates odd stream ids).
    Listener,
}

/// A frame queued for the writer task.
enum OutFrame {
    Control(Vec<u8>),
    Fds(Vec<u8>),
    StreamData(u32, Vec<u8>),
    StreamClose(u32),
}

/// A message handed up to [`MuxTransport::recv`].
enum CtrlItem {
    Control(Message),
    /// Descriptors were delegated; these local ends already proxy to their
    /// streams (materialized by the reader task before any stream data could
    /// race ahead).
    Fds(Vec<OwnedFd>),
}

/// Inbound payload routed to a stream's writer pump.
enum StreamMsg {
    Data(Vec<u8>),
    Close,
}

type StreamMap = Arc<Mutex<HashMap<u32, mpsc::Sender<StreamMsg>>>>;

/// A [`Transport`] over an arbitrary byte channel, with descriptor passing
/// emulated by stream multiplexing.
pub struct MuxTransport {
    frame_tx: mpsc::Sender<OutFrame>,
    ctrl_rx: mpsc::Receiver<CtrlItem>,
    streams: StreamMap,
    next_id: u32,
}

impl MuxTransport {
    /// Builds a transport over `channel`, spawning its reader and writer driver
    /// tasks. `side` partitions the stream-id space.
    pub fn new<S>(channel: S, side: Side) -> MuxTransport
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (reader, writer) = tokio::io::split(channel);
        let (frame_tx, frame_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (ctrl_tx, ctrl_rx) = mpsc::channel(CHANNEL_DEPTH);
        let streams: StreamMap = Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn(writer_task(writer, frame_rx));
        tokio::spawn(reader_task(
            reader,
            ctrl_tx,
            streams.clone(),
            frame_tx.clone(),
        ));

        let next_id = match side {
            Side::Dialer => 0,
            Side::Listener => 1,
        };

        MuxTransport {
            frame_tx,
            ctrl_rx,
            streams,
            next_id,
        }
    }

    fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(2);
        id
    }

    /// Starts the local-side pumps for an already-allocated delegated
    /// descriptor.
    ///
    /// This must run *after* the `Fds` frame has been queued, never before: a
    /// reader pump can produce stream data immediately, and if that data
    /// overtook the `Fds` frame the peer would not yet have a stream to route
    /// it to and would drop it (including stdin's EOF).
    fn start_sender_pumps(&mut self, id: u32, spec: &FdSpec<'_>) -> Result<()> {
        if spec.dir.writes() {
            // We will write inbound stream data to this descriptor.
            let (tx, rx) = mpsc::channel(CHANNEL_DEPTH);
            self.streams.lock().unwrap().insert(id, tx);
            let dup = dup_owned(spec.fd)?;
            spawn_blocking_writer(dup, rx);
        }
        if spec.dir.reads() {
            // We will read this descriptor and forward it as stream data.
            let dup = dup_owned(spec.fd)?;
            spawn_blocking_reader(dup, id, self.frame_tx.clone());
        }
        Ok(())
    }
}

#[async_trait]
impl Transport for MuxTransport {
    async fn send(&mut self, msg: &Message, fds: &[FdSpec<'_>]) -> Result<()> {
        if fds.is_empty() {
            return self
                .frame_tx
                .send(OutFrame::Control(msg.encode()))
                .await
                .map_err(|_| TransportError::UnexpectedEof);
        }

        // Allocate ids and advertise the streams *before* starting any pumps,
        // so the peer has materialized its ends before stream data can arrive.
        let planned: Vec<(u32, FdSpec<'_>)> =
            fds.iter().map(|spec| (self.alloc_id(), *spec)).collect();
        let advertised: Vec<(u32, FdDir)> =
            planned.iter().map(|(id, spec)| (*id, spec.dir)).collect();

        self.frame_tx
            .send(OutFrame::Fds(encode_fds(&advertised)))
            .await
            .map_err(|_| TransportError::UnexpectedEof)?;

        for (id, spec) in planned {
            self.start_sender_pumps(id, &spec)?;
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<Received>> {
        match self.ctrl_rx.recv().await {
            None => Ok(None),
            Some(CtrlItem::Control(message)) => Ok(Some(Received {
                message,
                fds: Vec::new(),
            })),
            Some(CtrlItem::Fds(fds)) => Ok(Some(Received {
                message: Message::fds(fds.len() as u32),
                fds,
            })),
        }
    }
}

/// Serializes all outbound frames onto the channel in queue order.
async fn writer_task<W>(mut writer: W, mut frame_rx: mpsc::Receiver<OutFrame>)
where
    W: AsyncWrite + Unpin,
{
    while let Some(frame) = frame_rx.recv().await {
        let result = match frame {
            OutFrame::Control(buf) => write_frame(&mut writer, KIND_CONTROL, 0, &buf).await,
            OutFrame::Fds(buf) => write_frame(&mut writer, KIND_FDS, 0, &buf).await,
            OutFrame::StreamData(id, buf) => {
                write_frame(&mut writer, KIND_STREAM_DATA, id, &buf).await
            }
            OutFrame::StreamClose(id) => write_frame(&mut writer, KIND_STREAM_CLOSE, id, &[]).await,
        };
        if result.is_err() {
            break;
        }
    }
}

/// Reads frames off the channel, routing stream traffic to per-stream pumps and
/// surfacing control/fd messages to [`MuxTransport::recv`].
async fn reader_task<R>(
    mut reader: R,
    ctrl_tx: mpsc::Sender<CtrlItem>,
    streams: StreamMap,
    frame_tx: mpsc::Sender<OutFrame>,
) where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => break,
        };
        let (kind, id, payload) = frame;

        match kind {
            KIND_CONTROL => {
                if let Some(message) = decode_message(&payload) {
                    if ctrl_tx.send(CtrlItem::Control(message)).await.is_err() {
                        break;
                    }
                }
            }
            KIND_FDS => {
                // Materialize local ends here, before reading the next frame, so
                // stream data that follows always finds its pump registered.
                let mut local_ends = Vec::new();
                for (stream_id, sender_dir) in decode_fds(&payload) {
                    match materialize_stream(&streams, &frame_tx, stream_id, sender_dir.invert()) {
                        Ok(fd) => local_ends.push(fd),
                        Err(_) => return,
                    }
                }
                if ctrl_tx.send(CtrlItem::Fds(local_ends)).await.is_err() {
                    break;
                }
            }
            KIND_STREAM_DATA => {
                let sender = streams.lock().unwrap().get(&id).cloned();
                if let Some(sender) = sender {
                    let _ = sender.send(StreamMsg::Data(payload)).await;
                }
            }
            KIND_STREAM_CLOSE => {
                let sender = streams.lock().unwrap().remove(&id);
                if let Some(sender) = sender {
                    let _ = sender.send(StreamMsg::Close).await;
                }
            }
            _ => {}
        }
    }
    // Dropping ctrl_tx here makes recv() observe a clean end-of-stream.
}

/// Fabricates a socket pair for a received stream, registers/spawns the pumps
/// that bridge our end to the channel, and returns the other end to hand out.
fn materialize_stream(
    streams: &StreamMap,
    frame_tx: &mpsc::Sender<OutFrame>,
    id: u32,
    dir: FdDir,
) -> Result<OwnedFd> {
    let (theirs, ours) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )
    .map_err(io::Error::from)?;

    set_nonblocking(&ours)?;
    let ours = Arc::new(AsyncFd::new(ours)?);

    if dir.writes() {
        let (tx, rx) = mpsc::channel(CHANNEL_DEPTH);
        streams.lock().unwrap().insert(id, tx);
        tokio::spawn(async_writer(ours.clone(), rx));
    }
    if dir.reads() {
        tokio::spawn(async_reader(ours.clone(), id, frame_tx.clone()));
    }

    Ok(theirs)
}

// ---- sender-side pumps (blocking, used on real caller descriptors) ----------
//
// The caller's descriptors may be regular files or ttys, which epoll cannot
// watch, so these run on the blocking pool. The client is short-lived (one
// session, then it exits), so a pump still blocked in read() at exit is reaped
// with the process.

fn spawn_blocking_reader(fd: OwnedFd, id: u32, frame_tx: mpsc::Sender<OutFrame>) {
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; PUMP_BUF];
        loop {
            match nix::unistd::read(fd.as_raw_fd(), &mut buf) {
                Ok(0) => {
                    let _ = frame_tx.blocking_send(OutFrame::StreamClose(id));
                    break;
                }
                Ok(n) => {
                    if frame_tx
                        .blocking_send(OutFrame::StreamData(id, buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => {
                    let _ = frame_tx.blocking_send(OutFrame::StreamClose(id));
                    break;
                }
            }
        }
    });
}

fn spawn_blocking_writer(fd: OwnedFd, mut inbound: mpsc::Receiver<StreamMsg>) {
    tokio::task::spawn_blocking(move || {
        while let Some(msg) = inbound.blocking_recv() {
            match msg {
                StreamMsg::Data(bytes) => {
                    if write_all_blocking(&fd, &bytes).is_err() {
                        break;
                    }
                }
                StreamMsg::Close => break, // dropping fd closes it, signalling EOF
            }
        }
    });
}

fn write_all_blocking(fd: &OwnedFd, mut bytes: &[u8]) -> nix::Result<()> {
    while !bytes.is_empty() {
        match nix::unistd::write(fd.as_fd(), bytes) {
            Ok(0) => return Err(nix::errno::Errno::EIO),
            Ok(n) => bytes = &bytes[n..],
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ---- receiver-side pumps (async, used on socket pairs we create) ------------

async fn async_reader(fd: Arc<AsyncFd<OwnedFd>>, id: u32, frame_tx: mpsc::Sender<OutFrame>) {
    let mut buf = [0u8; PUMP_BUF];
    loop {
        let mut guard = match fd.readable().await {
            Ok(guard) => guard,
            Err(_) => break,
        };
        let raw = fd.get_ref().as_raw_fd();
        match guard.try_io(|_| nix::unistd::read(raw, &mut buf).map_err(io::Error::from)) {
            Ok(Ok(0)) => {
                let _ = frame_tx.send(OutFrame::StreamClose(id)).await;
                break;
            }
            Ok(Ok(n)) => {
                if frame_tx
                    .send(OutFrame::StreamData(id, buf[..n].to_vec()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Ok(Err(_)) => break,
            Err(_would_block) => continue,
        }
    }
}

async fn async_writer(fd: Arc<AsyncFd<OwnedFd>>, mut inbound: mpsc::Receiver<StreamMsg>) {
    while let Some(msg) = inbound.recv().await {
        match msg {
            StreamMsg::Data(bytes) => {
                let mut offset = 0;
                while offset < bytes.len() {
                    let mut guard = match fd.writable().await {
                        Ok(guard) => guard,
                        Err(_) => return,
                    };
                    let raw = fd.get_ref().as_raw_fd();
                    match guard.try_io(|_| {
                        nix::unistd::write(unsafe { BorrowedFd::borrow_raw(raw) }, &bytes[offset..])
                            .map_err(io::Error::from)
                    }) {
                        Ok(Ok(n)) => offset += n,
                        Ok(Err(_)) => return,
                        Err(_would_block) => continue,
                    }
                }
            }
            StreamMsg::Close => {
                // Tell the peer (e.g. the child) it has reached EOF.
                let _ = nix::sys::socket::shutdown(
                    fd.get_ref().as_raw_fd(),
                    nix::sys::socket::Shutdown::Write,
                );
                break;
            }
        }
    }
}

// ---- helpers ----------------------------------------------------------------

use std::os::fd::AsFd;

fn dup_owned(fd: BorrowedFd<'_>) -> Result<OwnedFd> {
    let raw = nix::unistd::dup(fd.as_raw_fd()).map_err(io::Error::from)?;
    // SAFETY: dup returned a fresh, owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    let flags = OFlag::from_bits_truncate(fcntl(fd.as_raw_fd(), FcntlArg::F_GETFL).map_err(io::Error::from)?);
    fcntl(fd.as_raw_fd(), FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).map_err(io::Error::from)?;
    Ok(())
}

fn encode_fds(specs: &[(u32, FdDir)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(specs.len() * 5);
    for (id, dir) in specs {
        out.extend_from_slice(&id.to_le_bytes());
        out.push(match dir {
            FdDir::Read => 0,
            FdDir::Write => 1,
            FdDir::ReadWrite => 2,
        });
    }
    out
}

fn decode_fds(buf: &[u8]) -> Vec<(u32, FdDir)> {
    buf.chunks_exact(5)
        .filter_map(|chunk| {
            let id = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let dir = match chunk[4] {
                0 => FdDir::Read,
                1 => FdDir::Write,
                2 => FdDir::ReadWrite,
                _ => return None,
            };
            Some((id, dir))
        })
        .collect()
}

fn decode_message(buf: &[u8]) -> Option<Message> {
    if buf.len() < Header::SIZE {
        return None;
    }
    let mut header_bytes = [0u8; Header::SIZE];
    header_bytes.copy_from_slice(&buf[..Header::SIZE]);
    let header = Header::decode(&header_bytes).ok()?;
    if buf.len() != Header::SIZE + header.len as usize {
        return None;
    }
    Some(Message::new(header.field_type, buf[Header::SIZE..].to_vec()))
}

async fn write_frame<W>(writer: &mut W, kind: u8, stream_id: u32, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header = [0u8; MUX_HEADER];
    header[0] = kind;
    header[1..5].copy_from_slice(&stream_id.to_le_bytes());
    header[5..9].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    writer.write_all(&header).await?;
    if !payload.is_empty() {
        writer.write_all(payload).await?;
    }
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R>(reader: &mut R) -> io::Result<Option<(u8, u32, Vec<u8>)>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; MUX_HEADER];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let kind = header[0];
    let stream_id = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);
    let len = u32::from_le_bytes([header[5], header[6], header[7], header[8]]) as usize;

    let mut payload = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Ok(Some((kind, stream_id, payload)))
}
