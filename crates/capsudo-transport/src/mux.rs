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
//! in-process duplex pipe, or an Edera IDM ring. See [`fakeidm`](crate::fakeidm)
//! for a throwaway TCP-backed stand-in used in tests.
//!
//! Every stream is flow-controlled with a credit window, so a stream whose far
//! end stops reading never stops the reader from delivering control messages or
//! the other streams. Each end opens with a `Hello` frame that advertises the
//! window it grants and the largest stream frame it takes, and only a peer that
//! sent one is held to its grants, so an end that predates windowing still
//! interoperates.

use std::collections::HashMap;
use std::io;
use std::num::NonZeroU32;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use async_trait::async_trait;
use capsudo_proto::{Header, Message, MAX_PAYLOAD};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use nix::unistd::pipe;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};

use crate::error::{Result, TransportError};
use crate::traits::{ControlSender, FdDir, FdSpec, Received, Transport};

const KIND_CONTROL: u8 = 1;
const KIND_FDS: u8 = 2;
const KIND_STREAM_DATA: u8 = 3;
const KIND_STREAM_CLOSE: u8 = 4;
const KIND_HELLO: u8 = 5;
const KIND_WINDOW: u8 = 6;

const MUX_HEADER: usize = 9;
const PUMP_BUF: usize = 16 * 1024;
const CHANNEL_DEPTH: usize = 64;

/// The flow-control version this end speaks, carried in its `Hello` frame.
const WINDOW_VERSION: u32 = 1;

/// How many bytes a sender may have in flight on one stream before it waits for
/// a grant, unless the receiver advertises another window. Bytes are counted as
/// frame header plus payload, so a stream of tiny frames is bounded too.
const STREAM_WINDOW: u32 = 1024 * 1024;

/// The largest frame payload, which is one whole encoded control message.
const MAX_FRAME_PAYLOAD: usize = Header::SIZE + MAX_PAYLOAD;

/// The most streams the peer may have delegated to this end at once. Each holds
/// a socket pair from the moment its frame arrives, before anything can refuse
/// it, and a capsudo session delegates three.
const MAX_LIVE_STREAMS: usize = 8;

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
    Hello(Vec<u8>),
    Control(Vec<u8>),
    Fds(Vec<u8>),
    StreamData(u32, Vec<u8>),
    StreamClose(u32),
    /// The receiver consumed this many bytes of the stream and can take more.
    Window(u32, u32),
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

/// The receiving end of one stream: its pump's queue, and how much is in it.
struct Inbound {
    tx: mpsc::UnboundedSender<StreamMsg>,
    depth: Arc<QueueDepth>,
}

/// How many bytes wait in a stream's queue. Kept apart from the queue's sender,
/// which the pump must never hold, or its queue would never close.
struct QueueDepth {
    queued: AtomicUsize,
    drained: Notify,
    /// Set when the pump stops, so a reader waiting for room in its queue stops
    /// waiting.
    closed: AtomicBool,
}

type StreamMap = Arc<Mutex<HashMap<u32, Arc<Inbound>>>>;

/// How far each stream this end writes into the channel has got, what it may
/// still send, and what each end said about windowing.
struct Flow {
    /// The window this end grants each stream the peer sends on.
    window: u32,
    /// Set, under the `progress` lock, by the peer's first `Hello`.
    peer_windowed: AtomicBool,
    /// The window the peer grants each stream this end sends on.
    peer_window: AtomicU32,
    /// The largest stream frame the peer takes, as header plus payload.
    peer_max_stream_frame: AtomicUsize,
    closed: AtomicBool,
    progress: Mutex<HashMap<u32, Arc<Progress>>>,
}

/// How much of one stream its pump has read and framed, and how much the peer
/// says it may still send.
struct Progress {
    /// Credit in bytes. It goes negative by up to one frame, because a sender
    /// waits only for credit to be positive.
    available: Mutex<i64>,
    granted: Notify,
    /// Our end of the socket pair the stream reads, when the mux made it.
    socket: Option<Arc<AsyncFd<OwnedFd>>>,
    /// Bytes read out of `socket`. The pump reads under this lock, so a barrier
    /// sees what was read and what is still unread at one moment.
    taken: Mutex<u64>,
    /// Bytes whose frames are queued.
    sent: AtomicU64,
    progressed: Notify,
    done: AtomicBool,
}

impl Flow {
    fn new(window: u32) -> Flow {
        Flow {
            window,
            peer_windowed: AtomicBool::new(false),
            peer_window: AtomicU32::new(0),
            peer_max_stream_frame: AtomicUsize::new(MUX_HEADER + PUMP_BUF),
            closed: AtomicBool::new(false),
            progress: Mutex::new(HashMap::new()),
        }
    }

    /// How many bytes one stream may queue before the reader waits for its pump.
    /// A windowed sender overshoots its window by at most one frame, so only a
    /// peer without windowing ever makes the reader wait. A stream frame larger
    /// than this ends the session, and `Hello` advertises it, so a sender may
    /// raise its frame size up to this without breaking an older receiver.
    fn queue_limit(&self) -> usize {
        self.window as usize + MUX_HEADER + PUMP_BUF
    }

    /// The `Hello` payload: the version, the window this end grants, and the
    /// largest stream frame it takes.
    fn hello(&self) -> Vec<u8> {
        let mut hello = WINDOW_VERSION.to_le_bytes().to_vec();
        hello.extend_from_slice(&self.window.to_le_bytes());
        hello.extend_from_slice(&(self.queue_limit() as u32).to_le_bytes());
        hello
    }

    /// Takes the peer's `Hello`, and returns false when it advertises a stream
    /// frame too small to carry any data. A later version may add fields after
    /// the ones read here. Only the first `Hello` counts, so a second cannot
    /// grant every stream another window.
    fn take_hello(&self, payload: &[u8]) -> bool {
        let field = |at: usize| payload.get(at..at + 4).and_then(decode_u32);
        if field(0).is_none_or(|version| version < WINDOW_VERSION) {
            return true;
        }
        let window = field(4).unwrap_or(STREAM_WINDOW);
        let max_stream_frame = field(8).map_or(self.queue_limit(), |max| max as usize);
        if max_stream_frame <= MUX_HEADER {
            return false;
        }
        let progress = self.progress.lock().unwrap();
        if self.peer_windowed.load(Ordering::Acquire) {
            return true;
        }
        self.peer_window.store(window, Ordering::Release);
        self.peer_max_stream_frame
            .store(max_stream_frame, Ordering::Release);
        // A stream opened before `Hello` has been charged for what it sent, so
        // the window is added to what is left.
        for stream in progress.values() {
            *stream.available.lock().unwrap() += i64::from(window);
            stream.granted.notify_waiters();
        }
        self.peer_windowed.store(true, Ordering::Release);
        true
    }

    fn open(self: &Arc<Self>, id: u32, socket: Option<Arc<AsyncFd<OwnedFd>>>) -> Outbound {
        let mut streams = self.progress.lock().unwrap();
        let window = if self.peer_windowed.load(Ordering::Acquire) {
            self.peer_window.load(Ordering::Acquire)
        } else {
            0
        };
        let progress = Arc::new(Progress {
            available: Mutex::new(i64::from(window)),
            granted: Notify::new(),
            socket,
            taken: Mutex::new(0),
            sent: AtomicU64::new(0),
            progressed: Notify::new(),
            done: AtomicBool::new(false),
        });
        streams.insert(id, progress.clone());
        drop(streams);
        Outbound {
            flow: self.clone(),
            id,
            progress,
        }
    }

    fn grant(&self, id: u32, bytes: u32) {
        let progress = self.progress.lock().unwrap().get(&id).cloned();
        if let Some(progress) = progress {
            *progress.available.lock().unwrap() += i64::from(bytes);
            progress.granted.notify_waiters();
        }
    }

    /// Releases every sender waiting for credit, because no grant will come.
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        for progress in self.progress.lock().unwrap().values() {
            progress.granted.notify_waiters();
            progress.progressed.notify_waiters();
        }
    }

    /// Waits until every stream that reads a socket the mux made has queued what
    /// was unread in that socket when the barrier began. A frame queued after the
    /// barrier then follows the bytes written before it, as it would if the
    /// descriptor had really been passed. Only that backlog counts, so a holder
    /// that keeps writing cannot hold the barrier open.
    async fn barrier(&self) {
        let streams: Vec<Arc<Progress>> = self
            .progress
            .lock()
            .unwrap()
            .values()
            .filter(|progress| progress.socket.is_some())
            .cloned()
            .collect();
        for stream in streams {
            let target = {
                let taken = stream.taken.lock().unwrap();
                *taken + stream.socket.as_deref().map_or(0, unread)
            };
            loop {
                let progressed = stream.progressed.notified();
                tokio::pin!(progressed);
                progressed.as_mut().enable();
                if self.closed.load(Ordering::Acquire)
                    || stream.done.load(Ordering::Acquire)
                    || stream.sent.load(Ordering::Acquire) >= target
                {
                    break;
                }
                progressed.await;
            }
        }
    }
}

/// A pump's hold on a stream it reads into the channel.
struct Outbound {
    flow: Arc<Flow>,
    id: u32,
    progress: Arc<Progress>,
}

impl Outbound {
    /// Waits until the stream may send, or returns false once the transport is
    /// gone. A peer that never said `Hello` gives no grants, so it is not waited on.
    async fn ready(&self) -> bool {
        loop {
            let granted = self.progress.granted.notified();
            tokio::pin!(granted);
            granted.as_mut().enable();
            if self.flow.closed.load(Ordering::Acquire) {
                return false;
            }
            if !self.flow.peer_windowed.load(Ordering::Acquire)
                || *self.progress.available.lock().unwrap() > 0
            {
                return true;
            }
            granted.await;
        }
    }

    /// The most payload one frame may carry to the peer.
    fn frame_payload(&self) -> usize {
        let max_stream_frame = self.flow.peer_max_stream_frame.load(Ordering::Acquire);
        PUMP_BUF.min(max_stream_frame - MUX_HEADER)
    }

    /// Charges a frame carrying `payload` bytes against the window.
    fn debit(&self, payload: usize) {
        *self.progress.available.lock().unwrap() -= (MUX_HEADER + payload) as i64;
    }

    /// Reads from the stream's socket, counting what it takes for a barrier.
    fn read(&self, fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
        let mut taken = self.progress.taken.lock().unwrap();
        let read = nix::unistd::read(fd, buf).map_err(io::Error::from)?;
        *taken += read as u64;
        Ok(read)
    }

    /// Records that a frame carrying `payload` bytes is queued.
    fn queued(&self, payload: usize) {
        self.progress
            .sent
            .fetch_add(payload as u64, Ordering::AcqRel);
        self.progress.progressed.notify_waiters();
    }
}

impl Drop for Outbound {
    fn drop(&mut self) {
        let mut streams = self.flow.progress.lock().unwrap();
        // The peer picks the ids of the streams it delegates, so another
        // stream may hold this id by now.
        if streams
            .get(&self.id)
            .is_some_and(|progress| Arc::ptr_eq(progress, &self.progress))
        {
            streams.remove(&self.id);
        }
        drop(streams);
        self.progress.done.store(true, Ordering::Release);
        self.progress.progressed.notify_waiters();
    }
}

/// A pump's hold on a stream it writes out of the channel. Dropping it
/// unregisters the stream, so later data for it is discarded. The map is weak
/// because it owns the pump's queue, and the pump must see that queue close
/// when the transport goes.
struct StreamSink {
    id: u32,
    depth: Arc<QueueDepth>,
    streams: Weak<Mutex<HashMap<u32, Arc<Inbound>>>>,
    flow: Arc<Flow>,
    ungranted: usize,
}

impl StreamSink {
    fn open(
        streams: &StreamMap,
        flow: &Arc<Flow>,
        id: u32,
    ) -> (StreamSink, mpsc::UnboundedReceiver<StreamMsg>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let depth = Arc::new(QueueDepth {
            queued: AtomicUsize::new(0),
            drained: Notify::new(),
            closed: AtomicBool::new(false),
        });
        streams.lock().unwrap().insert(
            id,
            Arc::new(Inbound {
                tx,
                depth: depth.clone(),
            }),
        );
        let sink = StreamSink {
            id,
            depth,
            streams: Arc::downgrade(streams),
            flow: flow.clone(),
            ungranted: 0,
        };
        (sink, rx)
    }

    /// Records that the pump wrote out a frame carrying `payload` bytes, and
    /// returns a grant when one is due. `idle` says the queue is now empty, so a
    /// sender waiting on the remainder of its window is not left waiting.
    fn consumed(&mut self, payload: usize, idle: bool) -> Option<OutFrame> {
        let cost = MUX_HEADER + payload;
        self.depth.queued.fetch_sub(cost, Ordering::AcqRel);
        self.depth.drained.notify_waiters();
        if !self.flow.peer_windowed.load(Ordering::Acquire) {
            return None;
        }
        self.ungranted += cost;
        if self.ungranted < self.flow.window as usize / 4 && !idle {
            return None;
        }
        let grant = OutFrame::Window(self.id, self.ungranted as u32);
        self.ungranted = 0;
        Some(grant)
    }

    /// Unregisters a stream whose pump stops before the peer closes it, and
    /// returns a grant of a whole window. The sender may have spent its window on
    /// data the pump will never write, and the reader grants only what arrives
    /// after the stream is gone.
    fn abandon(self) -> Option<OutFrame> {
        let grant = OutFrame::Window(self.id, self.flow.window);
        let windowed = self.flow.peer_windowed.load(Ordering::Acquire);
        drop(self);
        windowed.then_some(grant)
    }
}

impl Drop for StreamSink {
    fn drop(&mut self) {
        if let Some(streams) = self.streams.upgrade() {
            let mut streams = streams.lock().unwrap();
            if streams
                .get(&self.id)
                .is_some_and(|inbound| Arc::ptr_eq(&inbound.depth, &self.depth))
            {
                streams.remove(&self.id);
            }
        }
        self.depth.closed.store(true, Ordering::Release);
        self.depth.drained.notify_waiters();
    }
}

/// One delegated stream's place in the count of live streams. Its pumps share
/// it, so the place is freed when the last of them stops.
struct StreamSlot(Arc<AtomicUsize>);

impl StreamSlot {
    fn take(live: &Arc<AtomicUsize>) -> Arc<StreamSlot> {
        live.fetch_add(1, Ordering::AcqRel);
        Arc::new(StreamSlot(live.clone()))
    }
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A [`Transport`] over an arbitrary byte channel, with descriptor passing
/// emulated by stream multiplexing.
pub struct MuxTransport {
    frame_tx: mpsc::Sender<OutFrame>,
    ctrl_rx: mpsc::Receiver<CtrlItem>,
    streams: StreamMap,
    next_id: u32,
    /// Read/write ends of a pipe used to cancel the blocking sender-side
    /// readers. Each reader `poll`s a dup of the read end; dropping the write
    /// end (when this transport is dropped) fires POLLHUP so every reader wakes
    /// and exits *without* consuming a byte from the descriptor it was pumping.
    /// This matters for a delegated descriptor that outlives the session (e.g.
    /// the caller's tty): a plain blocking `read` would otherwise sit in the
    /// syscall and steal the next byte (a keystroke) when it finally returned.
    cancel_read: OwnedFd,
    // Held only for its Drop: closing it fires POLLHUP on the readers' `poll`.
    #[allow(dead_code)]
    cancel_write: OwnedFd,
    reader: tokio::task::AbortHandle,
    flow: Arc<Flow>,
}

impl Drop for MuxTransport {
    fn drop(&mut self) {
        self.reader.abort();
        self.flow.close();
    }
}

impl MuxTransport {
    /// Builds a transport over `channel`, spawning its reader and writer driver
    /// tasks. `side` partitions the stream-id space.
    pub fn new<S>(channel: S, side: Side) -> MuxTransport
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let window = NonZeroU32::new(STREAM_WINDOW).expect("the default window is not zero");
        MuxTransport::with_window(channel, side, window)
    }

    /// Builds a transport like [`MuxTransport::new`] that grants each stream the
    /// peer sends on `window` bytes, counted as frame header plus payload. A
    /// smaller window holds less for a reader that falls behind, and a larger one
    /// lets a stream move more before it waits for a grant.
    pub fn with_window<S>(channel: S, side: Side, window: NonZeroU32) -> MuxTransport
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (reader, writer) = tokio::io::split(channel);
        let (frame_tx, frame_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (ctrl_tx, ctrl_rx) = mpsc::channel(CHANNEL_DEPTH);
        let streams: StreamMap = Arc::new(Mutex::new(HashMap::new()));
        let flow = Arc::new(Flow::new(window.get()));
        let (cancel_read, cancel_write) = pipe().expect("failed to create mux cancel pipe");

        // The peer reads `Hello` before any stream data, so it knows to grant.
        frame_tx
            .try_send(OutFrame::Hello(flow.hello()))
            .expect("a new frame queue has room");
        tokio::spawn(writer_task(writer, frame_rx));
        let reader = tokio::spawn(reader_task(
            reader,
            ctrl_tx,
            streams.clone(),
            frame_tx.clone(),
            flow.clone(),
        ))
        .abort_handle();

        let next_id = match side {
            Side::Dialer => 0,
            Side::Listener => 1,
        };

        MuxTransport {
            frame_tx,
            ctrl_rx,
            streams,
            next_id,
            cancel_read,
            cancel_write,
            reader,
            flow,
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
            let (sink, rx) = StreamSink::open(&self.streams, &self.flow, id);
            let dup = dup_owned(spec.fd)?;
            spawn_blocking_writer(dup, rx, sink, self.frame_tx.clone());
        }
        if spec.dir.reads() {
            // We will read this descriptor and forward it as stream data.
            let dup = dup_owned(spec.fd)?;
            let cancel = dup_owned(self.cancel_read.as_fd())?;
            spawn_blocking_reader(dup, self.flow.open(id, None), self.frame_tx.clone(), cancel);
        }
        Ok(())
    }
}

#[async_trait]
impl Transport for MuxTransport {
    async fn send(&mut self, msg: &Message, fds: &[FdSpec<'_>]) -> Result<()> {
        self.flow.barrier().await;
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

    fn control_sender(&self) -> Option<Box<dyn ControlSender>> {
        Some(Box::new(MuxControlSender {
            frame_tx: self.frame_tx.clone(),
            flow: self.flow.clone(),
        }))
    }
}

/// Sends control frames by cloning the multiplexer's outbound channel; ordered
/// with all other frames by the single writer task.
struct MuxControlSender {
    frame_tx: mpsc::Sender<OutFrame>,
    flow: Arc<Flow>,
}

#[async_trait]
impl ControlSender for MuxControlSender {
    async fn send_control(&self, msg: Message) -> Result<()> {
        self.flow.barrier().await;
        self.frame_tx
            .send(OutFrame::Control(msg.encode()))
            .await
            .map_err(|_| TransportError::UnexpectedEof)
    }
}

/// Serializes all outbound frames onto the channel in queue order.
async fn writer_task<W>(mut writer: W, mut frame_rx: mpsc::Receiver<OutFrame>)
where
    W: AsyncWrite + Unpin,
{
    while let Some(frame) = frame_rx.recv().await {
        let result = match frame {
            OutFrame::Hello(hello) => write_frame(&mut writer, KIND_HELLO, 0, &hello).await,
            OutFrame::Control(buf) => write_frame(&mut writer, KIND_CONTROL, 0, &buf).await,
            OutFrame::Fds(buf) => write_frame(&mut writer, KIND_FDS, 0, &buf).await,
            OutFrame::StreamData(id, buf) => {
                write_frame(&mut writer, KIND_STREAM_DATA, id, &buf).await
            }
            OutFrame::StreamClose(id) => write_frame(&mut writer, KIND_STREAM_CLOSE, id, &[]).await,
            OutFrame::Window(id, bytes) => {
                write_frame(&mut writer, KIND_WINDOW, id, &bytes.to_le_bytes()).await
            }
        };
        if result.is_err() {
            return;
        }
    }
    let _ = writer.shutdown().await;
}

/// Reads frames off the channel, routing stream traffic to per-stream pumps and
/// surfacing control/fd messages to [`MuxTransport::recv`].
async fn reader_task<R>(
    mut reader: R,
    ctrl_tx: mpsc::Sender<CtrlItem>,
    streams: StreamMap,
    frame_tx: mpsc::Sender<OutFrame>,
    flow: Arc<Flow>,
) where
    R: AsyncRead + Unpin,
{
    let live = Arc::new(AtomicUsize::new(0));
    'frames: loop {
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
                if live.load(Ordering::Acquire) + payload.len() / 5 > MAX_LIVE_STREAMS {
                    break;
                }
                // Materialize local ends here, before reading the next frame, so
                // stream data that follows always finds its pump registered.
                let mut local_ends = Vec::new();
                for (stream_id, sender_dir) in decode_fds(&payload) {
                    match materialize_stream(
                        &streams,
                        &frame_tx,
                        &flow,
                        StreamSlot::take(&live),
                        stream_id,
                        sender_dir.invert(),
                    ) {
                        Ok(fd) => local_ends.push(fd),
                        Err(_) => break 'frames,
                    }
                }
                if ctrl_tx.send(CtrlItem::Fds(local_ends)).await.is_err() {
                    break;
                }
            }
            KIND_STREAM_DATA => {
                let cost = MUX_HEADER + payload.len();
                if cost > flow.queue_limit() {
                    break;
                }
                let inbound = streams.lock().unwrap().get(&id).cloned();
                let delivered = match inbound {
                    Some(inbound) => {
                        wait_for_room(&inbound, cost, flow.queue_limit()).await;
                        inbound.depth.queued.fetch_add(cost, Ordering::AcqRel);
                        inbound.tx.send(StreamMsg::Data(payload)).is_ok()
                    }
                    None => false,
                };
                // The sender still waits for credit for data whose pump is gone.
                if !delivered && flow.peer_windowed.load(Ordering::Acquire) {
                    let _ = frame_tx.send(OutFrame::Window(id, cost as u32)).await;
                }
            }
            KIND_STREAM_CLOSE => {
                let inbound = streams.lock().unwrap().remove(&id);
                if let Some(inbound) = inbound {
                    let _ = inbound.tx.send(StreamMsg::Close);
                }
            }
            KIND_HELLO if !flow.take_hello(&payload) => break,
            KIND_WINDOW => {
                if let Some(bytes) = decode_u32(&payload) {
                    flow.grant(id, bytes);
                }
            }
            _ => {}
        }
    }
    // Dropping ctrl_tx here makes recv() observe a clean end-of-stream.
    flow.close();
}

/// Waits until a stream's queue has room for `cost` more bytes within `limit`,
/// or its pump is gone. An empty queue always has room, so one large frame
/// cannot wait forever.
async fn wait_for_room(inbound: &Inbound, cost: usize, limit: usize) {
    loop {
        let drained = inbound.depth.drained.notified();
        tokio::pin!(drained);
        drained.as_mut().enable();
        let queued = inbound.depth.queued.load(Ordering::Acquire);
        if queued == 0 || queued + cost <= limit || inbound.depth.closed.load(Ordering::Acquire) {
            return;
        }
        drained.await;
    }
}

/// Fabricates a socket pair for a received stream, registers/spawns the pumps
/// that bridge our end to the channel, and returns the other end to hand out.
fn materialize_stream(
    streams: &StreamMap,
    frame_tx: &mpsc::Sender<OutFrame>,
    flow: &Arc<Flow>,
    slot: Arc<StreamSlot>,
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

    // Set by the reader when the holder closes the end we hand out, so a writer
    // sharing the socket stops too.
    let hangup = Arc::new(Notify::new());
    if dir.writes() {
        let (sink, rx) = StreamSink::open(streams, flow, id);
        tokio::spawn(async_writer(
            ours.clone(),
            rx,
            sink,
            frame_tx.clone(),
            hangup.clone(),
            !dir.reads(),
            slot.clone(),
        ));
    }
    if dir.reads() {
        tokio::spawn(async_reader(
            ours.clone(),
            flow.open(id, Some(ours.clone())),
            frame_tx.clone(),
            hangup,
            slot,
        ));
    }

    Ok(theirs)
}

// ---- sender-side pumps (blocking, used on real caller descriptors) ----------
//
// The caller's descriptors may be regular files or ttys, which epoll cannot
// watch, so these run on the blocking pool. The client is short-lived (one
// session, then it exits), so a pump still blocked in read() at exit is reaped
// with the process.

fn spawn_blocking_reader(
    fd: OwnedFd,
    outbound: Outbound,
    frame_tx: mpsc::Sender<OutFrame>,
    cancel: OwnedFd,
) {
    let runtime = tokio::runtime::Handle::current();
    let id = outbound.id;
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; PUMP_BUF];
        loop {
            // Waiting before the read leaves the bytes in a descriptor that
            // outlives the session, e.g. a keystroke on the caller's tty.
            if !runtime.block_on(outbound.ready()) {
                break;
            }
            // Wait for the descriptor to be readable OR for the cancel pipe to
            // signal (its write end was dropped with the transport). Checking
            // cancel *before* reading is what stops us from consuming a byte
            // from a descriptor that outlives the session, e.g. stealing the
            // caller's next keystroke off a shared tty.
            let mut poll_fds = [
                PollFd::new(fd.as_fd(), PollFlags::POLLIN),
                PollFd::new(cancel.as_fd(), PollFlags::POLLIN),
            ];
            match poll(&mut poll_fds, PollTimeout::NONE) {
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => {
                    let _ = frame_tx.blocking_send(OutFrame::StreamClose(id));
                    break;
                }
            }

            // Cancelled (POLLHUP/POLLIN on the pipe): stop without reading `fd`.
            if poll_fds[1]
                .revents()
                .is_some_and(|revents| !revents.is_empty())
            {
                break;
            }

            let Some(revents) = poll_fds[0].revents() else {
                continue;
            };
            if revents.intersects(PollFlags::POLLIN) {
                // `poll` reported data, so this read returns promptly.
                match nix::unistd::read(&fd, &mut buf[..outbound.frame_payload()]) {
                    Ok(0) => {
                        let _ = frame_tx.blocking_send(OutFrame::StreamClose(id));
                        break;
                    }
                    Ok(n) => {
                        outbound.debit(n);
                        if frame_tx
                            .blocking_send(OutFrame::StreamData(id, buf[..n].to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(nix::errno::Errno::EINTR) => continue,
                    // The descriptor may be non-blocking: a caller can hand us
                    // one it also drives with an async runtime, and `dup` shares
                    // the open file description, so `O_NONBLOCK` comes with it.
                    // A readiness report is not a guarantee — the data can be
                    // gone by the time we read, e.g. consumed by another reader
                    // of the same description. Wait again rather than treating
                    // it as end of stream.
                    Err(nix::errno::Errno::EAGAIN) => continue,
                    Err(_) => {
                        let _ = frame_tx.blocking_send(OutFrame::StreamClose(id));
                        break;
                    }
                }
            } else if revents.intersects(PollFlags::POLLHUP | PollFlags::POLLERR) {
                let _ = frame_tx.blocking_send(OutFrame::StreamClose(id));
                break;
            }
        }
    });
}

fn spawn_blocking_writer(
    fd: OwnedFd,
    mut inbound: mpsc::UnboundedReceiver<StreamMsg>,
    mut sink: StreamSink,
    frame_tx: mpsc::Sender<OutFrame>,
) {
    tokio::task::spawn_blocking(move || {
        while let Some(msg) = inbound.blocking_recv() {
            match msg {
                StreamMsg::Data(bytes) => {
                    if write_all_blocking(&fd, &bytes).is_err() {
                        if let Some(grant) = sink.abandon() {
                            let _ = frame_tx.blocking_send(grant);
                        }
                        return;
                    }
                    // A grant that cannot be sent must not stop delivery of
                    // what the peer already sent.
                    if let Some(grant) = sink.consumed(bytes.len(), inbound.is_empty()) {
                        let _ = frame_tx.blocking_send(grant);
                    }
                }
                StreamMsg::Close => break, // dropping fd closes it, signalling EOF
            }
        }
    });
}

/// Writes every byte to `fd`, whether or not the descriptor is blocking.
///
/// A caller may hand us a descriptor it also drives with an async runtime, and
/// `dup` shares the open file description, so `O_NONBLOCK` comes along with it.
/// Treating the resulting `EAGAIN` as fatal would silently truncate a stream the
/// first time a peer wrote faster than the far end read — so wait for writability
/// and carry on, which is what a blocking descriptor would have done for us.
fn write_all_blocking(fd: &OwnedFd, mut bytes: &[u8]) -> nix::Result<()> {
    while !bytes.is_empty() {
        match nix::unistd::write(fd.as_fd(), bytes) {
            Ok(0) => return Err(nix::errno::Errno::EIO),
            Ok(n) => bytes = &bytes[n..],
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::EAGAIN) => wait_writable(fd)?,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Blocks until `fd` can accept more bytes, or the peer has gone.
fn wait_writable(fd: &OwnedFd) -> nix::Result<()> {
    loop {
        let mut poll_fds = [PollFd::new(fd.as_fd(), PollFlags::POLLOUT)];
        match poll(&mut poll_fds, PollTimeout::NONE) {
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e),
        }
        let Some(revents) = poll_fds[0].revents() else {
            continue;
        };
        // A hangup means nobody will ever read what is left; report it rather
        // than waiting forever on a descriptor that will never drain.
        if revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
            return Err(nix::errno::Errno::EPIPE);
        }
        if revents.intersects(PollFlags::POLLOUT) {
            return Ok(());
        }
    }
}

// ---- receiver-side pumps (async, used on socket pairs we create) ------------

async fn async_reader(
    fd: Arc<AsyncFd<OwnedFd>>,
    outbound: Outbound,
    frame_tx: mpsc::Sender<OutFrame>,
    hangup: Arc<Notify>,
    _slot: Arc<StreamSlot>,
) {
    let id = outbound.id;
    let mut buf = [0u8; PUMP_BUF];
    loop {
        if !outbound.ready().await {
            break;
        }
        let mut guard = match fd.readable().await {
            Ok(guard) => guard,
            Err(_) => break,
        };
        let payload = outbound.frame_payload();
        match guard.try_io(|_| outbound.read(fd.get_ref(), &mut buf[..payload])) {
            Ok(Ok(0)) => {
                // End of file is also a half-close, after which the holder still
                // reads. Only a full close ends the writer.
                if hung_up(fd.get_ref()) {
                    hangup.notify_one();
                }
                let _ = frame_tx.send(OutFrame::StreamClose(id)).await;
                break;
            }
            Ok(Ok(n)) => {
                outbound.debit(n);
                if frame_tx
                    .send(OutFrame::StreamData(id, buf[..n].to_vec()))
                    .await
                    .is_err()
                {
                    break;
                }
                outbound.queued(n);
            }
            Ok(Err(_)) => break,
            Err(_would_block) => continue,
        }
    }
}

/// Writes a stream's inbound data to our end of its socket pair. It stops when
/// the holder of the other end closes it, so a stream nobody holds frees its
/// socket. `watch_close` is set when no reader pump shares the socket to notice
/// the close instead.
async fn async_writer(
    fd: Arc<AsyncFd<OwnedFd>>,
    mut inbound: mpsc::UnboundedReceiver<StreamMsg>,
    mut sink: StreamSink,
    frame_tx: mpsc::Sender<OutFrame>,
    hangup: Arc<Notify>,
    watch_close: bool,
    _slot: Arc<StreamSlot>,
) {
    'pump: loop {
        let msg = tokio::select! {
            msg = inbound.recv() => msg,
            () = hangup.notified() => break 'pump,
            () = closed_by_holder(&fd), if watch_close => break 'pump,
        };
        let Some(msg) = msg else { return };
        match msg {
            StreamMsg::Data(bytes) => {
                let mut offset = 0;
                while offset < bytes.len() {
                    let mut guard = match fd.writable().await {
                        Ok(guard) => guard,
                        Err(_) => break 'pump,
                    };
                    match guard.try_io(|_| {
                        nix::unistd::write(fd.get_ref(), &bytes[offset..]).map_err(io::Error::from)
                    }) {
                        Ok(Ok(n)) => offset += n,
                        Ok(Err(_)) => break 'pump,
                        Err(_would_block) => continue,
                    }
                }
                if let Some(grant) = sink.consumed(bytes.len(), inbound.is_empty()) {
                    let _ = frame_tx.send(grant).await;
                }
            }
            StreamMsg::Close => {
                // Tell the peer (e.g. the child) it has reached EOF.
                let _ = nix::sys::socket::shutdown(
                    fd.get_ref().as_raw_fd(),
                    nix::sys::socket::Shutdown::Write,
                );
                return;
            }
        }
    }
    if let Some(grant) = sink.abandon() {
        let _ = frame_tx.send(grant).await;
    }
}

/// Resolves once the holder of the far end of a socket we only write to closes
/// it. Nothing reads what the holder writes into that end, so it is discarded.
async fn closed_by_holder(fd: &AsyncFd<OwnedFd>) {
    let mut buf = [0u8; 512];
    loop {
        let Ok(mut guard) = fd.readable().await else {
            return;
        };
        match guard.try_io(|_| nix::unistd::read(fd.get_ref(), &mut buf).map_err(io::Error::from)) {
            Ok(Ok(0)) | Ok(Err(_)) => return,
            Ok(Ok(_)) | Err(_) => {}
        }
    }
}

/// Whether both directions of a socket are shut, which for a socket pair means
/// the other end was closed rather than half-closed.
fn hung_up(fd: &OwnedFd) -> bool {
    let mut poll_fds = [PollFd::new(fd.as_fd(), PollFlags::empty())];
    poll(&mut poll_fds, PollTimeout::ZERO).is_ok()
        && poll_fds[0]
            .revents()
            .is_some_and(|revents| revents.contains(PollFlags::POLLHUP))
}

// ---- helpers ----------------------------------------------------------------

fn dup_owned(fd: BorrowedFd<'_>) -> Result<OwnedFd> {
    let owned = nix::unistd::dup(fd).map_err(io::Error::from)?;
    Ok(owned)
}

fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    let flags = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL).map_err(io::Error::from)?);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).map_err(io::Error::from)?;
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

/// How many bytes wait unread in a socket.
fn unread(fd: &AsyncFd<OwnedFd>) -> u64 {
    let mut unread: libc::c_int = 0;
    // SAFETY: FIONREAD writes one int through the pointer, which is valid for it.
    let result = unsafe { libc::ioctl(fd.get_ref().as_raw_fd(), libc::FIONREAD, &mut unread) };
    if result < 0 {
        0
    } else {
        unread as u64
    }
}

fn decode_u32(buf: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(buf.try_into().ok()?))
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
    Some(Message::new(
        header.field_type,
        buf[Header::SIZE..].to_vec(),
    ))
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
    if len > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mux frame too large",
        ));
    }

    let mut payload = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Ok(Some((kind, stream_id, payload)))
}
