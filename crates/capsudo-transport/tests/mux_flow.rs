//! Flow control and peer limits on the multiplexing transport. A peer that
//! stops reading one stream, or that sends what no well-behaved end would, must
//! not stall or exhaust the other end.

use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use capsudo_proto::{FieldType, Message};
use capsudo_transport::mux::{MuxTransport, Side};
use capsudo_transport::{FdSpec, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

const KIND_CONTROL: u8 = 1;
const KIND_FDS: u8 = 2;
const KIND_STREAM_DATA: u8 = 3;
const KIND_HELLO: u8 = 5;
const KIND_WINDOW: u8 = 6;

/// A raw mux frame, for a peer that speaks the wire format by hand.
fn frame(kind: u8, id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// An `Fds` frame delegating `count` streams from `first_id` in direction `dir`
/// (0 read, 1 write, 2 both, as the sender sees it).
fn fds_frame(first_id: u32, count: u32, dir: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    for id in first_id..first_id + count {
        payload.extend_from_slice(&id.to_le_bytes());
        payload.push(dir);
    }
    frame(KIND_FDS, 0, &payload)
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

/// Feeds `bytes` into `feed` from a thread, so a stream has more to send than
/// any window or buffer holds.
fn flood(mut feed: UnixStream, bytes: usize) {
    std::thread::spawn(move || {
        let chunk = vec![0u8; 64 * 1024];
        let mut sent = 0;
        while sent < bytes && feed.write_all(&chunk).is_ok() {
            sent += chunk.len();
        }
    });
}

/// Writes `frames` to a listener from a raw peer, and returns the listener.
async fn listener_fed(frames: &[Vec<u8>]) -> (MuxTransport, DuplexStream) {
    let (mut raw, listener_io) = tokio::io::duplex(64 * 1024);
    let listener = MuxTransport::new(listener_io, Side::Listener);
    for frame in frames {
        raw.write_all(frame).await.unwrap();
    }
    (listener, raw)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_nobody_reads_holds_a_bounded_backlog() {
    // Large frames, so a queue that counts frames rather than bytes would take
    // all of them.
    const FRAMES: usize = 32;

    let (mut listener, mut raw) = listener_fed(&[fds_frame(1, 1, 0)]).await;
    let _unread = listener.recv().await.unwrap().unwrap().fds;
    let chunk = vec![0u8; 1024 * 1024];
    let fed = timeout(Duration::from_secs(2), async {
        for _ in 0..FRAMES {
            raw.write_all(&frame(KIND_STREAM_DATA, 1, &chunk))
                .await
                .unwrap();
        }
    })
    .await;
    assert!(
        fed.is_err(),
        "the listener took {FRAMES} MiB for a stream nobody reads"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_stream_whose_end_was_dropped_does_not_stall_the_reader() {
    // The stream's queue is full, so the reader waits for room in it until the
    // dropped end stops its pump.
    let (mut listener, mut raw) = listener_fed(&[fds_frame(1, 1, 0)]).await;
    let delegated = listener.recv().await.unwrap().unwrap().fds;
    let feeder = tokio::spawn(async move {
        let chunk = vec![0u8; 16 * 1024];
        for _ in 0..256 {
            raw.write_all(&frame(KIND_STREAM_DATA, 1, &chunk))
                .await
                .unwrap();
        }
        raw.write_all(&frame(KIND_CONTROL, 0, &Message::arg("after").encode()))
            .await
            .unwrap();
        raw
    });
    tokio::time::sleep(Duration::from_millis(250)).await;
    drop(delegated);

    let control = timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("the reader stalled on the queue of a stream nobody holds")
        .unwrap()
        .unwrap();
    assert_eq!(control.message.field_type(), FieldType::Arg);
    drop(feeder);
}

#[tokio::test]
async fn an_oversized_frame_ends_the_session() {
    let mut header = vec![KIND_CONTROL];
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&u32::MAX.to_le_bytes());
    let (mut listener, _raw) = listener_fed(&[header]).await;

    let received = timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("the listener waited on a frame larger than any message");
    assert!(received.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_data_written_before_a_control_message_arrives_before_it() {
    // An `Exit` that overtook the output its program wrote first would let the
    // caller end the session with that output still unsent. One window plus
    // less than a socket buffer, so the program finishes writing while the
    // stream has no credit left.
    const PAYLOAD: usize = 1024 * 1024 + 64 * 1024;

    let (dialer_io, listener_io) = tokio::io::duplex(64 * 1024);
    let mut dialer = MuxTransport::new(dialer_io, Side::Dialer);
    let mut listener = MuxTransport::new(listener_io, Side::Listener);

    let (mut sink, output) = UnixStream::pair().unwrap();
    dialer
        .send(&Message::fds(1), &[FdSpec::write(output.as_fd())])
        .await
        .unwrap();
    drop(output);
    let delegated = listener.recv().await.unwrap().unwrap().fds;
    let [program_output]: [_; 1] = delegated.try_into().unwrap();

    // Late, so the stream runs out of credit before anything drains it.
    let drain = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(250));
        let mut received = Vec::new();
        std::io::Read::read_to_end(&mut sink, &mut received).unwrap();
        received.len()
    });

    let program = tokio::spawn(async move {
        let program_output = UnixStream::from(program_output);
        program_output.set_nonblocking(true).unwrap();
        let mut program_output = tokio::net::UnixStream::from_std(program_output).unwrap();
        program_output.write_all(&vec![0u8; PAYLOAD]).await.unwrap();
        drop(program_output);
        listener.send(&Message::exit(0), &[]).await.unwrap();
        listener
    });

    let exit = timeout(Duration::from_secs(30), dialer.recv())
        .await
        .expect("the exit never arrived")
        .unwrap()
        .unwrap();
    assert_eq!(exit.message.field_type(), FieldType::Exit);
    drop(dialer);
    drop(program.await.unwrap());

    let received = timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || drain.join().unwrap()),
    )
    .await
    .expect("draining the output timed out")
    .unwrap();
    assert_eq!(received, PAYLOAD, "output written before the exit was lost");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_nobody_reads_does_not_stall_the_others() {
    let (dialer_io, listener_io) = tokio::io::duplex(64 * 1024);
    let mut dialer = MuxTransport::new(dialer_io, Side::Dialer);
    let mut listener = MuxTransport::new(listener_io, Side::Listener);

    let (stalled_feed, stalled_source) = UnixStream::pair().unwrap();
    let (mut live_feed, live_source) = UnixStream::pair().unwrap();
    dialer
        .send(
            &Message::fds(2),
            &[
                FdSpec::read(stalled_source.as_fd()),
                FdSpec::read(live_source.as_fd()),
            ],
        )
        .await
        .unwrap();
    let delegated = listener.recv().await.unwrap().unwrap().fds;
    let [_stalled, live]: [_; 2] = delegated.try_into().unwrap();

    // Far more than one window, and nothing ever reads it.
    flood(stalled_feed, 16 * 1024 * 1024);
    tokio::time::sleep(Duration::from_millis(250)).await;

    live_feed.write_all(b"ping").unwrap();
    let control = timeout(Duration::from_secs(5), async {
        dialer.send(&Message::arg("still here"), &[]).await.unwrap();
        listener.recv().await
    })
    .await
    .expect("a stalled stream held up a control message")
    .unwrap()
    .unwrap();
    assert_eq!(control.message.field_type(), FieldType::Arg);

    let live = UnixStream::from(live);
    live.set_nonblocking(true).unwrap();
    let mut live = tokio::net::UnixStream::from_std(live).unwrap();
    let mut ping = [0u8; 4];
    timeout(Duration::from_secs(5), live.read_exact(&mut ping))
        .await
        .expect("a stalled stream held up another stream")
        .unwrap();
    assert_eq!(&ping, b"ping");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_never_says_hello_is_not_held_to_a_window() {
    // A peer that predates windowing never grants, so a sender that waited for
    // grants would stop after its first window.
    const PAYLOAD: usize = 4 * 1024 * 1024;

    let (dialer_io, mut old_peer) = tokio::io::duplex(64 * 1024);
    let mut dialer = MuxTransport::new(dialer_io, Side::Dialer);
    let (feed, source) = UnixStream::pair().unwrap();
    dialer
        .send(&Message::fds(1), &[FdSpec::read(source.as_fd())])
        .await
        .unwrap();
    flood(feed, PAYLOAD);

    let received = timeout(Duration::from_secs(30), async {
        let mut received = 0;
        while received < PAYLOAD {
            let mut header = [0u8; 9];
            old_peer.read_exact(&mut header).await.unwrap();
            let len = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
            let mut payload = vec![0u8; len];
            old_peer.read_exact(&mut payload).await.unwrap();
            if header[0] == KIND_STREAM_DATA {
                received += len;
            }
        }
        received
    })
    .await
    .expect("the sender waited for grants a peer without windowing never sends");
    assert!(received >= PAYLOAD);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_that_reuses_an_id_keeps_its_credit() {
    // The peer picks the ids of the streams it delegates, so it can name one
    // twice. The first stream ending must not take the second one's credit.
    const PAYLOAD: usize = 2 * 1024 * 1024;

    let (mut listener, mut raw) = listener_fed(&[
        frame(KIND_HELLO, 0, &1u32.to_le_bytes()),
        fds_frame(7, 1, 1),
        fds_frame(7, 1, 1),
    ])
    .await;
    let first = listener.recv().await.unwrap().unwrap().fds;
    let second = listener.recv().await.unwrap().unwrap().fds;
    drop(first);
    flood(
        UnixStream::from(second.into_iter().next().unwrap()),
        PAYLOAD,
    );

    timeout(Duration::from_secs(10), async {
        let mut received = 0;
        while received < PAYLOAD {
            let mut header = [0u8; 9];
            raw.read_exact(&mut header).await.unwrap();
            let id = u32::from_le_bytes(header[1..5].try_into().unwrap());
            let len = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
            let mut payload = vec![0u8; len];
            raw.read_exact(&mut payload).await.unwrap();
            if header[0] == KIND_STREAM_DATA && id == 7 {
                received += len;
                let grant = ((header.len() + len) as u32).to_le_bytes();
                raw.write_all(&frame(KIND_WINDOW, 7, &grant)).await.unwrap();
            }
        }
    })
    .await
    .expect("the second stream lost its credit when the first one ended");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hello_with_fields_after_the_version_still_turns_on_windowing() {
    // Far less than this arrives from a windowed stream that is never granted.
    const UNGRANTED_LIMIT: usize = 2 * 1024 * 1024;

    let mut hello = 1u32.to_le_bytes().to_vec();
    hello.extend_from_slice(&[0xff; 12]);
    let (mut listener, mut raw) =
        listener_fed(&[frame(KIND_HELLO, 0, &hello), fds_frame(1, 1, 1)]).await;
    let output = listener.recv().await.unwrap().unwrap().fds;
    flood(
        UnixStream::from(output.into_iter().next().unwrap()),
        8 * 1024 * 1024,
    );

    let mut received = 0;
    let mut header = [0u8; 9];
    while let Ok(read) = timeout(Duration::from_millis(500), raw.read_exact(&mut header)).await {
        read.unwrap();
        let len = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; len];
        raw.read_exact(&mut payload).await.unwrap();
        if header[0] == KIND_STREAM_DATA {
            received += len;
        }
        assert!(
            received < UNGRANTED_LIMIT,
            "the listener sent {received} bytes without a grant"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_program_whose_output_reader_went_away_still_exits() {
    // `capsudo cap cat big-file | head`: the caller's reader stops reading, then
    // exits with a full window queued behind it, and the program still has more
    // to write.
    const PAYLOAD: usize = 4 * 1024 * 1024;

    let (dialer_io, listener_io) = tokio::io::duplex(64 * 1024);
    let mut dialer = MuxTransport::new(dialer_io, Side::Dialer);
    let mut listener = MuxTransport::new(listener_io, Side::Listener);

    let (reader, output) = UnixStream::pair().unwrap();
    dialer
        .send(&Message::fds(1), &[FdSpec::write(output.as_fd())])
        .await
        .unwrap();
    drop(output);
    let delegated = listener.recv().await.unwrap().unwrap().fds;
    let [program_output]: [_; 1] = delegated.try_into().unwrap();

    let _program = tokio::spawn(async move {
        let program_output = UnixStream::from(program_output);
        program_output.set_nonblocking(true).unwrap();
        let mut program_output = tokio::net::UnixStream::from_std(program_output).unwrap();
        program_output.write_all(&vec![0u8; PAYLOAD]).await.unwrap();
        drop(program_output);
        listener.send(&Message::exit(0), &[]).await.unwrap();
        listener
    });
    tokio::time::sleep(Duration::from_millis(250)).await;
    drop(reader);

    let exit = timeout(Duration::from_secs(10), dialer.recv())
        .await
        .expect("the program stalled once the reader of its output went away")
        .unwrap()
        .unwrap();
    assert_eq!(exit.message.field_type(), FieldType::Exit);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_whose_delegated_end_was_dropped_keeps_its_sender_going() {
    const PAYLOAD: usize = 8 * 1024 * 1024;

    let (dialer_io, listener_io) = tokio::io::duplex(64 * 1024);
    let mut dialer = MuxTransport::new(dialer_io, Side::Dialer);
    let mut listener = MuxTransport::new(listener_io, Side::Listener);

    let (mut feed, source) = UnixStream::pair().unwrap();
    dialer
        .send(&Message::fds(1), &[FdSpec::read(source.as_fd())])
        .await
        .unwrap();
    drop(source);
    let delegated = listener.recv().await.unwrap().unwrap().fds;

    let fed = tokio::task::spawn_blocking(move || {
        let chunk = vec![0u8; 64 * 1024];
        for _ in 0..PAYLOAD / chunk.len() {
            feed.write_all(&chunk).unwrap();
        }
    });
    // Dropped only once a full window waits behind it.
    tokio::time::sleep(Duration::from_millis(250)).await;
    drop(delegated);
    timeout(Duration::from_secs(10), fed)
        .await
        .expect("the sender stopped once the end it delegated was dropped")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_frame_must_fit_in_the_stream_queue() {
    // The listener's queue limit, as frame header plus payload: one window plus
    // the one frame a windowed sender may overshoot it by.
    const QUEUE_LIMIT: usize = 1024 * 1024 + 9 + 16 * 1024;
    const HEADER: usize = 9;

    let (mut listener, mut raw) = listener_fed(&[
        fds_frame(1, 1, 0),
        frame(KIND_STREAM_DATA, 1, &vec![0u8; QUEUE_LIMIT - HEADER]),
        frame(KIND_CONTROL, 0, &Message::arg("fits").encode()),
    ])
    .await;
    let _delegated = listener.recv().await.unwrap().unwrap().fds;
    let fits = timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("a frame that fits the queue held up the reader")
        .unwrap()
        .unwrap();
    assert_eq!(fits.message.field_type(), FieldType::Arg);

    raw.write_all(&frame(
        KIND_STREAM_DATA,
        1,
        &vec![0u8; QUEUE_LIMIT - HEADER + 1],
    ))
    .await
    .unwrap();
    let after = timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("the listener took a frame larger than its stream queue");
    assert!(after.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delegated_end_that_is_dropped_frees_its_stream() {
    // The peer never closes these streams, so only the dropped ends can free
    // the sockets the listener made for them, and their places among the live
    // streams with them.
    const ROUNDS: u32 = 50;

    let before = open_fds();
    let (mut listener, mut raw) = listener_fed(&[]).await;
    for round in 0..ROUNDS {
        // A stream the listener only writes, and one it reads and writes.
        raw.write_all(&fds_frame(round * 4, 1, 0)).await.unwrap();
        raw.write_all(&fds_frame(round * 4 + 2, 1, 2))
            .await
            .unwrap();
        for _ in 0..2 {
            let delegated = timeout(Duration::from_secs(5), listener.recv())
                .await
                .expect("the listener stopped taking streams")
                .unwrap()
                .expect("the listener ended the session");
            drop(delegated);
        }
        let freed = timeout(Duration::from_secs(10), async {
            while open_fds() > before + 16 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            freed.is_ok(),
            "{} descriptors are still open for streams nobody holds",
            open_fds() - before
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_may_hold_only_a_few_streams_at_once() {
    // Each stream takes a socket pair as soon as its frame arrives, before the
    // listener's owner sees it, so the number alive at once is what counts.
    const LIVE_LIMIT: u32 = 8;

    let (mut listener, mut raw) = listener_fed(&[fds_frame(0, LIVE_LIMIT, 0)]).await;
    let held = listener.recv().await.unwrap().unwrap().fds;
    assert_eq!(held.len(), LIVE_LIMIT as usize);

    raw.write_all(&fds_frame(100, 1, 0)).await.unwrap();
    let after = timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("the listener waited after a stream past its limit");
    assert!(after.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_fds_frame_past_the_stream_limit_ends_the_session() {
    let (mut listener, _raw) = listener_fed(&[fds_frame(0, 1000, 0)]).await;
    let after = timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("the listener waited after a frame past its stream limit");
    assert!(after.unwrap().is_none());
}
