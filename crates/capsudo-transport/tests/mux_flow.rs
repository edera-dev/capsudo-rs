//! Limits on what a multiplexing peer can make the other end hold. A peer that
//! stops reading one stream, or that sends what no well-behaved end would, must
//! not exhaust the other end.

use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use capsudo_proto::{FieldType, Message};
use capsudo_transport::mux::{MuxTransport, Side};
use capsudo_transport::{FdSpec, Transport};
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

const KIND_CONTROL: u8 = 1;
const KIND_FDS: u8 = 2;
const KIND_STREAM_DATA: u8 = 3;

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
async fn a_stream_frame_must_fit_in_the_stream_queue() {
    // The listener's queue limit, as frame header plus payload.
    const QUEUE_LIMIT: usize = 1024 * 1024;
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
