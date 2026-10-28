//! A reader that fails on its own side must still release every send waiting
//! on the peer. The test lowers the descriptor limit of the whole process, so
//! it has a binary of its own.

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use capsudo_proto::Message;
use capsudo_transport::mux::{MuxTransport, Side};
use capsudo_transport::Transport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const KIND_FDS: u8 = 2;
const KIND_HELLO: u8 = 5;

fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// An `Fds` frame delegating one stream that the sender writes.
fn one_stream(id: u32) -> Vec<u8> {
    let mut payload = id.to_le_bytes().to_vec();
    payload.push(1);
    frame(KIND_FDS, &payload)
}

fn set_descriptor_limit(soft: libc::rlim_t) -> libc::rlim_t {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: both calls only read or write the rlimit struct passed to them.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        let previous = limit.rlim_cur;
        limit.rlim_cur = soft;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
        previous
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_that_cannot_make_a_stream_releases_a_waiting_send() {
    let (raw, listener_io) = tokio::io::duplex(64 * 1024);
    let mut listener = MuxTransport::new(listener_io, Side::Listener);
    let (mut raw_read, mut raw_write) = tokio::io::split(raw);
    raw_write
        .write_all(&frame(KIND_HELLO, &1u32.to_le_bytes()))
        .await
        .unwrap();
    raw_write.write_all(&one_stream(1)).await.unwrap();
    let output = listener.recv().await.unwrap().unwrap().fds.pop().unwrap();

    // Take what the listener sends, but never grant, so its output stays unsent.
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 64 * 1024];
        while raw_read.read(&mut buffer).await.is_ok_and(|read| read > 0) {}
    });
    let mut output = UnixStream::from(output);
    std::thread::spawn(move || {
        let chunk = vec![0u8; 64 * 1024];
        while std::io::Write::write_all(&mut output, &chunk).is_ok() {}
    });
    tokio::time::sleep(Duration::from_millis(250)).await;

    let send = tokio::spawn(async move {
        let _ = listener.send(&Message::exit(0), &[]).await;
        listener
    });
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        !send.is_finished(),
        "the send should wait behind the output it would overtake"
    );

    // No descriptor is left for the next stream the peer delegates. The limit
    // bounds descriptor numbers, not how many are open, and a new descriptor
    // takes the lowest free number, so every number below this one is in use.
    let lowest_free = std::fs::File::open("/dev/null").unwrap().as_raw_fd();
    let previous = set_descriptor_limit(lowest_free as libc::rlim_t);
    raw_write.write_all(&one_stream(3)).await.unwrap();
    let released = timeout(Duration::from_secs(5), send).await;
    set_descriptor_limit(previous);

    assert!(
        released.is_ok(),
        "the send kept waiting after the reader had stopped"
    );
}
