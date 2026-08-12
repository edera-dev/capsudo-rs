//! End-to-end proof that a full capsudo session works over the multiplexing
//! transport — i.e. with *simulated* descriptor passing, no `SCM_RIGHTS` — so
//! the same client/daemon logic would run across an Edera zone boundary.
//!
//! The client runs `cat` through the daemon, feeding stdin and capturing stdout
//! entirely through multiplexed streams over an in-memory byte channel.

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::time::Duration;

use capsudo_core::{run_client, serve_connection, ClientRequest, DaemonConfig};
use capsudo_proto::SessionType;
use capsudo_transport::mux::{MuxTransport, Side};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cat_round_trips_stdio_over_multiplexer() {
    // The cross-zone byte channel, stood in for by an in-memory duplex pipe.
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let mut server = MuxTransport::new(server_io, Side::Listener);
    let mut client = MuxTransport::new(client_io, Side::Dialer);

    // Daemon: run whatever the client asks (no fixed program).
    let server_task = tokio::spawn(async move {
        serve_connection(&mut server, &DaemonConfig::default())
            .await
            .unwrap();
    });

    // Client stdio, all backed by ordinary pipes we control.
    let (stdin_r, mut stdin_w) = std::io::pipe().unwrap();
    let (mut stdout_r, stdout_w) = std::io::pipe().unwrap();
    let devnull = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();

    // Preload stdin and close the writer so `cat` sees EOF and exits.
    stdin_w.write_all(b"hello\n").unwrap();
    drop(stdin_w);

    let request = ClientRequest {
        args: vec!["cat".to_owned()],
        env: Vec::new(),
        session_type: SessionType::NonInteractive,
        winsize: None,
    };

    let stdio = [stdin_r.as_fd(), stdout_w.as_fd(), devnull.as_fd()];
    let code = run_client(&mut client, &request, stdio).await.unwrap();
    assert_eq!(code, 0, "cat should exit cleanly");

    server_task.await.unwrap();

    // The bytes cat wrote to its stdout came back through the multiplexed
    // stream and into our pipe.
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 6];
            stdout_r.read_exact(&mut buf).unwrap();
            buf
        }),
    )
    .await
    .expect("reading stdout timed out")
    .unwrap();

    assert_eq!(&read, b"hello\n");
}

/// A caller may delegate descriptors it also drives with an async runtime, so
/// they arrive here non-blocking — and `dup` shares the open file description,
/// so the pump inherits that. Writing more than the descriptor can absorb must
/// therefore wait for room rather than give up: treating `EAGAIN` as fatal
/// truncated the stream silently, with no error anywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn output_survives_a_non_blocking_stdout_that_fills_up() {
    // Comfortably more than a socket buffer, so the pump cannot possibly write
    // it all in one go.
    const PAYLOAD: usize = 4 * 1024 * 1024;

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let mut server = MuxTransport::new(server_io, Side::Listener);
    let mut client = MuxTransport::new(client_io, Side::Dialer);

    let server_task = tokio::spawn(async move {
        serve_connection(&mut server, &DaemonConfig::default())
            .await
            .unwrap();
    });

    let (mut sink, stdout_w) = std::os::unix::net::UnixStream::pair().unwrap();
    stdout_w.set_nonblocking(true).unwrap();
    let stdin_r = std::fs::File::open("/dev/null").unwrap();
    let devnull = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();

    // Deliberately late: let the socket fill first, so the pump has to cope
    // with a descriptor that cannot take another byte.
    let drain = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(250));
        let mut received = Vec::new();
        sink.read_to_end(&mut received).unwrap();
        received.len()
    });

    let request = ClientRequest {
        args: vec![
            "head".to_owned(),
            "-c".to_owned(),
            PAYLOAD.to_string(),
            "/dev/zero".to_owned(),
        ],
        env: Vec::new(),
        session_type: SessionType::NonInteractive,
        winsize: None,
    };

    let stdio = [stdin_r.as_fd(), stdout_w.as_fd(), devnull.as_fd()];
    let code = run_client(&mut client, &request, stdio).await.unwrap();
    assert_eq!(code, 0, "head should exit cleanly");
    server_task.await.unwrap();

    // Close both ends of the write side — ours here, and the pump's `dup` when
    // dropping the transport ends it — so the drain reaches EOF.
    drop(client);
    drop(stdout_w);

    let received = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || drain.join().unwrap()),
    )
    .await
    .expect("draining stdout timed out")
    .unwrap();

    assert_eq!(
        received, PAYLOAD,
        "every byte should arrive; a short read means the pump gave up on a full descriptor"
    );
}
