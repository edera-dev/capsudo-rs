//! End-to-end check that the Unix transport carries both a message payload and
//! a real file descriptor (via `SCM_RIGHTS`) across a connection.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;

use capsudo_proto::{FieldType, Message};
use capsudo_transport::{FdSpec, Listener, Transport, UnixListener, UnixTransport};

fn temp_sock(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("capsudo-test-{}-{}.sock", std::process::id(), tag))
}

#[tokio::test]
async fn passes_payload_and_descriptor() {
    let path = temp_sock("roundtrip");
    let mut listener = UnixListener::bind(&path, None, None, 0o700).unwrap();

    let server = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        let received = conn.recv().await.unwrap().expect("a message");

        assert_eq!(received.message.field_type(), FieldType::Arg);
        assert_eq!(received.message.as_str().unwrap(), "hello");
        assert_eq!(received.fds.len(), 1, "exactly one descriptor delivered");

        // The descriptor we got is a dup of the client's pipe write end.
        let mut wr = File::from(received.fds.into_iter().next().unwrap());
        wr.write_all(b"ping").unwrap();
    });

    // Client side: build a pipe, hand the write end to the server.
    let (rd, wr) = nix::unistd::pipe().unwrap();
    let mut client = UnixTransport::connect(&path).await.unwrap();
    client
        .send(&Message::arg("hello"), &[FdSpec::write(wr.as_fd())])
        .await
        .unwrap();

    server.await.unwrap();
    drop(wr); // close our copy so only the server's dup remains

    // What the server wrote through its dup appears on our read end.
    let mut rd = File::from(rd);
    let mut buf = [0u8; 4];
    rd.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn clean_eof_returns_none() {
    let path = temp_sock("eof");
    let mut listener = UnixListener::bind(&path, None, None, 0o700).unwrap();

    let server = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        // Peer connects and immediately drops: recv should report clean EOF.
        assert!(conn.recv().await.unwrap().is_none());
    });

    let client = UnixTransport::connect(&path).await.unwrap();
    drop(client);

    server.await.unwrap();
    let _ = std::fs::remove_file(&path);
}
