//! Dropping a multiplexing transport must close the channel under it, or a peer
//! in a long-lived process (a zone agent, the daemon) waits on it forever.

use std::time::Duration;

use capsudo_proto::{FieldType, Message};
use capsudo_transport::mux::{MuxTransport, Side};
use capsudo_transport::Transport;
use tokio::time::timeout;

#[tokio::test]
async fn dropping_a_mux_ends_the_peers_stream() {
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let mux = MuxTransport::new(ours, Side::Dialer);
    let mut peer = MuxTransport::new(theirs, Side::Listener);

    drop(mux);

    let received = timeout(Duration::from_secs(5), peer.recv())
        .await
        .expect("the peer never saw the dropped side close");
    assert!(received.unwrap().is_none());
}

#[tokio::test]
async fn a_frame_sent_just_before_the_drop_still_arrives() {
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let mut mux = MuxTransport::new(ours, Side::Dialer);
    let mut peer = MuxTransport::new(theirs, Side::Listener);

    mux.send(&Message::arg("last"), &[]).await.unwrap();
    drop(mux);

    let received = timeout(Duration::from_secs(5), peer.recv())
        .await
        .expect("the queued frame never arrived")
        .unwrap()
        .expect("the stream ended before the queued frame");
    assert_eq!(received.message.field_type(), FieldType::Arg);
    assert_eq!(received.message.as_str().unwrap(), "last");

    let after = timeout(Duration::from_secs(5), peer.recv())
        .await
        .expect("the peer never saw the dropped side close");
    assert!(after.unwrap().is_none());
}
