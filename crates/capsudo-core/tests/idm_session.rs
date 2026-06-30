//! Same end-to-end session as `mux_session`, but over the IDM transport stub
//! (TCP), to confirm the cross-zone path works over a real socket rather than
//! an in-process pipe.

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::time::Duration;

use capsudo_core::{run_client, serve_connection, ClientRequest, DaemonConfig};
use capsudo_proto::SessionType;
use capsudo_transport::idm::{connect, IdmListener};
use capsudo_transport::Listener;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cat_round_trips_over_idm_stub() {
    let mut listener = IdmListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        serve_connection(&mut *conn, &DaemonConfig::default())
            .await
            .unwrap();
    });

    let mut client = connect(addr).await.unwrap();

    let (stdin_r, mut stdin_w) = std::io::pipe().unwrap();
    let (mut stdout_r, stdout_w) = std::io::pipe().unwrap();
    let devnull = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();

    stdin_w.write_all(b"over-idm\n").unwrap();
    drop(stdin_w);

    let request = ClientRequest {
        args: vec!["cat".to_owned()],
        env: Vec::new(),
        session_type: SessionType::NonInteractive,
        winsize: None,
    };

    let stdio = [stdin_r.as_fd(), stdout_w.as_fd(), devnull.as_fd()];
    let code = run_client(&mut client, &request, stdio).await.unwrap();
    assert_eq!(code, 0);

    server_task.await.unwrap();

    let read = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 8];
            stdout_r.read_exact(&mut buf).unwrap();
            buf
        }),
    )
    .await
    .expect("reading stdout timed out")
    .unwrap();

    assert_eq!(&read, b"over-idm");
}
