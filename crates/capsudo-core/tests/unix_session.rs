//! Full sessions over a real Unix-domain socket, connected the way `capsudod`
//! accepts them, so `SO_PEERSEC` is live.
//!
//! The daemon reads the peer's label through `SO_PEERSEC` and applies it to
//! the child. On a host whose LSM is not SELinux (AppArmor on Ubuntu, which
//! includes GitHub's `ubuntu-latest` runners) that label is not an exec
//! context, and applying it made every spawn fail with `EINVAL`. The in-memory
//! transports used by the other tests report no label, so they could not
//! catch this.

use std::os::fd::AsFd;
use std::path::PathBuf;

use capsudo_core::{run_session, serve_connection, ClientRequest, DaemonConfig, SessionOutcome};
use capsudo_proto::SessionType;
use capsudo_transport::{Transport, UnixListener, UnixTransport};

fn temp_sock(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "capsudo-core-test-{}-{}.sock",
        std::process::id(),
        tag
    ))
}

/// Runs `args` through a daemon on a fresh socket and returns how it ended.
async fn run_over_unix_socket(
    tag: &str,
    args: &[&str],
    session_type: SessionType,
) -> SessionOutcome {
    let path = temp_sock(tag);
    let mut listener = UnixListener::bind(&path, None, None, 0o700).unwrap();

    let server = tokio::spawn(async move {
        let mut conn = listener.accept_unix().await.unwrap();
        // Shown on failure, to tell which LSM answered on this host.
        eprintln!(
            "peer SO_PEERSEC: {:?}",
            conn.peer_secontext()
                .map(|label| String::from_utf8_lossy(&label).into_owned())
        );
        serve_connection(&mut conn, &DaemonConfig::default()).await
    });

    // stdin is a pipe that is already at EOF; output goes to /dev/null.
    let (stdin_r, stdin_w) = std::io::pipe().unwrap();
    drop(stdin_w);
    let devnull = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();

    let request = ClientRequest {
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        env: Vec::new(),
        session_type,
        winsize: (session_type == SessionType::Interactive).then_some([24, 80, 0, 0]),
    };

    let mut client = UnixTransport::connect(&path).await.unwrap();
    let stdio = [stdin_r.as_fd(), devnull.as_fd(), devnull.as_fd()];
    let outcome = run_session(&mut client, &request, stdio, None)
        .await
        .unwrap();

    server.await.unwrap().unwrap();
    let _ = std::fs::remove_file(&path);
    outcome
}

fn assert_exited_zero(outcome: SessionOutcome) {
    match outcome {
        SessionOutcome::Exited(code) => assert_eq!(code, 0, "`true` should exit 0"),
        SessionOutcome::Failed { code, message } => {
            panic!("daemon could not run the program (exit {code}): {message}")
        }
        SessionOutcome::Unauthorized(prompt) => panic!("unexpected auth challenge: {prompt}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runs_a_program_over_a_unix_socket() {
    let outcome = run_over_unix_socket("direct", &["true"], SessionType::NonInteractive).await;
    assert_exited_zero(outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runs_an_interactive_program_over_a_unix_socket() {
    // The pty path applies the peer label in its own pre_exec, so it is checked
    // separately.
    let outcome = run_over_unix_socket("pty", &["true"], SessionType::Interactive).await;
    assert_exited_zero(outcome);
}
