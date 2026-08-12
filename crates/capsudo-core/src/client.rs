//! Client side of a capsudo session.
//!
//! The client describes *what* to run (argv, environment, session type) and
//! delegates the descriptors its program should use for stdio, then waits for
//! the daemon to report an exit status. It is written entirely against
//! [`Transport`] and so is identical whether the daemon is local or in another
//! Edera zone.
//!
//! For interactive sessions the pty lives on the daemon side (see
//! [`crate::pty`]); the client's only extra duties are to forward its terminal
//! size up front and to relay `SIGWINCH` resizes during the session.

use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use capsudo_proto::{FieldType, Message, SessionType};
use capsudo_transport::{ControlSender, FdSpec, Transport};
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinHandle;

use crate::error::{CoreError, Result};

/// What the client is asking the daemon to do.
pub struct ClientRequest {
    /// Argument vector for the target program. Empty means "the daemon decides"
    /// (typically a shell).
    pub args: Vec<String>,
    /// Environment entries to install, each `KEY=VALUE`.
    pub env: Vec<String>,
    /// Requested stdio handling.
    pub session_type: SessionType,
    /// Initial terminal size `[rows, cols, xpixels, ypixels]` for interactive
    /// sessions; `None` for non-interactive.
    pub winsize: Option<[u16; 4]>,
}

/// How a client session ended.
pub enum SessionOutcome {
    /// The program ran and exited with this status.
    Exited(i32),
    /// The daemon reported why it would not run the program, and the session
    /// ended with `code`. Kept distinct from [`SessionOutcome::Exited`] so a
    /// caller can tell "the program ran and failed" from "the program never
    /// ran", and can put the daemon's own words somewhere useful.
    Failed { code: i32, message: String },
    /// The daemon (or an authenticating front-end) requires a secret; the
    /// payload is the prompt to show the user. The caller should obtain a
    /// secret, reconnect, and retry with it.
    Unauthorized(String),
}

/// Runs a client session to completion and returns the target program's exit
/// status. Treats an authentication challenge as an error; use [`run_session`]
/// to drive the secret-retry flow.
pub async fn run_client(
    transport: &mut dyn Transport,
    request: &ClientRequest,
    stdio: [BorrowedFd<'_>; 3],
) -> Result<i32> {
    match run_session(transport, request, stdio, None).await? {
        SessionOutcome::Exited(code) => Ok(code),
        // There is no exit status to report: the program never ran, and the
        // daemon said why.
        SessionOutcome::Failed { message, .. } => Err(CoreError::Refused(message)),
        SessionOutcome::Unauthorized(_) => Err(CoreError::Protocol("authentication required")),
    }
}

/// Runs one client session, optionally presenting `secret` for authentication.
///
/// `stdio` holds the three descriptors (stdin, stdout, stderr) to delegate. For
/// a non-interactive session these are the client's own standard streams; for
/// an interactive session they are the client's terminal, which the daemon
/// bridges to the pty it allocates.
pub async fn run_session(
    transport: &mut dyn Transport,
    request: &ClientRequest,
    stdio: [BorrowedFd<'_>; 3],
    secret: Option<&str>,
) -> Result<SessionOutcome> {
    // An authenticating front-end may reject and close the connection after the
    // first non-secret message, so a send failure is not necessarily fatal — the
    // auth challenge may already be waiting to be read. Try the read regardless,
    // and only surface the send error if nothing useful came back.
    let send_result = send_configuration(transport, request, stdio, secret).await;

    // For an interactive session, forward terminal resizes for as long as the
    // session lasts. The task borrows nothing from this scope (it copies the
    // terminal fd), so it can outlive a single recv and is aborted on return.
    let winch_task = if send_result.is_ok() && request.winsize.is_some() {
        transport
            .control_sender()
            .map(|sender| spawn_winch_forwarder(sender, stdio[0].as_raw_fd()))
    } else {
        None
    };

    let result = await_outcome(transport).await;

    if let Some(task) = winch_task {
        task.abort();
    }

    match (result, send_result) {
        (Ok(outcome), _) => Ok(outcome),
        (Err(recv_err), Ok(())) => Err(recv_err),
        (Err(_), Err(send_err)) => Err(send_err),
    }
}

/// Waits for the daemon's terminal message (exit, or an auth challenge).
///
/// An `Error` is not itself terminal — the daemon sends it and then an `Exit` —
/// so it is carried until the exit arrives and returned with it. This is a
/// library: writing the daemon's message to the process's stderr would put it
/// somewhere an embedder cannot capture, redirect, or attribute, and lose it
/// for the caller entirely.
async fn await_outcome(transport: &mut dyn Transport) -> Result<SessionOutcome> {
    let mut failure: Option<String> = None;
    loop {
        let Some(received) = transport.recv().await? else {
            return Err(CoreError::DaemonClosed);
        };

        match received.message.field_type() {
            FieldType::Exit => {
                let code = received.message.as_i32()?;
                return Ok(match failure {
                    Some(message) => SessionOutcome::Failed { code, message },
                    None => SessionOutcome::Exited(code),
                });
            }
            FieldType::Unauthorized => {
                let prompt = received.message.as_str().unwrap_or("password: ").to_owned();
                return Ok(SessionOutcome::Unauthorized(prompt));
            }
            FieldType::Error => {
                // Keep the first: it is the one that describes why the session
                // failed, and anything after it is likely a consequence.
                failure.get_or_insert_with(|| {
                    received
                        .message
                        .as_str()
                        .unwrap_or("<malformed error>")
                        .to_owned()
                });
            }
            // Nothing else is meaningful here, and a peer is free to send
            // messages this version does not know about.
            _ => {}
        }
    }
}

/// Sends the configuration handshake: secret (if any), env, args, session type,
/// window size (if interactive), the stdio descriptors, then `End`.
async fn send_configuration(
    transport: &mut dyn Transport,
    request: &ClientRequest,
    stdio: [BorrowedFd<'_>; 3],
    secret: Option<&str>,
) -> Result<()> {
    if let Some(secret) = secret {
        transport.send(&Message::secret(secret), &[]).await?;
    }

    for entry in &request.env {
        transport.send(&Message::env(entry), &[]).await?;
    }
    for arg in &request.args {
        transport.send(&Message::arg(arg), &[]).await?;
    }
    transport
        .send(&Message::session_type(request.session_type), &[])
        .await?;

    if let Some(dims) = request.winsize {
        transport.send(&Message::winsize(dims), &[]).await?;
    }

    // stdio[0] is the program's input (we read it), stdio[1]/[2] its outputs (we
    // write them). Tagging the directions lets a multiplexing transport pump
    // each the right way; the local transport ignores the tags.
    let fds = [
        FdSpec::read(stdio[0]),
        FdSpec::write(stdio[1]),
        FdSpec::write(stdio[2]),
    ];
    transport.send(&Message::fds(3), &fds).await?;
    transport.send(&Message::end(), &[]).await?;
    Ok(())
}

/// Spawns a task that resends the terminal size whenever `SIGWINCH` fires.
fn spawn_winch_forwarder(sender: Box<dyn ControlSender>, term_fd: RawFd) -> JoinHandle<()> {
    tokio::spawn(async move {
        let Ok(mut winch) = signal(SignalKind::window_change()) else {
            return;
        };
        while winch.recv().await.is_some() {
            if let Some(dims) = read_winsize(term_fd) {
                if sender.send_control(Message::winsize(dims)).await.is_err() {
                    break;
                }
            }
        }
    })
}

/// Reads the current terminal dimensions from `fd`.
pub fn read_winsize(fd: RawFd) -> Option<[u16; 4]> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ as _, &mut ws) } < 0 {
        return None;
    }
    Some([ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel])
}
