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

/// Runs a client session to completion and returns the target program's exit
/// status.
///
/// `stdio` holds the three descriptors (stdin, stdout, stderr) to delegate. For
/// a non-interactive session these are the client's own standard streams; for
/// an interactive session they are the client's terminal, which the daemon
/// bridges to the pty it allocates.
pub async fn run_client(
    transport: &mut dyn Transport,
    request: &ClientRequest,
    stdio: [BorrowedFd<'_>; 3],
) -> Result<i32> {
    send_configuration(transport, request, stdio).await?;

    // For an interactive session, forward terminal resizes for as long as the
    // session lasts. The task borrows nothing from this scope (it copies the
    // terminal fd), so it can outlive a single recv and is aborted on return.
    let winch_task = match (request.winsize.is_some(), transport.control_sender()) {
        (true, Some(sender)) => Some(spawn_winch_forwarder(sender, stdio[0].as_raw_fd())),
        _ => None,
    };

    let result = await_exit(transport).await;

    if let Some(task) = winch_task {
        task.abort();
    }
    result
}

/// Waits for the daemon's exit (or error) messages.
async fn await_exit(transport: &mut dyn Transport) -> Result<i32> {
    loop {
        let Some(received) = transport.recv().await? else {
            return Err(CoreError::DaemonClosed);
        };

        match received.message.field_type() {
            FieldType::Exit => return Ok(received.message.as_i32()?),
            FieldType::Error => {
                eprintln!(
                    "capsudo: error: {}",
                    received.message.as_str().unwrap_or("<malformed error>")
                );
            }
            other => {
                eprintln!("capsudo: ignoring unexpected message {other:?}");
            }
        }
    }
}

/// Sends the configuration handshake: env, args, session type, window size (if
/// interactive), the stdio descriptors, then `End`.
async fn send_configuration(
    transport: &mut dyn Transport,
    request: &ClientRequest,
    stdio: [BorrowedFd<'_>; 3],
) -> Result<()> {
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
