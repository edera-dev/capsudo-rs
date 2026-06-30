//! Client side of a capsudo session.
//!
//! The client describes *what* to run (argv, environment, session type) and
//! delegates the descriptors its program should use for stdio, then waits for
//! the daemon to report an exit status. It is written entirely against
//! [`Transport`] and so is identical whether the daemon is local or in another
//! Edera zone.

use std::os::fd::BorrowedFd;

use capsudo_proto::{FieldType, Message, SessionType};
use capsudo_transport::Transport;

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
}

/// Runs a client session to completion and returns the target program's exit
/// status.
///
/// `stdio` holds the three descriptors (stdin, stdout, stderr) to delegate to
/// the program the daemon runs. For a non-interactive session these are the
/// client's own standard streams; for an interactive session they are the three
/// ends of a locally-allocated pty.
pub async fn run_client(
    transport: &mut dyn Transport,
    request: &ClientRequest,
    stdio: [BorrowedFd<'_>; 3],
) -> Result<i32> {
    send_configuration(transport, request, stdio).await?;

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

/// Sends the configuration handshake: env, args, session type, the stdio
/// descriptors, then `End`.
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
    transport.send(&Message::fds(3), &stdio).await?;
    transport.send(&Message::end(), &[]).await?;
    Ok(())
}
