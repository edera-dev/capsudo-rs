//! Helpers shared by the interactive and non-interactive daemon paths for
//! reporting status back to the client.

use std::os::unix::process::ExitStatusExt;

use capsudo_proto::Message;
use capsudo_transport::Transport;

use crate::error::Result;

/// Maps a process exit status to capsudo's reported code: the exit code if it
/// exited normally, or `128 + signal` if it was killed.
pub(crate) fn exit_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        code
    } else if let Some(signal) = status.signal() {
        128 + signal
    } else {
        1
    }
}

pub(crate) async fn send_error(transport: &mut dyn Transport, message: &str) -> Result<()> {
    transport.send(&Message::error(message), &[]).await?;
    Ok(())
}

pub(crate) async fn send_exit(transport: &mut dyn Transport, code: i32) -> Result<()> {
    transport.send(&Message::exit(code), &[]).await?;
    Ok(())
}

/// Reports a failed program spawn to the client: a human-readable error
/// followed by the conventional exit code 127.
pub(crate) async fn send_spawn_failure(
    transport: &mut dyn Transport,
    program: &str,
    err: &std::io::Error,
) -> Result<()> {
    let _ = send_error(transport, &format!("unable to run {program}: {err}")).await;
    send_exit(transport, 127).await
}
