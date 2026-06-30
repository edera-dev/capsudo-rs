//! Daemon side of a capsudo session.
//!
//! The daemon receives a client's configuration, applies its own policy
//! (attenuation flags, fixed argv/env), then runs the requested program with
//! the delegated stdio descriptors duped onto its standard streams, and relays
//! the exit status back.

use std::os::fd::OwnedFd;
use std::process::Stdio;

use capsudo_proto::{FieldType, SessionType};
use capsudo_transport::Transport;
use tokio::process::Command;

use crate::error::{CoreError, Result};
use crate::exit::{exit_code, send_error, send_exit};
use crate::pty;

/// Default terminal size assumed if the client sends no window size.
const DEFAULT_WINSIZE: [u16; 4] = [24, 80, 0, 0];

/// Daemon-side policy applied to every session.
#[derive(Default, Clone)]
pub struct DaemonConfig {
    /// Argument vector prefix fixed by the daemon (e.g. from its own CLI). The
    /// client's args are appended unless [`no_client_argv`](Self::no_client_argv).
    pub fixed_args: Vec<String>,
    /// Environment entries fixed by the daemon, prepended to the client's.
    pub fixed_env: Vec<String>,
    /// Ignore client-supplied argv entirely (the `-f` attenuation). The daemon
    /// then dictates exactly the command to run.
    pub no_client_argv: bool,
    /// Ignore client-supplied environment entirely (the `-E` attenuation).
    pub no_client_env: bool,
}

/// A fully-assembled request ready to execute.
struct SessionRequest {
    argv: Vec<String>,
    envp: Vec<String>,
    session_type: SessionType,
    stdio: [OwnedFd; 3],
    winsize: [u16; 4],
}

/// Serves a single client connection: receives configuration, runs the
/// program, and reports the exit status.
pub async fn serve_connection(transport: &mut dyn Transport, config: &DaemonConfig) -> Result<()> {
    let request = match receive_configuration(transport, config).await {
        Ok(request) => request,
        Err(e) => {
            let _ = send_error(transport, &e.to_string()).await;
            let _ = send_exit(transport, 1).await;
            return Err(e);
        }
    };

    run_and_report(transport, request).await
}

/// Drains the configuration handshake up to `End`, applying attenuation policy.
async fn receive_configuration(
    transport: &mut dyn Transport,
    config: &DaemonConfig,
) -> Result<SessionRequest> {
    let mut argv = config.fixed_args.clone();
    let mut envp = config.fixed_env.clone();
    let mut session_type = SessionType::NonInteractive;
    let mut stdio: Option<[OwnedFd; 3]> = None;
    let mut winsize = DEFAULT_WINSIZE;

    loop {
        let Some(received) = transport.recv().await? else {
            return Err(CoreError::ClientClosed);
        };

        match received.message.field_type() {
            FieldType::Arg => {
                if !config.no_client_argv {
                    argv.push(received.message.as_str()?.to_owned());
                }
            }
            FieldType::Env => {
                if !config.no_client_env {
                    envp.push(received.message.as_str()?.to_owned());
                }
            }
            FieldType::SessionType => {
                session_type = received.message.as_session_type()?;
            }
            FieldType::Winsize => {
                winsize = received.message.as_winsize()?;
            }
            FieldType::Fd => {
                stdio = Some(received.fds.try_into().map_err(|_| {
                    CoreError::Protocol("expected exactly three stdio descriptors")
                })?);
            }
            // Secrets are consumed by an authenticating front-end, not here.
            FieldType::Secret => {}
            FieldType::End => break,
            _ => {}
        }
    }

    // A session with no program defaults to a shell, matching the C behaviour.
    if argv.is_empty() {
        argv.push("sh".to_owned());
    }

    let stdio = stdio.ok_or(CoreError::Protocol("client did not delegate stdio descriptors"))?;

    Ok(SessionRequest {
        argv,
        envp,
        session_type,
        stdio,
        winsize,
    })
}

/// Spawns the program and relays its exit status, choosing the interactive
/// (pty) or non-interactive (direct stdio) path.
async fn run_and_report(transport: &mut dyn Transport, request: SessionRequest) -> Result<()> {
    if request.session_type == SessionType::Interactive {
        return pty::run_interactive(
            transport,
            request.argv,
            request.envp,
            request.stdio,
            request.winsize,
        )
        .await;
    }

    let [child_stdin, child_stdout, child_stderr] = request.stdio;

    let mut command = Command::new(&request.argv[0]);
    command.args(&request.argv[1..]);

    // Exactly the delegated environment is installed; the daemon's own
    // environment is not inherited (mirrors execvpe with an explicit envp).
    command.env_clear();
    for entry in &request.envp {
        if let Some((key, value)) = entry.split_once('=') {
            command.env(key, value);
        }
    }

    command.stdin(Stdio::from(child_stdin));
    command.stdout(Stdio::from(child_stdout));
    command.stderr(Stdio::from(child_stderr));

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            let _ = send_error(transport, &format!("unable to run {}: {e}", request.argv[0])).await;
            return send_exit(transport, 127).await;
        }
    };

    let status = child.wait().await?;
    send_exit(transport, exit_code(status)).await
}
