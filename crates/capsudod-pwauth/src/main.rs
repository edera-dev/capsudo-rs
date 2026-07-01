//! Authenticating front-end for capsudo.
//!
//! `capsudod-pwauth` listens on a socket, identifies the connecting user from
//! the peer credentials, and requires a shadow-password secret before chaining
//! the (now authenticated) connection to `capsudod`, which performs the actual
//! privileged exec. It is the building block for an "attenuation pipeline":
//!
//! ```text
//! capsudod-pwauth -S sock -o owner -m mode -- capsudod <args> -- <program>
//! ```
//!
//! On success it hands the live socket to `capsudod` as its stdin (one-shot
//! mode), so `capsudod` reads the rest of the client's configuration — including
//! the delegated descriptors — directly.

use std::os::fd::OwnedFd;
use std::process::Stdio;

use capsudo_proto::{FieldType, Message};
use capsudo_transport::ownerspec::{parse_mode, parse_owner_spec};
use capsudo_transport::{Transport, UnixListener, UnixTransport};
use nix::unistd::{Uid, User};

mod shadow;

struct Options {
    socket: Option<String>,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: u32,
    capsudod_cmd: Vec<String>,
}

fn usage() -> ! {
    eprintln!("usage: capsudod-pwauth -S socket [-o user[:group]] [-m mode] -- capsudod [args...]");
    std::process::exit(2);
}

fn parse_options() -> Options {
    let mut opts = Options {
        socket: None,
        uid: None,
        gid: None,
        mode: 0o770,
        capsudod_cmd: Vec::new(),
    };

    let mut it = std::env::args().skip(1);
    while let Some(token) = it.next() {
        match token.as_str() {
            "-h" | "--help" => usage(),
            "-S" => opts.socket = Some(it.next().unwrap_or_else(|| usage())),
            "-o" => {
                let spec = it.next().unwrap_or_else(|| usage());
                match parse_owner_spec(&spec) {
                    Some((uid, gid)) => {
                        opts.uid = uid;
                        opts.gid = gid;
                    }
                    None => {
                        eprintln!("capsudod-pwauth: invalid owner spec: {spec}");
                        std::process::exit(2);
                    }
                }
            }
            "-m" => {
                let spec = it.next().unwrap_or_else(|| usage());
                match parse_mode(&spec) {
                    Some(mode) => opts.mode = mode,
                    None => {
                        eprintln!("capsudod-pwauth: invalid mode: {spec}");
                        std::process::exit(2);
                    }
                }
            }
            "--" => {
                opts.capsudod_cmd.extend(it.by_ref());
                break;
            }
            other => {
                opts.capsudod_cmd.push(other.to_owned());
                opts.capsudod_cmd.extend(it.by_ref());
                break;
            }
        }
    }

    // Default to plain `capsudod` if no command was given after `--`.
    if opts.capsudod_cmd.is_empty() {
        opts.capsudod_cmd.push("capsudod".to_owned());
    }

    opts
}

fn hostname() -> String {
    nix::unistd::gethostname()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "localhost".to_owned())
}

fn auth_prompt(user: &str) -> String {
    format!("[capsudo] {user}@{}'s password: ", hostname())
}

/// Sends a terminal error (an `Error` followed by an `Exit`) so the client
/// shuts down cleanly rather than observing a connection reset.
async fn fail(transport: &mut UnixTransport, message: &str) {
    let _ = transport.send(&Message::error(message), &[]).await;
    let _ = transport.send(&Message::exit(1), &[]).await;
}

/// Handles one client: authenticate, then chain to capsudod on success.
async fn handle_client(mut transport: UnixTransport, capsudod_cmd: Vec<String>) {
    let Some(cred) = transport.peer_cred() else {
        fail(&mut transport, "unable to determine peer credentials").await;
        return;
    };

    let user = match User::from_uid(Uid::from_raw(cred.uid)) {
        Ok(Some(user)) => user.name,
        _ => {
            fail(&mut transport, "unknown peer user").await;
            return;
        }
    };

    let prompt = auth_prompt(&user);

    let Ok(Some(received)) = transport.recv().await else {
        return;
    };

    // Reject any attempt to smuggle descriptors on the authentication channel,
    // and any first message that is not a secret, with a prompt to retry.
    if !received.fds.is_empty() || received.message.field_type() != FieldType::Secret {
        let _ = transport.send(&Message::unauthorized(&prompt), &[]).await;
        return;
    }

    if !shadow::check_password(&user, received.message.payload()) {
        fail(&mut transport, "secret invalid").await;
        return;
    }

    // Authenticated: hand the live socket to capsudod as its stdin.
    let Ok(std_stream) = transport.into_inner().into_std() else {
        return;
    };
    let fd = OwnedFd::from(std_stream);

    let mut command = std::process::Command::new(&capsudod_cmd[0]);
    command.args(&capsudod_cmd[1..]);
    command.stdin(Stdio::from(fd));
    // Inherit stdout/stderr for diagnostics; we do not wait (SIGCHLD ignored).
    if let Err(e) = command.spawn() {
        eprintln!("capsudod-pwauth: cannot spawn {}: {e}", capsudod_cmd[0]);
    }
}

#[tokio::main]
async fn main() {
    let opts = parse_options();

    // Children (the capsudod we spawn) are reaped automatically; we never wait.
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN);
    }

    let Some(socket) = opts.socket else {
        usage();
    };

    let mut listener = match UnixListener::bind(&socket, opts.uid, opts.gid, opts.mode) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("capsudod-pwauth: cannot bind {socket}: {e}");
            std::process::exit(1);
        }
    };

    loop {
        match listener.accept_unix().await {
            Ok(transport) => {
                let cmd = opts.capsudod_cmd.clone();
                tokio::spawn(handle_client(transport, cmd));
            }
            Err(e) => eprintln!("capsudod-pwauth: accept failed: {e}"),
        }
    }
}
