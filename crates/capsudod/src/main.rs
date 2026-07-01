//! capsudo daemon: bind a socket whose permissions are the capability, and run
//! the delegated program for each client that connects.

use std::os::fd::{FromRawFd, OwnedFd};
use std::process::ExitCode;

use capsudo_core::{serve_connection, DaemonConfig};
use capsudo_transport::ownerspec::{parse_mode, parse_owner_spec};
use capsudo_transport::{Listener, UnixListener, UnixTransport};

struct Options {
    socket: Option<String>,
    env: Vec<String>,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: u32,
    no_client_argv: bool,
    no_client_env: bool,
    program: Vec<String>,
}

fn usage() -> ! {
    eprintln!(
        "usage: capsudod -S socket [-fE] [-o user[:group]] [-m mode] [-e key=value]... [program [args...]]"
    );
    std::process::exit(2);
}

fn parse_options() -> Options {
    let mut opts = Options {
        socket: None,
        env: Vec::new(),
        uid: None,
        gid: None,
        mode: 0o770,
        no_client_argv: false,
        no_client_env: false,
        program: Vec::new(),
    };

    let mut it = std::env::args().skip(1);
    while let Some(token) = it.next() {
        match token.as_str() {
            "-h" | "--help" => usage(),
            "-f" => opts.no_client_argv = true,
            "-E" => opts.no_client_env = true,
            "-S" => opts.socket = Some(it.next().unwrap_or_else(|| usage())),
            "-e" => opts.env.push(it.next().unwrap_or_else(|| usage())),
            "-o" => {
                let spec = it.next().unwrap_or_else(|| usage());
                match parse_owner_spec(&spec) {
                    Some((uid, gid)) => {
                        opts.uid = uid;
                        opts.gid = gid;
                    }
                    None => {
                        eprintln!("capsudod: invalid owner spec: {spec}");
                        std::process::exit(2);
                    }
                }
            }
            "-m" => {
                let spec = it.next().unwrap_or_else(|| usage());
                match parse_mode(&spec) {
                    Some(mode) => opts.mode = mode,
                    None => {
                        eprintln!("capsudod: invalid mode: {spec}");
                        std::process::exit(2);
                    }
                }
            }
            "--" => {
                opts.program.extend(it.by_ref());
                break;
            }
            program => {
                opts.program.push(program.to_owned());
                opts.program.extend(it.by_ref());
                break;
            }
        }
    }

    opts
}

#[tokio::main]
async fn main() -> ExitCode {
    let opts = parse_options();

    let config = DaemonConfig {
        fixed_args: opts.program,
        fixed_env: opts.env,
        no_client_argv: opts.no_client_argv,
        no_client_env: opts.no_client_env,
    };

    let Some(socket) = opts.socket else {
        // One-shot mode: serve a single connection on inherited stdin. This is
        // how an authenticating front-end (capsudod-pwauth) chains to us — it
        // hands over the already-authenticated client socket as our stdin.
        let fd = unsafe { OwnedFd::from_raw_fd(0) };
        let mut transport = match UnixTransport::from_fd(fd) {
            Ok(transport) => transport,
            Err(e) => {
                eprintln!("capsudod: stdin is not a usable socket: {e}");
                return ExitCode::FAILURE;
            }
        };
        return match serve_connection(&mut transport, &config).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("capsudod: session error: {e}");
                ExitCode::FAILURE
            }
        };
    };

    let mut listener = match UnixListener::bind(&socket, opts.uid, opts.gid, opts.mode) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("capsudod: cannot bind {socket}: {e}");
            return ExitCode::FAILURE;
        }
    };

    loop {
        let mut conn = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("capsudod: accept failed: {e}");
                continue;
            }
        };

        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(&mut *conn, &config).await {
                eprintln!("capsudod: session error: {e}");
            }
        });
    }
}
