//! capsudo client: connect to a capsudo daemon and invoke the capability it
//! holds, delegating this process's stdio to the program it runs.

use std::os::fd::{AsFd, AsRawFd};
use std::process::ExitCode;

use capsudo_core::{run_client, ClientRequest};
use capsudo_proto::SessionType;
use capsudo_transport::UnixTransport;

/// Default endpoint when `-S` is not given.
const DEFAULT_SOCKET: &str = "/run/capsudo/default";

/// Environment variables forwarded by default so the remote program behaves
/// sensibly in the caller's terminal/locale.
const DEFAULT_ENV: &[&str] = &[
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "COLORTERM",
];

struct Options {
    socket: String,
    session: Option<SessionType>,
    shell: bool,
    env: Vec<String>,
    args: Vec<String>,
}

fn usage() -> ! {
    eprintln!("usage: capsudo [-S socket] [-i|-n] [-s] [-e key=value]... [program [args...]]");
    eprintln!("default socket: {DEFAULT_SOCKET}");
    std::process::exit(2);
}

fn parse_options() -> Options {
    let mut opts = Options {
        socket: DEFAULT_SOCKET.to_owned(),
        session: None,
        shell: false,
        env: Vec::new(),
        args: Vec::new(),
    };

    let mut it = std::env::args().skip(1);
    while let Some(token) = it.next() {
        match token.as_str() {
            "-h" | "--help" => usage(),
            "-i" => opts.session = Some(SessionType::Interactive),
            "-n" => opts.session = Some(SessionType::NonInteractive),
            "-s" => opts.shell = true,
            "-S" => opts.socket = it.next().unwrap_or_else(|| usage()),
            "-e" => opts.env.push(it.next().unwrap_or_else(|| usage())),
            "--" => {
                opts.args.extend(it.by_ref());
                break;
            }
            // First non-flag token begins the program; the rest are its args
            // verbatim (so `capsudo ls -la` works as expected).
            program => {
                opts.args.push(program.to_owned());
                opts.args.extend(it.by_ref());
                break;
            }
        }
    }

    opts
}

/// Forwards selected environment variables from this process, appending them to
/// any the user supplied explicitly.
fn append_default_env(env: &mut Vec<String>) {
    for name in DEFAULT_ENV {
        if let Ok(value) = std::env::var(name) {
            env.push(format!("{name}={value}"));
        }
    }
}

/// Picks a session type when the user did not force one: interactive if both
/// stdin and stdout are terminals.
fn determine_session_type() -> SessionType {
    let stdin_tty = nix::unistd::isatty(std::io::stdin().as_raw_fd()).unwrap_or(false);
    let stdout_tty = nix::unistd::isatty(std::io::stdout().as_raw_fd()).unwrap_or(false);
    if stdin_tty && stdout_tty {
        SessionType::Interactive
    } else {
        SessionType::NonInteractive
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut opts = parse_options();

    if opts.shell {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "sh".to_owned());
        opts.args = vec![shell];
    }

    append_default_env(&mut opts.env);

    let session_type = opts.session.unwrap_or_else(determine_session_type);

    let request = ClientRequest {
        args: opts.args,
        env: opts.env,
        session_type,
    };

    let mut transport = match UnixTransport::connect(&opts.socket).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("capsudo: cannot connect to daemon at {}: {e}", opts.socket);
            return ExitCode::FAILURE;
        }
    };

    // Non-interactive: delegate our own standard streams. (Interactive pty
    // allocation arrives in a later step.)
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let stdio = [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()];

    match run_client(&mut transport, &request, stdio).await {
        Ok(code) => ExitCode::from(u8::try_from(code & 0xff).unwrap_or(0)),
        Err(e) => {
            eprintln!("capsudo: {e}");
            ExitCode::FAILURE
        }
    }
}
