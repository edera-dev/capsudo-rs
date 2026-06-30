//! capsudo client: connect to a capsudo daemon and invoke the capability it
//! holds, delegating this process's stdio to the program it runs.

use std::os::fd::{AsFd, AsRawFd, RawFd};
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

/// Puts a terminal into raw mode for the duration of a session, restoring the
/// original settings on drop.
struct RawMode {
    fd: RawFd,
    original: nix::sys::termios::Termios,
}

impl RawMode {
    fn enable(fd: RawFd) -> Option<RawMode> {
        use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, SetArg};
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
        let original = tcgetattr(borrowed).ok()?;
        let mut raw = original.clone();
        cfmakeraw(&mut raw);
        tcsetattr(borrowed, SetArg::TCSANOW, &raw).ok()?;
        Some(RawMode { fd, original })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        use nix::sys::termios::{tcsetattr, SetArg};
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(self.fd) };
        let _ = tcsetattr(borrowed, SetArg::TCSANOW, &self.original);
    }
}

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
    let interactive = session_type == SessionType::Interactive;

    // For an interactive session, capture the terminal size and put our own
    // terminal into raw mode so keystrokes pass through to the daemon's pty
    // unmodified. The guard restores the terminal on return.
    let mut request_winsize = None;
    let _raw_guard = if interactive {
        request_winsize = capsudo_core::read_winsize(std::io::stdin().as_raw_fd());
        RawMode::enable(std::io::stdin().as_raw_fd())
    } else {
        None
    };

    let request = ClientRequest {
        args: opts.args,
        env: opts.env,
        session_type,
        winsize: request_winsize,
    };

    let mut transport = match UnixTransport::connect(&opts.socket).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("capsudo: cannot connect to daemon at {}: {e}", opts.socket);
            return ExitCode::FAILURE;
        }
    };

    // Delegate our own standard streams; for an interactive session these are
    // our terminal, which the daemon bridges to the pty it allocates.
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
