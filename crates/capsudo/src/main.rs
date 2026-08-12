//! capsudo client: connect to a capsudo daemon and invoke the capability it
//! holds, delegating this process's stdio to the program it runs.

use std::os::fd::{AsFd, AsRawFd};
use std::process::ExitCode;

use capsudo_core::{run_session, ClientRequest, SessionOutcome};
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

/// Puts the terminal on stdin into raw mode for the duration of a session,
/// restoring the original settings on drop.
struct RawMode {
    original: nix::sys::termios::Termios,
}

impl RawMode {
    fn enable() -> Option<RawMode> {
        use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, SetArg};
        let stdin = std::io::stdin();
        let original = tcgetattr(stdin.as_fd()).ok()?;
        let mut raw = original.clone();
        cfmakeraw(&mut raw);
        tcsetattr(stdin.as_fd(), SetArg::TCSANOW, &raw).ok()?;
        Some(RawMode { original })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        use nix::sys::termios::{tcsetattr, SetArg};
        let _ = tcsetattr(std::io::stdin().as_fd(), SetArg::TCSANOW, &self.original);
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
    let stdin_tty = nix::unistd::isatty(std::io::stdin()).unwrap_or(false);
    let stdout_tty = nix::unistd::isatty(std::io::stdout()).unwrap_or(false);
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
        RawMode::enable()
    } else {
        None
    };

    let request = ClientRequest {
        args: opts.args,
        env: opts.env,
        session_type,
        winsize: request_winsize,
    };

    // Delegate our own standard streams; for an interactive session these are
    // our terminal, which the daemon bridges to the pty it allocates.
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let stdio = [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()];

    // Reconnect-and-retry once if an authenticating front-end demands a secret.
    let mut secret: Option<String> = None;
    loop {
        let mut transport = match UnixTransport::connect(&opts.socket).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("capsudo: cannot connect to daemon at {}: {e}", opts.socket);
                return ExitCode::FAILURE;
            }
        };

        match run_session(&mut transport, &request, stdio, secret.as_deref()).await {
            Ok(SessionOutcome::Exited(code)) => {
                return ExitCode::from((code & 0xff) as u8);
            }
            // The library hands the daemon's explanation back rather than
            // printing it, so telling the user is this binary's job.
            Ok(SessionOutcome::Failed { code, message }) => {
                eprintln!("capsudo: error: {message}");
                return ExitCode::from((code & 0xff) as u8);
            }
            Ok(SessionOutcome::Unauthorized(prompt)) => {
                if secret.is_some() {
                    eprintln!("capsudo: authentication failed");
                    return ExitCode::FAILURE;
                }
                match prompt_secret(&prompt) {
                    Some(s) => secret = Some(s),
                    None => {
                        eprintln!("capsudo: a secret is required but none was provided");
                        return ExitCode::FAILURE;
                    }
                }
            }
            Err(e) => {
                eprintln!("capsudo: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
}

/// Prompts for a secret on the controlling terminal with echo disabled.
fn prompt_secret(prompt: &str) -> Option<String> {
    use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg};
    use std::io::{BufRead, BufReader, Write};

    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let fd = tty.as_fd();

    // Disable echo (and ensure canonical line input) for the prompt, restoring
    // the prior terminal state afterward.
    let original = tcgetattr(fd).ok()?;
    let mut quiet = original.clone();
    quiet.local_flags.remove(LocalFlags::ECHO);
    quiet.local_flags.insert(LocalFlags::ICANON);
    let _ = tcsetattr(fd, SetArg::TCSANOW, &quiet);

    let _ = write!(&tty, "{prompt}");
    let _ = (&tty).flush();

    let mut line = String::new();
    let read = BufReader::new(&tty).read_line(&mut line);

    let _ = tcsetattr(fd, SetArg::TCSANOW, &original);
    let _ = writeln!(&tty);

    match read {
        Ok(0) | Err(_) => None,
        Ok(_) => {
            let secret = line.trim_end_matches(['\r', '\n']).to_owned();
            (!secret.is_empty()).then_some(secret)
        }
    }
}
