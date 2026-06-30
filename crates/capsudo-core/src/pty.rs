//! Daemon-side pseudo-terminal handling for interactive sessions.
//!
//! Unlike the original C capsudo — where the *client* allocates the pty and
//! ships the slave over `SCM_RIGHTS` — the daemon allocates it here. A pty slave
//! is a real terminal with working job control, but a socket pair (all a
//! cross-zone transport can fabricate) is not, so a client-allocated pty cannot
//! survive a zone hop. Allocating it daemon-side means the child always gets a
//! genuine controlling terminal in its own zone, and the only thing that
//! crosses the channel is a raw byte stream plus window-size updates — which
//! work identically over a local socket or an IDM link.
//!
//! The daemon bridges the pty master to the descriptors the client delegated
//! (its real terminal locally; socket-pair ends standing in for it cross-zone).

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::process::Stdio;
use std::thread::JoinHandle;

use capsudo_proto::FieldType;
use capsudo_transport::Transport;
use nix::pty::openpty;
use tokio::process::Command;

use crate::error::{CoreError, Result};
use crate::exit::{exit_code, send_exit};

const BRIDGE_BUF: usize = 8192;

fn to_winsize(dims: [u16; 4]) -> libc::winsize {
    libc::winsize {
        ws_row: dims[0],
        ws_col: dims[1],
        ws_xpixel: dims[2],
        ws_ypixel: dims[3],
    }
}

/// Runs an interactive session: allocate a pty, give the child a real
/// controlling terminal, bridge the master to the client's descriptors, and
/// apply window-size updates until the child exits.
pub(crate) async fn run_interactive(
    transport: &mut dyn Transport,
    argv: Vec<String>,
    envp: Vec<String>,
    client_fds: [OwnedFd; 3],
    winsize: [u16; 4],
) -> Result<()> {
    let ws = to_winsize(winsize);
    let pty = openpty(Some(&ws), None).map_err(io::Error::from)?;
    let master = pty.master;
    let slave = pty.slave;

    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    command.env_clear();
    for entry in &envp {
        if let Some((key, value)) = entry.split_once('=') {
            command.env(key, value);
        }
    }

    // The child's stdio is the pty slave; it becomes a session leader with the
    // slave as its controlling terminal.
    command.stdin(Stdio::from(slave.try_clone().map_err(CoreError::Io)?));
    command.stdout(Stdio::from(slave.try_clone().map_err(CoreError::Io)?));
    command.stderr(Stdio::from(slave));
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            let _ = crate::exit::send_error(transport, &format!("unable to run {}: {e}", argv[0]))
                .await;
            return send_exit(transport, 127).await;
        }
    };

    // Release the parent's copies of the slave (still held inside `command`'s
    // Stdio), so the master reports EOF once the child closes the slave on exit.
    drop(command);

    // Bridge the master to the client's terminal: fd[0] is read (its input),
    // fd[1] is written (its output). fd[2] (stderr) folds into the tty.
    let [client_in, client_out, _client_err] = client_fds;
    let bridge = Bridge::start(
        master.try_clone().map_err(CoreError::Io)?,
        client_in,
        client_out,
    )?;

    // Whichever finishes first wins: the child exiting, or the client hanging
    // up (its winsize stream ending). The losing future is dropped, releasing
    // its borrow of `transport` so we can send the exit status.
    let status = tokio::select! {
        status = child.wait() => status.map_err(CoreError::Io)?,
        _ = winsize_loop(transport, master.as_raw_fd()) => {
            // Client hung up; tear down the child rather than linger.
            let _ = child.start_kill();
            child.wait().await.map_err(CoreError::Io)?
        }
    };

    bridge.stop();
    drop(master);
    send_exit(transport, exit_code(status)).await
}

/// Reads control messages, applying each window-size update to the pty, until
/// the client disconnects.
async fn winsize_loop(transport: &mut dyn Transport, master_fd: RawFd) {
    loop {
        match transport.recv().await {
            Ok(Some(received)) => {
                if received.message.field_type() == FieldType::Winsize {
                    if let Ok(dims) = received.message.as_winsize() {
                        let ws = to_winsize(dims);
                        unsafe {
                            libc::ioctl(master_fd, libc::TIOCSWINSZ as _, &ws);
                        }
                    }
                }
            }
            Ok(None) | Err(_) => return,
        }
    }
}

/// Two threads relaying bytes between the pty master and the client's terminal
/// descriptors. The client→master thread is cancellable (the client's input may
/// never reach EOF); the master→client thread runs until the master reports EOF
/// so the child's final output is never truncated.
struct Bridge {
    cancel_w: OwnedFd,
    threads: Vec<JoinHandle<()>>,
}

impl Bridge {
    fn start(master: OwnedFd, client_in: OwnedFd, client_out: OwnedFd) -> Result<Bridge> {
        let (cancel_r, cancel_w) = nix::unistd::pipe().map_err(io::Error::from)?;
        let master_for_write = master.try_clone().map_err(CoreError::Io)?;

        // client input -> master (cancellable)
        let t_in = std::thread::spawn(move || {
            relay(client_in.as_raw_fd(), master_for_write.as_raw_fd(), Some(cancel_r.as_raw_fd()));
            // keep fds owned until the thread ends
            drop((client_in, master_for_write, cancel_r));
        });

        // master -> client output (runs to natural EOF)
        let t_out = std::thread::spawn(move || {
            relay(master.as_raw_fd(), client_out.as_raw_fd(), None);
            drop((master, client_out));
        });

        Ok(Bridge {
            cancel_w,
            threads: vec![t_in, t_out],
        })
    }

    fn stop(self) {
        // Wake the cancellable thread; the other ends on master EOF.
        let _ = nix::unistd::write(&self.cancel_w, &[1]);
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}

/// Copies `src` to `dst` until `src` reaches EOF/error, or (if `cancel` is set)
/// the cancel descriptor becomes readable.
fn relay(src: RawFd, dst: RawFd, cancel: Option<RawFd>) {
    let mut buf = [0u8; BRIDGE_BUF];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: src,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: cancel.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let nfds = if cancel.is_some() { 2 } else { 1 };

        let ready = unsafe { libc::poll(fds.as_mut_ptr(), nfds, -1) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }

        if cancel.is_some() && fds[1].revents != 0 {
            return;
        }
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
            continue;
        }

        let n = unsafe { libc::read(src, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            return; // EOF, or EIO once the pty's other side has closed
        }
        if write_all(dst, &buf[..n as usize]).is_err() {
            return;
        }
    }
}

fn write_all(fd: RawFd, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let n = unsafe { libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        bytes = &bytes[n as usize..];
    }
    Ok(())
}
