# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & test

```
cargo build
cargo test
cargo clippy --all-targets
cargo build --features capsudo-transport/fakeidm   # build the fake IDM stub
```

- Async throughout, on tokio. Edition 2021, license `0BSD`.
- The fake IDM transport lives behind the `fakeidm` feature of
  `capsudo-transport`. Tests for it are in `capsudo-core` (its dev-dependency
  enables the feature), so a plain `cargo test` already covers the cross-zone
  path — no `--features` needed.
- Linux-only: relies on `SCM_RIGHTS`, `SO_PEERCRED`/`SO_PEERSEC`, ptys, and
  `/proc/self/attr/exec`.

## What this is

A Rust reimplementation of capsudo (object-capability `sudo`) whose defining goal
is that the capability channel can be **proxied across Edera Protect zones over
IDM**, not just a local Unix socket. Privilege comes from reaching a transport
endpoint, not from setuid. The whole design exists to make the client and daemon
*transport-agnostic*.

## Architecture

The crates form a strict dependency stack; lower layers know nothing of higher.

### `capsudo-proto` — the wire protocol (no I/O)

`Message` = a `FieldType` tag + payload. Framing is a fixed 5-byte header (`u8`
type + `u32` little-endian length) then payload — **explicitly little-endian and
fixed-width** so a frame survives a zone hop unchanged (the C original writes raw
native structs and silently assumes a shared ABI; this does not). `Fd` messages
carry only a *count*; the descriptors themselves are handled out-of-band by the
transport.

### `capsudo-transport` — the seam that makes cross-zone work

`Transport` is a message channel that can also convey descriptors out-of-band:

```rust
async fn send(&mut self, msg: &Message, fds: &[FdSpec<'_>]) -> Result<()>;
async fn recv(&mut self) -> Result<Option<Received>>;   // Received carries OwnedFds
```

The crucial idea: **`send`/`recv` expose descriptor passing uniformly, and the
transport decides how to realize it.** Client and daemon are written against the
trait alone and never change between local and cross-zone.

- `unix::UnixTransport` — real `SCM_RIGHTS`. Also supplies `peer_cred`
  (`SO_PEERCRED`, used by pwauth) and `peer_secontext` (`SO_PEERSEC`, used for
  SELinux propagation).
- `mux::MuxTransport` — wraps **any** `AsyncRead + AsyncWrite` byte channel and
  *simulates* descriptor passing. When you "send an fd", it opens a logical
  stream and pumps the fd's bytes inside the channel; the receiver fabricates a
  socket pair, hands one end out as if it arrived over `SCM_RIGHTS`, and bridges
  the other end to the stream. Neither peer can tell.
- `fakeidm` (feature-gated) — a throwaway stand-in for an Edera IDM channel
  built on `MuxTransport` over TCP, for exercising the cross-zone path on one
  host. The real integration lives in Protect's zone agent; swapping it in is
  just replacing the byte-channel constructor, since everything above is
  unchanged.

`FdSpec`/`FdDir` tag each delegated fd with a direction. The unix transport
ignores it; the mux transport needs it (it must not, e.g., *read* a write-only
stdout fd — on a tty that would steal the user's input). The receiver pumps the
mirror direction (`FdDir::invert`).

`ControlSender` is a detached, clonable handle for sending fd-less control
messages (window-size updates) concurrently with a parked `recv()`.

### `capsudo-core` — the actual capsudo behaviour

- `client` — sends the config handshake (optional secret, env, args, session
  type, winsize, the delegated stdio, `End`), then awaits the outcome.
  `run_session` surfaces an `Unauthorized` challenge so the binary can prompt and
  retry; `run_client` is the simple wrapper.
- `daemon` — `serve_connection` drains the handshake (applying the `-f`/`-E`
  attenuation), captures the peer SELinux context, then runs the program with the
  delegated stdio and relays the exit status.
- `pty` — interactive sessions allocate the pty **on the daemon side** (see
  README for why) and bridge the master to the client's delegated descriptors.

## Key cross-cutting mechanisms (read these files together)

- **Simulated fd-passing** spans `mux.rs` (driver/reader/writer tasks, per-stream
  pumps) and the `FdSpec`/`Received` contract in `traits.rs`. The mux `send` must
  queue the `Fds` frame *before* starting pumps, or stream data races ahead of
  the frame that tells the peer how to route it (this was a real bug; the
  ordering is load-bearing).
- **Daemon-side pty** spans `pty.rs` (pty alloc, child session-leader setup via
  `pre_exec`, the master↔client bridge threads) and `client.rs` + the `capsudo`
  binary (raw mode, `SIGWINCH` → `Winsize` over `ControlSender`). The bridge's
  `master→client` thread must run to master EOF (not be cancelled) so final
  output isn't truncated; the daemon must drop the `Command` after spawn so its
  retained slave fds don't keep the master from ever reaching EOF.
- **Auth chaining**: `capsudod-pwauth` reads only the first (secret) message,
  then hands the live socket to `capsudod` (one-shot mode, `UnixTransport::from_fd`
  on stdin), which reads the rest — including the `SCM_RIGHTS` descriptors.

## Gotchas

- `MuxTransport` spawns tasks, so it must be constructed inside a tokio runtime.
- Sender-side mux pumps use blocking threads (caller fds may be regular files or
  ttys, which epoll can't watch); receiver-side pumps are async on the socket
  pairs the transport creates. This asymmetry is intentional — see `mux.rs`.
- SELinux/`SO_PEERSEC` and a successful pwauth login can only be exercised on an
  SELinux host / with root + a real password; the rest is covered by `cargo test`
  and the binaries' smoke paths.
