# capsudo-rs

`sudo`, but [object-capability style][ocap] — a Rust reimplementation of
[capsudo](https://github.com/kaniini/capsudo) built so the capability channel
can be **proxied across [Edera Protect][edera] zones over IDM**, not just a
local Unix socket.

   [ocap]: https://en.wikipedia.org/wiki/Object-capability_model
   [edera]: https://edera.dev

## The idea

Privilege is not granted by a setuid bit. A privileged daemon (`capsudod`) is
started ahead of time, already holding the privilege you want to delegate, and
bound to a *transport endpoint*. Whoever can reach that endpoint can invoke the
capability. The endpoint **is** the capability.

In the original, the endpoint is always an `AF_UNIX` socket whose file
permissions decide who may connect. Here the transport is abstracted: the same
protocol and the same client/daemon logic run unchanged over a local Unix
socket *or* a cross-zone IDM channel, so a capability held in one Edera zone can
be exposed to another without either side knowing the difference.

## Why a rewrite was needed for cross-zone

Two things in the original assume a shared kernel:

1. **Descriptor passing.** The caller's stdin/stdout/stderr are handed to the
   daemon over `SCM_RIGHTS`. File descriptors are meaningless across a zone
   boundary. Here the transport layer papers over that — real `SCM_RIGHTS`
   locally, **simulated** descriptor passing (stream multiplexing + local pipe
   ends) cross-zone — transparently, so client and daemon never learn which
   happened.

2. **The interactive pty.** The original allocates the pty on the *client* and
   ships the slave. A pty slave is a real terminal; a socket pair (all a
   cross-zone link can fabricate) is not. So the pty is allocated on the
   **daemon** side instead: the child always gets a genuine controlling
   terminal in its own zone, and only a byte stream plus window-size updates
   cross the channel. (The C version was updated to match.)

## Workspace layout

| Crate | Role |
|-------|------|
| `capsudo-proto` | Transport-agnostic wire protocol: message types, portable fixed-endianness framing. No I/O. |
| `capsudo-transport` | `Transport`/`Listener` traits + implementations: `unix` (real `SCM_RIGHTS`), `mux` (simulated fd-passing over any byte channel), `fakeidm` (throwaway TCP cross-zone stub, feature `fakeidm`). |
| `capsudo-core` | Client and daemon session logic, written entirely against the traits. |
| `capsudo` | Client binary. |
| `capsudod` | Daemon binary (listening, or one-shot on stdin). |
| `capsudod-pwauth` | Authenticating front-end: shadow-password check, then chain to `capsudod`. |

## Build & test

```
cargo build
cargo test
cargo build --features capsudo-transport/fakeidm    # include the fake IDM stub
```

## Command-line

```
# Delegate "run anything" to whoever can reach the socket:
capsudod -S /run/capsudo/sudo -o root:wheel -m 0770 &
capsudo  -S /run/capsudo/sudo -- id

# Pin an exact command (client args ignored):
capsudod -S /run/capsudo/reboot -f /sbin/reboot &
capsudo  -S /run/capsudo/reboot

# Require a password first, then chain to capsudod:
capsudod-pwauth -S /run/capsudo/auth -o root:wheel -m 0770 -- capsudod &
capsudo -S /run/capsudo/auth -- id
```

See `CLAUDE.md` for the architecture in depth.
