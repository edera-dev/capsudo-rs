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

In the original, the endpoint is always a `AF_UNIX` socket whose file
permissions decide who may connect. Here the transport is abstracted: the same
protocol and the same client/daemon logic run unchanged over a local Unix
socket *or* over a cross-zone IDM channel, so a capability held in one Edera
zone can be exposed to another without either side knowing the difference.

## Why a rewrite was needed for cross-zone

The original delegates the caller's terminal by passing stdin/stdout/stderr as
file descriptors over `SCM_RIGHTS`. File descriptors are meaningless across a
zone boundary. The transport layer here papers over that: on a local socket it
uses real `SCM_RIGHTS`, and on a non-local channel it **simulates** descriptor
passing by multiplexing the stream data and handing each side local pipe ends.
Client and daemon code never learn which happened.

## Workspace layout

| Crate | Role |
|-------|------|
| `capsudo-proto` | Transport-agnostic wire protocol: message types and portable, fixed-endianness framing. No I/O. |

(More crates land as the implementation grows; see `CLAUDE.md`.)

## Build

```
cargo build
cargo test
```
