//! Transport abstraction for capsudo.
//!
//! The capsudo protocol ([`capsudo_proto`]) is spoken over *some* channel. This
//! crate defines the [`Transport`] and [`Listener`] traits that abstract that
//! channel, plus concrete implementations. `capsudo` and `capsudod` are written
//! against the traits alone, so the same logic runs over:
//!
//! * [`unix`] — a local `AF_UNIX` socket, using real `SCM_RIGHTS` to delegate
//!   the caller's stdio descriptors; and
//! * (forthcoming) a cross-zone Edera Protect IDM channel, which *simulates*
//!   descriptor passing by multiplexing stream data — transparently, so neither
//!   client nor daemon needs to know.

mod error;
mod traits;
pub mod unix;

pub use error::{Result, TransportError};
pub use traits::{Listener, PeerCred, Received, Transport};
pub use unix::{UnixListener, UnixTransport};
