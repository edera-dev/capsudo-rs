//! Client and daemon session logic for capsudo, generic over any
//! [`Transport`](capsudo_transport::Transport).
//!
//! This crate contains the actual capsudo behaviour — the configuration
//! handshake, attenuation policy, and program execution — with no knowledge of
//! whether it is talking over a local Unix socket or a cross-zone IDM channel.

mod client;
mod daemon;
mod error;
mod exit;
mod pty;

pub use client::{read_winsize, run_client, ClientRequest};
pub use daemon::{serve_connection, DaemonConfig};
pub use error::{CoreError, Result};
