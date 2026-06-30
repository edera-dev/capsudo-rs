use capsudo_proto::ProtoError;

/// Errors produced by a [`Transport`](crate::Transport) or
/// [`Listener`](crate::Listener).
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// An underlying I/O failure.
    #[error("transport i/o: {0}")]
    Io(#[from] std::io::Error),

    /// A peer sent bytes that did not decode as a valid protocol frame.
    #[error("protocol: {0}")]
    Proto(#[from] ProtoError),

    /// A message frame ended mid-payload (peer closed or truncated the stream).
    #[error("unexpected end of stream while reading a message")]
    UnexpectedEof,

    /// A transport-specific failure with a human-readable description.
    #[error("{0}")]
    Other(String),
}

/// Convenience result alias for transport operations.
pub type Result<T> = std::result::Result<T, TransportError>;
