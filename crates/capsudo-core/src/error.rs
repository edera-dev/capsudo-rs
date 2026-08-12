/// Errors arising from the client or daemon session logic.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// A failure in the underlying transport.
    #[error(transparent)]
    Transport(#[from] capsudo_transport::TransportError),

    /// A message payload could not be decoded.
    #[error(transparent)]
    Proto(#[from] capsudo_proto::ProtoError),

    /// A local I/O failure (e.g. spawning the target program).
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),

    /// The daemon hung up before reporting an exit status.
    #[error("daemon closed the connection before sending an exit status")]
    DaemonClosed,

    /// The client hung up before finishing the configuration handshake.
    #[error("client closed the connection before completing configuration")]
    ClientClosed,

    /// The peer sent something that violates the protocol contract.
    #[error("protocol violation: {0}")]
    Protocol(&'static str),

    /// The daemon refused to run the program, in its own words.
    #[error("{0}")]
    Refused(String),
}

/// Convenience result alias for core operations.
pub type Result<T> = std::result::Result<T, CoreError>;
