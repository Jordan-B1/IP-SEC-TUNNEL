/// Errors that can occur during the tunneling process.
///
/// This enum is used to represent the different errors that can occur during the tunneling process.
///
/// # Variants
/// - **InvalidData** - The data received is invalid
/// - **UnexpectedValue** - The value received is unexpected
/// - **HandshakeWentWrong** - The handshake went wrong
#[derive(Debug)]
pub enum TunnelError {
    InvalidData,
    UnexpectedValue,
    HandshakeWentWrong,

    ServerDisconnected,
}

/// Result type for the tunneling process.
///
/// This type is used to represent the result of the tunneling process.
pub type TunnelResult<T> = std::result::Result<T, TunnelError>;
