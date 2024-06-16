#[derive(Debug)]
pub enum TunnelError {
    InvalidData,
    UnexpectedValue,
    HandshakeWentWrong,
}

pub type TunnelResult<T> = std::result::Result<T, TunnelError>;
