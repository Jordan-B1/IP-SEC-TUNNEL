#[derive(Debug)]
pub enum TunnelError {
    INVALIDPACKET,
    INVALIDKEYSIZE,
    HANDSHAKEWENTWRONG,
}

pub type TunnelResult<T> = std::result::Result<T, TunnelError>;
