//! Constants used in the protocol

/// Maximum size of a packet
pub const MAX_PACKET_SIZE: usize = 1024;

/// Maximum number of connection attempts
pub const MAX_CONNECTION_ATTEMPS: u8 = 3;

/// Number of byte sent to the server to perform the hello_client during the handshake
pub const CLIENT_MASTER_KEY_SIZE: usize = 12;

/// Number of byte sent to the client to perform the hello_server during the handshake
pub const SERVER_MASTER_KEY_SIZE: usize = 12;

/// Size of the master key
pub const MASTER_KEY_SIZE: usize = CLIENT_MASTER_KEY_SIZE + SERVER_MASTER_KEY_SIZE;

/// Bytes sent by the server to indicate that the handshake succeed
pub const OK_BYTES: &[u8] = "OK".as_bytes();

/// Bytes sent by the server to indicate that the handshake failed
pub const KO_BYTES: &[u8] = "KO".as_bytes();
