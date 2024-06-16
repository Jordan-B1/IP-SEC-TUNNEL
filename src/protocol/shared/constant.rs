pub const MAX_PACKET_SIZE: usize = 1024;

pub const MAX_CONNECTION_ATTEMPS: u8 = 3;

pub const CLIENT_MASTER_KEY_SIZE: usize = 12;

pub const SERVER_MASTER_KEY_SIZE: usize = 12;

pub const MASTER_KEY_SIZE: usize = CLIENT_MASTER_KEY_SIZE + SERVER_MASTER_KEY_SIZE;

pub const OK_BYTES: &[u8] = "OK".as_bytes();
pub const KO_BYTES: &[u8] = "KO".as_bytes();
