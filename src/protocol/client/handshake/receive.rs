use std::net::TcpStream;

use serde::Deserialize;

use crate::protocol::{
    client::errors::{TunnelError, TunnelResult},
    shared::{
        constant::SERVER_MASTER_KEY_SIZE,
        types::{HelloServerRequest, SharingCryptedPubKeyRequest},
    },
};

/// Read the hello message from the server
///
/// This function will read the hello message from the server
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the server
///
/// # Returns
/// **TunnelResult<[u8; SERVER_MASTER_KEY_SIZE]>** - The random bytes received from the server
pub fn read_server_hello(stream: &mut TcpStream) -> TunnelResult<[u8; SERVER_MASTER_KEY_SIZE]> {
    let mut de = serde_json::Deserializer::from_reader(stream);

    match HelloServerRequest::deserialize(&mut de) {
        Ok(buffer) => Ok(buffer.key()),
        Err(_) => Err(TunnelError::InvalidData),
    }
}

/// Read the public key from the server
///
/// This function will read the public key from the server
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the server
///
/// # Returns
/// **TunnelResult<Vec<u8>>** - The cyphered public key received from the server
pub fn read_server_cyphered_pub_key(stream: &mut TcpStream) -> TunnelResult<Vec<u8>> {
    let mut de = serde_json::Deserializer::from_reader(stream);

    match SharingCryptedPubKeyRequest::deserialize(&mut de) {
        Ok(buffer) => Ok(buffer.crypted_pub_key()),
        Err(_) => Err(TunnelError::InvalidData),
    }
}
