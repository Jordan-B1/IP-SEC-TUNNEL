use std::net::TcpStream;

use serde::Deserialize;

use crate::protocol::{
    client::errors::{TunnelError, TunnelResult},
    shared::{
        constant::SERVER_MASTER_KEY_SIZE,
        types::{HelloServerRequest, SharingCryptedPubKeyRequest},
    },
};

pub fn read_server_hello(stream: &mut TcpStream) -> TunnelResult<[u8; SERVER_MASTER_KEY_SIZE]> {
    let mut de = serde_json::Deserializer::from_reader(stream);

    match HelloServerRequest::deserialize(&mut de) {
        Ok(buffer) => Ok(buffer.key()),
        Err(_) => Err(TunnelError::InvalidData),
    }
}

pub fn read_server_cyphered_pub_key(stream: &mut TcpStream) -> TunnelResult<Vec<usize>> {
    let mut de = serde_json::Deserializer::from_reader(stream);

    match SharingCryptedPubKeyRequest::deserialize(&mut de) {
        Ok(buffer) => Ok(buffer.crypted_pub_key()),
        Err(_) => Err(TunnelError::InvalidData),
    }
}
