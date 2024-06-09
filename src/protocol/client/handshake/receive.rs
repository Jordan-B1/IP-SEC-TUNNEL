use std::net::TcpStream;

use serde::Deserialize;

use crate::protocol::shared::{
    constant::SERVER_MASTER_KEY_SIZE,
    types::{HelloServerRequest, SharingCryptedPubKeyRequest},
};

pub fn read_server_hello(stream: &mut TcpStream) -> std::io::Result<[u8; SERVER_MASTER_KEY_SIZE]> {
    let mut de = serde_json::Deserializer::from_reader(stream);
    let buffer: HelloServerRequest =
        HelloServerRequest::deserialize(&mut de).expect("Invalid data received from server...");

    Ok(buffer.key())
}

pub fn read_server_cyphered_pub_key(stream: &mut TcpStream) -> std::io::Result<Vec<usize>> {
    let mut de = serde_json::Deserializer::from_reader(stream);
    let buffer: SharingCryptedPubKeyRequest = SharingCryptedPubKeyRequest::deserialize(&mut de)
        .expect("Invalid data received from server...");

    Ok(buffer.crypted_pub_key())
}
