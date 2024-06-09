use std::{io::Error, net::TcpStream};

use serde::Deserialize;

use crate::{
    keys_generator::keys::PublicKey,
    protocol::shared::{
        constant::{CLIENT_MASTER_KEY_SIZE, MASTER_KEY_SIZE},
        types::{HelloClientRequest, KeysValidatedRequest, SharingPubKeyRequest},
    },
};

pub fn read_client_hello(stream: &mut TcpStream) -> std::io::Result<[u8; CLIENT_MASTER_KEY_SIZE]> {
    let mut de = serde_json::Deserializer::from_reader(stream);
    let buffer: HelloClientRequest =
        HelloClientRequest::deserialize(&mut de).expect("Invalid data received from client...");

    Ok(buffer.key())
}

pub fn read_client_public_key(stream: &mut TcpStream) -> std::io::Result<PublicKey> {
    let mut de = serde_json::Deserializer::from_reader(stream);
    let buffer: SharingPubKeyRequest =
        SharingPubKeyRequest::deserialize(&mut de).expect("Invalid data received from client...");

    Ok(buffer.pub_key())
}

pub fn read_cyphered_password(stream: &mut TcpStream) -> std::io::Result<Vec<usize>> {
    let mut de = serde_json::Deserializer::from_reader(stream);
    let buffer: KeysValidatedRequest =
        KeysValidatedRequest::deserialize(&mut de).expect("Invalid data received from client...");
    let key = buffer.key();
    if key.len() != MASTER_KEY_SIZE {
        return Err(Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid key size",
        ));
    }
    Ok(buffer.key())
}
