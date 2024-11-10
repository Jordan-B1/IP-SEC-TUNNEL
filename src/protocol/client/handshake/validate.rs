use std::net::TcpStream;

use serde::Deserialize;

use crate::{
    cypher::enigma,
    keys_generator::keys::{generate_keys, PrivateKey, PublicKey},
    protocol::{
        client::errors::TunnelResult,
        shared::{
            constant::{
                CLIENT_MASTER_KEY_SIZE, KO_BYTES, MASTER_KEY_SIZE, OK_BYTES, SERVER_MASTER_KEY_SIZE,
            },
            types::HandshakeValidatedRequest,
        },
    },
};

use super::{
    receive::{read_server_cyphered_pub_key, read_server_hello},
    send::{send_cyphered_master_password, send_hello, send_public_key},
};

/// Check if the handshake succeed
///
/// This function will read the stream from the server and check if the handshake succeed at the end of the protocol
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the server
///
/// # Returns
/// **TunnelResult<bool>** - True if the handshake succeed, false otherwise or an error if the value received is unexpected
fn handshake_succeed(stream: &mut TcpStream) -> TunnelResult<bool> {
    let mut de = serde_json::Deserializer::from_reader(stream);
    let buffer: HandshakeValidatedRequest = HandshakeValidatedRequest::deserialize(&mut de)
        .expect("Invalid data received from server...");

    match &buffer.status()[0..2] {
        OK_BYTES => Ok(true),
        KO_BYTES => Ok(false),
        _ => Err(crate::protocol::client::errors::TunnelError::UnexpectedValue),
    }
}

/// Handshake with the server
///
/// This function will perform the handshake protocol with the server
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the server
///
/// # Returns
/// **TunnelResult<((PublicKey, PrivateKey), PublicKey)>** - The keys used during the handshake if the handshake succeed or an error if it failed
pub fn handshake(stream: &mut TcpStream) -> TunnelResult<((PublicKey, PrivateKey), PublicKey)> {
    let keys: (PublicKey, PrivateKey) = generate_keys();
    let client_hello: [u8; CLIENT_MASTER_KEY_SIZE] = send_hello(stream)?;
    let server_hello: [u8; SERVER_MASTER_KEY_SIZE] = read_server_hello(stream)?;
    send_public_key(stream, &keys.0);
    let cyphered_server_key: Vec<u8> = read_server_cyphered_pub_key(stream)?;
    let server_key: Vec<u8> = enigma(
        &cyphered_server_key,
        &keys.1.decryption_value(),
        &keys.1.modulus(),
    );
    let server_key: PublicKey = serde_json::from_slice(&server_key).unwrap();
    let master_password: [u8; MASTER_KEY_SIZE] = [client_hello, server_hello].concat()
        [0..MASTER_KEY_SIZE]
        .try_into()
        .unwrap();
    send_cyphered_master_password(stream, &server_key, &master_password);
    match handshake_succeed(stream) {
        Ok(true) => Ok((keys, server_key)),
        Ok(false) => Err(crate::protocol::client::errors::TunnelError::HandshakeWentWrong),
        Err(x) => Err(x),
    }
}
