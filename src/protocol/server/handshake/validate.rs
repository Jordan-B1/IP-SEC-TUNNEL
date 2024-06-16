use std::net::TcpStream;

use crate::{
    cypher::enigma,
    keys_generator::keys::{generate_keys, PrivateKey, PublicKey},
    protocol::{
        server::errors::TunnelResult,
        shared::{
            constant::{
                CLIENT_MASTER_KEY_SIZE, KO_BYTES, MASTER_KEY_SIZE, OK_BYTES, SERVER_MASTER_KEY_SIZE,
            },
            types::HandshakeValidatedRequest,
        },
    },
};

use super::{
    receive::{read_client_hello, read_client_public_key, read_cyphered_password},
    send::{send_crypted_public_key, send_hello},
};

fn validate_handshake(
    stream: &mut TcpStream,
    password_received: Vec<usize>,
    real_password: &[u8; MASTER_KEY_SIZE],
    private_key: &PrivateKey,
) -> TunnelResult<bool> {
    let plain_password: Vec<u8> = enigma(
        &password_received,
        private_key.decryption_value(),
        private_key.modulus(),
    )
    .iter()
    .map(|&x| x as u8)
    .collect();
    let mut data: [u8; 2] = [0; 2];
    if plain_password == Vec::from(real_password) {
        data.copy_from_slice(OK_BYTES);
    } else {
        data.copy_from_slice(KO_BYTES);
    }
    let buffer: HandshakeValidatedRequest = HandshakeValidatedRequest::new(data);
    serde_json::to_writer(stream, &buffer).expect("Failed to send data to client...");
    Ok(&data[0..2] == OK_BYTES)
}

pub fn handshake(stream: &mut TcpStream) -> TunnelResult<((PublicKey, PrivateKey), PublicKey)> {
    let keys: (PublicKey, PrivateKey) = generate_keys();
    let client_hello: [u8; CLIENT_MASTER_KEY_SIZE] = read_client_hello(stream)?;
    let server_hello: [u8; SERVER_MASTER_KEY_SIZE] = send_hello(stream)?;

    let master_password: [u8; MASTER_KEY_SIZE] = [client_hello, server_hello].concat()
        [0..MASTER_KEY_SIZE]
        .try_into()
        .unwrap();
    let client_public_key: PublicKey = read_client_public_key(stream)?;
    send_crypted_public_key(stream, &keys.0, &client_public_key)?;
    let received_master_password: Vec<usize> = read_cyphered_password(stream)?;
    let handshake_result: bool =
        validate_handshake(stream, received_master_password, &master_password, &keys.1)?;
    if handshake_result {
        return Ok((keys, client_public_key));
    } else {
        return Err(crate::protocol::server::errors::TunnelError::HANDSHAKEWENTWRONG);
    }
}
