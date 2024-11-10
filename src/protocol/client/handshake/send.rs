use std::net::TcpStream;

use rand::{rngs::ThreadRng, Rng};

use crate::{
    cypher::enigma,
    keys_generator::keys::PublicKey,
    protocol::{
        client::errors::TunnelResult,
        shared::{
            constant::{CLIENT_MASTER_KEY_SIZE, MASTER_KEY_SIZE},
            types::{HelloClientRequest, KeysValidatedRequest, SharingPubKeyRequest},
        },
    },
};

/// Send the hello message to the server
///
/// This function will send the hello message to the server, first step of the handshake protocol
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the server
///
/// # Returns
/// **TunnelResult<[u8; CLIENT_MASTER_KEY_SIZE]>** - The random bytes sent to the server
pub fn send_hello(stream: &mut TcpStream) -> TunnelResult<[u8; CLIENT_MASTER_KEY_SIZE]> {
    let mut rng: ThreadRng = rand::thread_rng();
    let mut data: [u8; CLIENT_MASTER_KEY_SIZE] = [0; CLIENT_MASTER_KEY_SIZE];
    data.copy_from_slice(
        (0..CLIENT_MASTER_KEY_SIZE)
            .map(|_| rng.gen_range(0..255))
            .collect::<Vec<u8>>()
            .as_slice(),
    );
    let buffer: HelloClientRequest = HelloClientRequest::new(data);
    serde_json::to_writer(stream, &buffer).expect("Failed to send data to server...");
    Ok(data)
}

/// Send the public key to the server
///
/// This function will send the public key to the server
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the server<br/>
/// pub_key: **&PublicKey** - The public key to send
pub fn send_public_key(stream: &mut TcpStream, pub_key: &PublicKey) {
    let buffer: SharingPubKeyRequest = SharingPubKeyRequest::new((pub_key.encryption_value().to_bytes_be(), pub_key.modulus().to_bytes_be()));

    serde_json::to_writer(stream, &buffer).expect("Failed to send data to server...");
}

/// Send the master password cyphered to the server
///
/// This function will cypher the master password and send it to the server
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the server<br/>
/// public_key: **&PublicKey** - The public key used to cypher the message<br/>
/// password: **&[u8; MASTER_KEY_SIZE]** - The master password to cypher
pub fn send_cyphered_master_password(
    stream: &mut TcpStream,
    public_key: &PublicKey,
    password: &[u8; MASTER_KEY_SIZE],
) {
    let data: Vec<u8> = enigma(
        &password.to_vec(),
        &public_key.encryption_value(),
        &public_key.modulus(),
    );
    let buffer: KeysValidatedRequest = KeysValidatedRequest::new(data);
    serde_json::to_writer(stream, &buffer).expect("Failed to send data to server...");
}
