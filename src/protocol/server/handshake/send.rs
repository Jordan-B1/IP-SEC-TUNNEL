use std::net::TcpStream;

use rand::{rngs::ThreadRng, Rng};

use crate::{
    cypher::enigma,
    keys_generator::keys::PublicKey,
    protocol::{
        server::errors::TunnelResult,
        shared::{
            constant::SERVER_MASTER_KEY_SIZE,
            types::{HelloServerRequest, SharingCryptedPubKeyRequest},
        },
    },
};

pub fn send_hello(stream: &mut TcpStream) -> TunnelResult<[u8; SERVER_MASTER_KEY_SIZE]> {
    let mut rng: ThreadRng = rand::thread_rng();
    let mut data: [u8; SERVER_MASTER_KEY_SIZE] = [0; SERVER_MASTER_KEY_SIZE];
    data.copy_from_slice(
        (0..SERVER_MASTER_KEY_SIZE)
            .map(|_| rng.gen_range(0..255))
            .collect::<Vec<u8>>()
            .as_slice(),
    );
    let buffer: HelloServerRequest = HelloServerRequest::new(data);
    serde_json::to_writer(stream, &buffer).expect("Failed to send data to client...");
    Ok(data)
}

pub fn send_crypted_public_key(
    stream: &mut TcpStream,
    pub_key: &PublicKey,
    other_pub_key: &PublicKey,
) -> TunnelResult<()> {
    let data: Vec<u8> = serde_json::to_vec(pub_key).unwrap();
    let data: Vec<usize> = enigma(
        &data.iter().map(|&x| x as usize).collect::<Vec<usize>>(),
        other_pub_key.encryption_value(),
        other_pub_key.modulus(),
    );
    let buffer: SharingCryptedPubKeyRequest = SharingCryptedPubKeyRequest::new(data);
    serde_json::to_writer(stream, &buffer).expect("Failed to send data to client...");
    Ok(())
}
