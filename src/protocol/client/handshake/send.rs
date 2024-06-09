use std::net::TcpStream;

use rand::{rngs::ThreadRng, Rng};

use crate::{
    cypher::enigma,
    keys_generator::keys::PublicKey,
    protocol::shared::{
        constant::{CLIENT_MASTER_KEY_SIZE, MASTER_KEY_SIZE},
        types::{HelloClientRequest, KeysValidatedRequest, SharingPubKeyRequest},
    },
};

pub fn send_hello(stream: &mut TcpStream) -> std::io::Result<[u8; CLIENT_MASTER_KEY_SIZE]> {
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

pub fn send_public_key(stream: &mut TcpStream, pub_key: &PublicKey) -> std::io::Result<()> {
    let buffer: SharingPubKeyRequest = SharingPubKeyRequest::new(pub_key.clone());

    serde_json::to_writer(stream, &buffer).expect("Failed to send data to server...");
    Ok(())
}

pub fn send_cyphered_master_password(
    stream: &mut TcpStream,
    public_key: &PublicKey,
    password: &[u8; MASTER_KEY_SIZE],
) -> std::io::Result<()> {
    let data: Vec<usize> = enigma(
        &password
            .iter()
            .map(|&x| usize::from(x))
            .collect::<Vec<usize>>(),
        public_key.encryption_value(),
        public_key.modulus(),
    );
    let buffer: KeysValidatedRequest = KeysValidatedRequest::new(data);
    serde_json::to_writer(stream, &buffer).expect("Failed to send data to server...");
    Ok(())
}
