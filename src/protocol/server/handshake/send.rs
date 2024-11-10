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

/// Send the hello message to the client
///
/// This function will send the hello message to the client
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the client
///
/// # Returns
/// **TunnelResult<[u8; SERVER_MASTER_KEY_SIZE]>** - The key sent to the client
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

/// Send the crypted public key to the client
///
/// This function will cypher the public key and send it to the client
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the client<br/>
/// pub_key: **&PublicKey** - The public key to cypher<br/>
/// other_pub_key: **&PublicKey** - The public key of the client
///
/// # Returns
/// **TunnelResult<()>** - An error if the data could not be sent
pub fn send_crypted_public_key(
    stream: &mut TcpStream,
    pub_key: &PublicKey,
    other_pub_key: &PublicKey,
) -> TunnelResult<()> {
    let data: Vec<u8> = serde_json::to_vec(pub_key).unwrap();
    let data: Vec<u8> = enigma(
        &data,
        &other_pub_key.encryption_value(),
        &other_pub_key.modulus(),
    );
    let buffer: SharingCryptedPubKeyRequest = SharingCryptedPubKeyRequest::new(data);
    serde_json::to_writer(stream, &buffer).expect("Failed to send data to client...");
    Ok(())
}
