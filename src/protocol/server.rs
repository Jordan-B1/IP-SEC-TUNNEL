use rand::rngs::ThreadRng;
use rand::Rng;
use serde::Deserialize;
use std::io::{self, Error, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use crate::cypher::enigma;
use crate::keys_generator::keys::{generate_keys, PrivateKey, PublicKey};
use crate::protocol::shared::constant::{MAX_PACKET_SIZE, SERVER_MASTER_KEY_SIZE};
use crate::protocol::shared::types::{
    HandshakeValidatedRequest, KeysValidatedRequest, PacketData, SharingCryptedPubKeyRequest,
};

use super::shared::constant::{CLIENT_MASTER_KEY_SIZE, KO_BYTES, MASTER_KEY_SIZE, OK_BYTES};
use super::shared::types::{HelloClientRequest, HelloServerRequest, SharingPubKeyRequest};

fn send_hello(stream: &mut TcpStream) -> std::io::Result<[u8; SERVER_MASTER_KEY_SIZE]> {
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

fn send_crypted_public_key(
    stream: &mut TcpStream,
    pub_key: &PublicKey,
    other_pub_key: &PublicKey,
) -> std::io::Result<()> {
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

fn validate_handshake(
    stream: &mut TcpStream,
    password_received: Vec<usize>,
    real_password: &[u8; MASTER_KEY_SIZE],
    private_key: &PrivateKey,
) -> std::io::Result<bool> {
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

fn read_client_hello(stream: &mut TcpStream) -> std::io::Result<[u8; CLIENT_MASTER_KEY_SIZE]> {
    let mut de = serde_json::Deserializer::from_reader(stream);
    let buffer: HelloClientRequest =
        HelloClientRequest::deserialize(&mut de).expect("Invalid data received from client...");

    Ok(buffer.key())
}

fn read_client_public_key(stream: &mut TcpStream) -> std::io::Result<PublicKey> {
    let mut de = serde_json::Deserializer::from_reader(stream);
    let buffer: SharingPubKeyRequest =
        SharingPubKeyRequest::deserialize(&mut de).expect("Invalid data received from client...");

    Ok(buffer.pub_key())
}

fn read_cyphered_password(stream: &mut TcpStream) -> std::io::Result<Vec<usize>> {
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

fn handshake(stream: &mut TcpStream) -> std::io::Result<((PublicKey, PrivateKey), PublicKey)> {
    let keys = generate_keys();
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
        return Err(Error::other("Handshake went wrong :("));
    }
}
fn echo_server(stream: &mut TcpStream) {
    let mut buffer: PacketData = [0; MAX_PACKET_SIZE];
    let mut byte_read: usize;
    let stdin: io::Stdin = io::stdin();
    let mut input_buffer: String = String::new();

    println!("New client connected!");
    let keys = handshake(stream).unwrap();
    println!("handshake completed! keys {:?}", keys);
    loop {
        byte_read = stream
            .read(&mut buffer)
            .expect("Couldn't read from client...");
        if byte_read == 0 {
            break;
        }
        println!("{}", std::str::from_utf8(&buffer).unwrap());
        stdin
            .read_line(&mut input_buffer)
            .expect("Error while reading standard input...");
        stream
            .write(input_buffer.as_bytes())
            .expect("Failed sending data to server...");
        buffer.fill(0);
        input_buffer.clear();
    }
    println!("Client disconnected!");
}

pub fn start_server(ip: String, port: u16) -> std::io::Result<()> {
    let endpoint: String = format!("{}:{}", ip, port);
    let listener: TcpListener = TcpListener::bind(endpoint)?;

    println!("Server launched on port {}!", port);
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                thread::spawn(move || echo_server(&mut stream));
            }
            Err(e) => println!("Couldn't get client: {e:?}"),
        }
    }
    Ok(())
}
