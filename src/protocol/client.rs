use crate::cypher::enigma;
use crate::keys_generator::keys::{generate_keys, PrivateKey, PublicKey};
use crate::protocol::shared::constant::{
    CLIENT_MASTER_KEY_SIZE, KO_BYTES, MASTER_KEY_SIZE, MAX_PACKET_SIZE, OK_BYTES,
};
use rand::rngs::ThreadRng;
use rand::Rng;
use serde::Deserialize;
use std::io::{self, Error, Read, Write};
use std::net::TcpStream;

use super::shared::constant::SERVER_MASTER_KEY_SIZE;
use super::shared::types::{
    HandshakeValidatedRequest, HelloClientRequest, HelloServerRequest, KeysValidatedRequest,
    SharingCryptedPubKeyRequest, SharingPubKeyRequest,
};

fn send_hello(stream: &mut TcpStream) -> std::io::Result<[u8; CLIENT_MASTER_KEY_SIZE]> {
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

fn send_public_key(stream: &mut TcpStream, pub_key: &PublicKey) -> std::io::Result<()> {
    let buffer: SharingPubKeyRequest = SharingPubKeyRequest::new(pub_key.clone());

    serde_json::to_writer(stream, &buffer).expect("Failed to send data to server...");
    Ok(())
}

fn send_cyphered_master_password(
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

fn read_server_hello(stream: &mut TcpStream) -> std::io::Result<[u8; SERVER_MASTER_KEY_SIZE]> {
    let mut de = serde_json::Deserializer::from_reader(stream);
    let buffer: HelloServerRequest =
        HelloServerRequest::deserialize(&mut de).expect("Invalid data received from server...");

    Ok(buffer.key())
}

fn read_server_cyphered_pub_key(stream: &mut TcpStream) -> std::io::Result<Vec<usize>> {
    let mut de = serde_json::Deserializer::from_reader(stream);
    let buffer: SharingCryptedPubKeyRequest = SharingCryptedPubKeyRequest::deserialize(&mut de)
        .expect("Invalid data received from server...");

    Ok(buffer.crypted_pub_key())
}

fn handshake_succeed(stream: &mut TcpStream) -> std::io::Result<bool> {
    let mut de = serde_json::Deserializer::from_reader(stream);
    let buffer: HandshakeValidatedRequest = HandshakeValidatedRequest::deserialize(&mut de)
        .expect("Invalid data received from server...");

    match &buffer.status()[0..2] {
        OK_BYTES => Ok(true),
        KO_BYTES => Ok(false),
        _ => Err(Error::other("Unexpected value!")),
    }
}

fn send_input(stream: &mut TcpStream, pub_key: &PublicKey) {
    let mut input_buffer: String = String::new();
    let stdin: io::Stdin = io::stdin();
    let enigma_buffer: Vec<usize>;

    print!("> ");
    std::io::stdout().flush();
    stdin
        .read_line(&mut input_buffer)
        .expect("Error while reading standard input...");
    enigma_buffer = enigma(
        &input_buffer
            .as_bytes()
            .iter()
            .map(|x| usize::from(*x))
            .collect(),
        pub_key.encryption_value(),
        pub_key.modulus(),
    );
    input_buffer = serde_json::to_string(&enigma_buffer).unwrap();
    stream
        .write(input_buffer.as_bytes())
        .expect("Failed sending data to client...");
}

fn read_stream(stream: &mut TcpStream, private_key: &PrivateKey) {
    let mut buffer: [u8; MAX_PACKET_SIZE] = [0; MAX_PACKET_SIZE];
    let json_data: &str;
    let cyphered_message: Vec<usize>;
    let plain_message: Vec<usize>;
    let data_size: usize;

    data_size = stream
        .read(&mut buffer)
        .expect("Failed to read from client...");
    json_data = std::str::from_utf8(&buffer[0..data_size]).unwrap();
    cyphered_message = serde_json::from_str(json_data).unwrap();
    plain_message = enigma(
        &cyphered_message,
        private_key.decryption_value(),
        private_key.modulus(),
    );
    print!(
        "Peer: {}",
        std::str::from_utf8(&plain_message.iter().map(|x| *x as u8).collect::<Vec<u8>>()).unwrap()
    );
}

fn handshake(stream: &mut TcpStream) -> std::io::Result<((PublicKey, PrivateKey), PublicKey)> {
    let keys: (PublicKey, PrivateKey) = generate_keys();
    let client_hello: [u8; CLIENT_MASTER_KEY_SIZE] = send_hello(stream).unwrap();
    let server_hello: [u8; SERVER_MASTER_KEY_SIZE] = read_server_hello(stream)?;
    send_public_key(stream, &keys.0)?;
    let cyphered_server_key: Vec<usize> = read_server_cyphered_pub_key(stream)?;
    let server_key: Vec<usize> = enigma(
        &cyphered_server_key,
        keys.1.decryption_value(),
        keys.1.modulus(),
    );
    let server_key: Vec<u8> = server_key.iter().map(|&x| x as u8).collect();
    let server_key: PublicKey = serde_json::from_slice(&server_key).unwrap();
    let master_password: [u8; MASTER_KEY_SIZE] = [client_hello, server_hello].concat()
        [0..MASTER_KEY_SIZE]
        .try_into()
        .unwrap();
    send_cyphered_master_password(stream, &server_key, &master_password)?;

    match handshake_succeed(stream) {
        Ok(true) => Ok((keys, server_key)),
        Ok(false) => Err(Error::other("Handshake went wrong :(")),
        Err(x) => Err(x),
    }
}

pub fn start_client(ip: String, port: u16) -> std::io::Result<()> {
    let endpoint: String = format!("{}:{}", ip, port);
    let mut stream: TcpStream =
        TcpStream::connect(endpoint.clone()).expect("Failed to connect to server...");

    println!("Client started and connected to {}!", endpoint);
    let keys: ((PublicKey, PrivateKey), PublicKey) = handshake(&mut stream).unwrap();
    println!("handshake completed! keys {:?}", keys);
    loop {
        send_input(&mut stream, &keys.1);
        read_stream(&mut stream, &keys.0 .1);
    }
    Ok(())
}
