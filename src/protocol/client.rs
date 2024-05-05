use crate::cypher::enigma;
use crate::keys_generator::keys::{generate_keys, PrivateKey, PublicKey};
use crate::protocol::shared::constant::{CLIENT_MASTER_KEY_SIZE, KO_BYTES, MASTER_KEY_SIZE, MAX_PACKET_SIZE, OK_BYTES};
use rand::rngs::ThreadRng;
use rand::Rng;
use std::io::{self, Error, Read, Write};
use std::net::TcpStream;

use super::shared::constant::SERVER_MASTER_KEY_SIZE;
use super::shared::types::{Packet, PacketData, PacketType};

fn send_hello(stream: &mut TcpStream) -> std::io::Result<Packet> {
    let mut rng: ThreadRng = rand::thread_rng();
    let mut data: PacketData = [0; MAX_PACKET_SIZE];
    data.copy_from_slice(
        (0..CLIENT_MASTER_KEY_SIZE)
            .map(|_| rng.gen_range(0..255))
            .collect::<Vec<u8>>()
            .as_slice(),
    );
    let buffer = Packet::new(PacketType::HELLOCLIENT, data);
    serde_cbor::to_writer(stream, &buffer).expect("Failed to send data to server...");
    Ok(buffer)
}

fn send_public_key(stream: &mut TcpStream, pub_key: &PublicKey) -> std::io::Result<Packet> {
    let data_vec: Vec<u8> =
        serde_cbor::to_vec(&pub_key.encryption_value()).expect("Error while  formatting data...");
    let mut data: PacketData = [0; MAX_PACKET_SIZE];
    data.copy_from_slice(&data_vec);
    let buffer: Packet = Packet::new(PacketType::SHARINGPUBKEY, data);
    serde_cbor::to_writer(stream, &buffer).expect("Failed to send data to server...");
    Ok(buffer)
}

fn send_cyphered_master_password(
    stream: &mut TcpStream,
    public_key: &PublicKey,
    password: &[u8; MASTER_KEY_SIZE],
) -> std::io::Result<Packet> {
    let mut data: PacketData = [0; MAX_PACKET_SIZE];
    data.copy_from_slice(password);

    let buffer: Packet = Packet::new(PacketType::KEYSVALIDATED, data);
    let cyphered_buffer: Vec<u8> =
        serde_cbor::to_vec(&buffer).expect("Error while formatting data...");
    let cyphered_buffer: Vec<u8> = enigma(
        &cyphered_buffer,
        public_key.encryption_value(),
        public_key.key_len(),
    );
    serde_cbor::to_writer(stream, &cyphered_buffer).expect("Failed to send data to server...");
    Ok(buffer)
}

fn read_server_hello(stream: &mut TcpStream) -> std::io::Result<[u8; SERVER_MASTER_KEY_SIZE]> {
    let buffer: Packet =
        serde_cbor::from_reader(stream).expect("Invalid data received from server...");
    if buffer.packet_type() != PacketType::HELLOSERVER {
        Err(Error::other("Wrong packet type"))
    } else {
        let mut val: [u8; SERVER_MASTER_KEY_SIZE] = [0; SERVER_MASTER_KEY_SIZE];
        val.copy_from_slice(&buffer.data());
        Ok(val)
    }
}

fn read_server_cyphered_pub_key(stream: &mut TcpStream) -> std::io::Result<Packet> {
    let buffer: Packet =
        serde_cbor::from_reader(stream).expect("Invalid data received from server...");
    if buffer.packet_type() != PacketType::SHARINGCRYPTEDPUBKEY {
        Err(Error::other("Wrong packet type"))
    } else {
        Ok(buffer)
    }
}

fn handshake_succeed(stream: &mut TcpStream) -> std::io::Result<bool>
{
    let buffer: Packet = serde_cbor::from_reader(stream).expect("Invalid data received from server...");
    if buffer.packet_type() != PacketType::HANDSHAKEVALIDATED {
       return  Err(Error::other("Wrong packet type"));
    }
    match &buffer.data()[0..2] {
        OK_BYTES => Ok(true),
        KO_BYTES => Ok(false),
        _ => Err(Error::other("Unexpected value!"))
    }
}

fn handshake(stream: &mut TcpStream) -> std::io::Result<((PublicKey, PrivateKey), PublicKey)> {
    let keys = generate_keys();
    let client_hello = send_hello(stream).unwrap().data();
    let mut client_hello_bytes: [u8; CLIENT_MASTER_KEY_SIZE] = [0; CLIENT_MASTER_KEY_SIZE]; 
    client_hello_bytes.copy_from_slice(&client_hello);
    let server_hello_bytes = read_server_hello(stream)?;
    send_public_key(stream, &keys.0)?;
    let cyphered_server_key: Vec<u8> = enigma(
        &read_server_cyphered_pub_key(stream)
            .unwrap()
            .data()
            .to_vec(),
        keys.1.decryption_value(),
        keys.1.key_len(),
    );
    let server_key: PublicKey = serde_cbor::from_slice(cyphered_server_key.as_slice())
        .expect("Invalid data, expected a public key!");
    let master_password: [u8; MASTER_KEY_SIZE] = [client_hello_bytes, server_hello_bytes].concat()[0..MASTER_KEY_SIZE].try_into().unwrap();
    send_cyphered_master_password(stream, &server_key, &master_password)?;
    match handshake_succeed(stream) {
        Ok(true) => Ok((keys, server_key)),
        Ok(false) => Err(Error::other("Handshake went wrong :(")),
        Err(x) => Err(x),
    }
}

pub fn start_client(ip: String, port: u16) -> std::io::Result<()> {
    let endpoint: String = format!("{}:{}", ip, port);
    let mut stream = TcpStream::connect(endpoint.clone()).expect("Failed to connect to server...");
    let mut byte_read: usize;
    let mut input_buffer: String = String::new();
    let mut stream_buffer: [u8; 1024] = [0; MAX_PACKET_SIZE];
    let stdin: io::Stdin = io::stdin();

    println!("Client started and connected to {}!", endpoint);
    loop {
        stdin
            .read_line(&mut input_buffer)
            .expect("Error while reading standard input...");
        stream
            .write(input_buffer.as_bytes())
            .expect("Failed sending data to server...");
        byte_read = stream
            .read(&mut stream_buffer)
            .expect("Failed while reading from server...");
        println!("{}", std::str::from_utf8(&stream_buffer).unwrap());
        if byte_read == 0 {
            break;
        }
        input_buffer.clear();
        stream_buffer.fill(0);
    }
    Ok(())
}
