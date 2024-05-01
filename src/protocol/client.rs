use crate::cypher::enigma;
use crate::keys_generator::keys::PublicKey;
use crate::protocol::shared::constant::MAX_PACKET_SIZE;
use rand::rngs::ThreadRng;
use rand::Rng;
use serde::Serialize;
use serde_bytes;
use std::io::{self, Read, Write};
use std::net::TcpStream;

use super::shared::types::{Packet, PacketData, PacketType};

fn send_hello(stream: &mut TcpStream) -> std::io::Result<Packet> {
    let mut rng = rand::thread_rng();
    let mut data: PacketData = [0; MAX_PACKET_SIZE];
    data.copy_from_slice(
        (0..12)
            .map(|_| rng.gen_range(0..255))
            .collect::<Vec<u8>>()
            .as_slice(),
    );
    let buffer = Packet::new(PacketType::HELLOCLIENT, data);
    serde_cbor::to_writer(stream, &buffer).expect("Failed to send data to server...");
    Ok(buffer)
}

fn send_public_key(stream: &mut TcpStream, pub_key: &PublicKey) -> std::io::Result<Packet> {
    let data_vec =
        serde_cbor::to_vec(&pub_key.encryption_value()).expect("Error while  formatting data...");
    let mut data: PacketData = [0; MAX_PACKET_SIZE];
    data.copy_from_slice(&data_vec);
    let buffer = Packet::new(PacketType::SHARINGPUBKEY, data);
    serde_cbor::to_writer(stream, &buffer).expect("Failed to send data to server...");
    Ok(buffer)
}

fn send_cyphered_ok(stream: &mut TcpStream, public_key: &PublicKey) -> std::io::Result<Packet> {
    let mut data: PacketData = [0; MAX_PACKET_SIZE];
    data.copy_from_slice(String::from("OK").as_bytes());

    let buffer = Packet::new(PacketType::KEYSVALIDATED, data);
    let cyphered_buffer = serde_cbor::to_vec(&buffer).expect("Error while formatting data...");
    let cyphered_buffer = enigma(
        &cyphered_buffer,
        public_key.encryption_value(),
        public_key.key_len(),
    );
    serde_cbor::to_writer(stream, &cyphered_buffer).expect("Failed to send data to server...");
    Ok(buffer)
}

fn handshake(stream: &mut TcpStream) {}

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
