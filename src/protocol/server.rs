use rand::rngs::ThreadRng;
use rand::Rng;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use crate::cypher::enigma;
use crate::keys_generator::keys::PublicKey;
use crate::protocol::shared::constant::MAX_PACKET_SIZE;
use crate::protocol::shared::types::PacketData;

use super::shared::types::{Packet, PacketType};

fn send_hello(stream: &mut TcpStream) -> std::io::Result<Packet> {
    let mut rng = rand::thread_rng();
    let mut data: PacketData = [0; MAX_PACKET_SIZE];
    data.copy_from_slice(
        (0..12)
            .map(|_| rng.gen_range(0..255))
            .collect::<Vec<u8>>()
            .as_slice(),
    );
    let buffer = Packet::new(PacketType::HELLOSERVER, data);
    serde_cbor::to_writer(stream, &buffer).expect("Failed to send data to client...");
    Ok(buffer)
}

fn send_crypted_public_key(
    stream: &mut TcpStream,
    pub_key: &PublicKey,
    other_pub_key: &PublicKey,
) -> std::io::Result<Packet> {
    let mut data: PacketData = [0; MAX_PACKET_SIZE];
    let b_pub_key: Vec<u8> = serde_cbor::to_vec(&pub_key).expect("Error while formatting data...");
    data.copy_from_slice(&b_pub_key);
    let crypted_key: Vec<u8> = enigma(
        &b_pub_key,
        other_pub_key.encryption_value(),
        other_pub_key.key_len(),
    );
    let buffer: Packet = Packet::new(PacketType::SHARINGCRYPTEDPUBKEY, data);
    serde_cbor::to_writer(stream, &crypted_key).expect("Failed to send data to client...");
    Ok(buffer)
}


fn handshake(stream: &mut TcpStream) {}

fn echo_server(stream: &mut TcpStream) {
    let mut buffer: PacketData = [0; MAX_PACKET_SIZE];
    let mut byte_read: usize;

    println!("New client connected!");
    loop {
        byte_read = stream
            .read(&mut buffer)
            .expect("Couldn't read from client...");
        if byte_read == 0 {
            break;
        }
        stream
            .write(&buffer)
            .expect("Couldn't send data to client...");
        buffer.fill(0);
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
