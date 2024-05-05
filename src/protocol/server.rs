use rand::rngs::ThreadRng;
use rand::Rng;
use std::io::{Error, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use crate::cypher::enigma;
use crate::keys_generator::keys::{generate_keys, PrivateKey, PublicKey};
use crate::protocol::shared::constant::{MAX_PACKET_SIZE, SERVER_MASTER_KEY_SIZE};
use crate::protocol::shared::types::PacketData;

use super::shared::constant::{CLIENT_MASTER_KEY_SIZE, KO_BYTES, MASTER_KEY_SIZE, OK_BYTES};
use super::shared::types::{Packet, PacketType};

fn send_hello(stream: &mut TcpStream) -> std::io::Result<Packet> {
    let mut rng: ThreadRng = rand::thread_rng();
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
    let b_pub_key: Vec<u8> = serde_cbor::to_vec(&pub_key).expect("Error while formatting data...");
    let mut data: PacketData = [0; MAX_PACKET_SIZE];
    let crypted_key: Vec<u8> = enigma(
        &b_pub_key,
        other_pub_key.encryption_value(),
        other_pub_key.key_len(),
    );
    data.copy_from_slice(&crypted_key);
    let buffer: Packet = Packet::new(PacketType::SHARINGCRYPTEDPUBKEY, data);
    serde_cbor::to_writer(stream, &buffer).expect("Failed to send data to client...");
    Ok(buffer)
}

fn validate_handshake(
    stream: &mut TcpStream,
    password_received: &[u8; MASTER_KEY_SIZE],
    real_password: &[u8; MASTER_KEY_SIZE],
    private_key: &PrivateKey,
) -> std::io::Result<Packet> {
    let password_received = Vec::from(password_received);
    let plain_password: Vec<u8> = enigma(
        &Vec::from(password_received),
        private_key.decryption_value(),
        private_key.key_len(),
    );
    let mut data: PacketData = [0; MAX_PACKET_SIZE];
    let buffer: Packet;
    if plain_password == Vec::from(real_password) {
        data.copy_from_slice(OK_BYTES);
    } else {
        data.copy_from_slice(KO_BYTES);
    }
    buffer = Packet::new(PacketType::HANDSHAKEVALIDATED, data);
    serde_cbor::to_writer(stream, &buffer).expect("Failed to send data to client...");
    Ok(buffer)
}

fn read_client_hello(stream: &mut TcpStream) -> std::io::Result<[u8; CLIENT_MASTER_KEY_SIZE]> {
    let buffer: Packet =
        serde_cbor::from_reader(stream).expect("Invalid data received from client...");
    if buffer.packet_type() != PacketType::HELLOCLIENT {
        Err(Error::other("Wrong packet type"))
    } else {
        let mut val: [u8; CLIENT_MASTER_KEY_SIZE] = [0; CLIENT_MASTER_KEY_SIZE];
        val.copy_from_slice(&buffer.data());
        Ok(val)
    }
}

fn read_client_public_key(stream: &mut TcpStream) -> std::io::Result<PublicKey>
{
    let buffer: Packet = serde_cbor::from_reader(stream).expect("Invalid data received from client...");
    if buffer.packet_type() != PacketType::SHARINGPUBKEY {
        return Err(Error::other("Wrong packet type"));
    }
    let key: PublicKey = serde_cbor::from_slice(&buffer.data()).expect("Invalid data received from client...");
    Ok(key)
}

fn read_cyphered_password(stream: &mut TcpStream) -> std::io::Result<[u8; MASTER_KEY_SIZE]>
{
    let buffer: Packet = serde_cbor::from_reader(stream).expect("Invalid data received from client...");
    if buffer.packet_type() != PacketType::KEYSVALIDATED {
        return Err(Error::other("Wrong packet type"));
    }
    let password: [u8; MASTER_KEY_SIZE] = buffer.data().as_slice().try_into().unwrap();
    Ok(password)
}

fn handshake(stream: &mut TcpStream) -> std::io::Result<((PublicKey, PrivateKey), PublicKey)> {
    let keys = generate_keys();
    let client_hello_bytes: [u8; 12] = read_client_hello(stream)?;
    let server_hello = send_hello(stream).unwrap().data();
    let mut server_hello_bytes: [u8; SERVER_MASTER_KEY_SIZE] = [0; SERVER_MASTER_KEY_SIZE];
    server_hello_bytes.copy_from_slice(&server_hello);
    let master_password: [u8; MASTER_KEY_SIZE] = [client_hello_bytes, server_hello_bytes].concat()[0..MASTER_KEY_SIZE].try_into().unwrap();
    let client_public_key: PublicKey = read_client_public_key(stream)?;
    send_crypted_public_key(stream, &keys.0, &client_public_key)?;
    let received_master_password = read_cyphered_password(stream)?;
    let handshake_result: [u8; 1024] = validate_handshake(stream, &received_master_password, &master_password, &keys.1)?.data();
    if handshake_result == OK_BYTES {
        return Ok((keys, client_public_key));
    } else if handshake_result == KO_BYTES {
        return Err(Error::other("Handshake went wrong :("));
    } else {
        unreachable!();
    }
}
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
