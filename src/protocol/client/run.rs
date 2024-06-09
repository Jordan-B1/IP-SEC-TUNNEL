use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

use crate::{
    cypher::enigma,
    keys_generator::keys::{PrivateKey, PublicKey},
    protocol::{client::handshake::validate::handshake, shared::constant::MAX_PACKET_SIZE},
};

fn send_input(stream: &mut TcpStream, pub_key: &PublicKey) {
    let mut input_buffer: String = String::new();
    let stdin: io::Stdin = io::stdin();
    let enigma_buffer: Vec<usize>;

    print!("> ");
    std::io::stdout().flush().unwrap();
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
        .expect("Failed sending data to server...");
}

fn read_stream(stream: &mut TcpStream, private_key: &PrivateKey) {
    let mut buffer: [u8; MAX_PACKET_SIZE] = [0; MAX_PACKET_SIZE];
    let json_data: &str;
    let cyphered_message: Vec<usize>;
    let plain_message: Vec<usize>;
    let data_size: usize;

    data_size = stream
        .read(&mut buffer)
        .expect("Failed to read from server...");
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
