use std::{
    io::{self, Error, Read, Write},
    net::{TcpListener, TcpStream},
    thread,
};

use crate::{
    cypher::enigma,
    keys_generator::keys::{PrivateKey, PublicKey},
    protocol::{server::handshake::validate::handshake, shared::constant::MAX_PACKET_SIZE},
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

fn echo_server(stream: &mut TcpStream) {
    println!("New client connected!");
    let keys: Result<((PublicKey, PrivateKey), PublicKey), Error> = handshake(stream); //handshake(stream).unwrap();
    while keys.is_err() {
        println!("Handshake went wrong with {:?}", stream.peer_addr());
        println!("Should we retry the process ? Y/n");
    }
    let keys: ((PublicKey, PrivateKey), PublicKey) = keys.unwrap();
    println!("handshake completed! keys {:?}", keys);
    loop {
        read_stream(stream, &keys.0 .1);
        send_input(stream, &keys.1);
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
