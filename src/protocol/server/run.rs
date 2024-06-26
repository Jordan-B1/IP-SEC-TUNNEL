use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    thread,
};

use crate::{
    cypher::enigma,
    keys_generator::keys::{PrivateKey, PublicKey},
    protocol::{
        server::{errors::TunnelResult, handshake::validate::handshake},
        shared::{
            constant::{MAX_CONNECTION_ATTEMPS, MAX_PACKET_SIZE},
            types::PacketType,
        },
    },
};

/// Send input to the client
///
/// This function will read the input from the user and send it to the client
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the client<br/>
/// pub_key: **&PublicKey** - The public key of the client
fn send_input(stream: &mut TcpStream, pub_key: &PublicKey) {
    let mut input_buffer: String = String::new();
    let stdin: io::Stdin = io::stdin();
    let enigma_buffer: Vec<usize>;

    print!("Pocalhost: ");
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

/// Read the stream from the client
///
/// This function will read the stream from the client and print the message
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the client<br/>
/// private_key: **&PrivateKey** - The private key to decrypt the message
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

/// Launch the server
///
/// This function will launch the server and handle the client connection
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the client
fn launch(stream: &mut TcpStream) {
    println!("New client connected!");
    let mut connection_attemps: u8 = 0;
    let mut keys: TunnelResult<((PublicKey, PrivateKey), PublicKey)> = handshake(stream);
    connection_attemps += 1;
    while keys.is_err() && connection_attemps <= MAX_CONNECTION_ATTEMPS {
        println!("Handshake went wrong : {:?}", keys.err().unwrap());
        println!("Trying again");
        keys = handshake(stream);
        connection_attemps += 1;
    }
    if keys.is_err() {
        println!(
            "Too many failed connection for client {:?}, stopping connection...",
            stream.peer_addr()
        );
        serde_json::to_writer(stream, &PacketType::LEAVE)
            .expect("Failed to send data to client...");
        println!("Client disconnected!");
        return;
    }
    let keys: ((PublicKey, PrivateKey), PublicKey) = keys.unwrap();
    println!("handshake completed! keys {:?}", keys);
    loop {
        read_stream(stream, &keys.0 .1);
        send_input(stream, &keys.1);
    }
}

/// Start the server
///
/// This function will start the server and listen for incoming connections
///
/// # Arguments
/// ip: **String** - The ip address to listen to<br/>
/// port: **u16** - The port to listen to
///
/// # Returns
/// **()** - Nothing
pub fn start_server(ip: String, port: u16) -> () {
    let endpoint: String = format!("{}:{}", ip, port);
    let listener: TcpListener =
        TcpListener::bind(endpoint).expect("Failed to connect to tcp socket!");

    println!("Server launched on port {}!", port);
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                thread::spawn(move || launch(&mut stream));
            }
            Err(e) => println!("Couldn't get client: {e:?}"),
        }
    }
}
