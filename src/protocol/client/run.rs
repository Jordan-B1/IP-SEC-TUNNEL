use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

use crate::{
    cypher::enigma,
    keys_generator::keys::{PrivateKey, PublicKey},
    protocol::{
        client::{errors::TunnelError, handshake::validate::handshake},
        shared::constant::MAX_PACKET_SIZE,
    },
};

use super::errors::TunnelResult;

/// Send an input to the server
///
/// This function will ask the user for an input and send it to the server cyphered
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the server<br/>
/// pub_key: **&PublicKey** - The public key used to cypher the message
fn send_input(stream: &mut TcpStream, pub_key: &PublicKey) {
    let mut input_buffer: String = String::new();
    let stdin: io::Stdin = io::stdin();
    let enigma_buffer: Vec<u8>;

    print!("Localhost: ");
    std::io::stdout().flush().unwrap();
    stdin
        .read_line(&mut input_buffer)
        .expect("Error while reading standard input...");
    enigma_buffer = enigma(
        &input_buffer.as_bytes().to_vec(),
        &pub_key.encryption_value(),
        &pub_key.modulus(),
    );
    input_buffer = serde_json::to_string(&enigma_buffer).unwrap();
    stream
        .write(input_buffer.as_bytes())
        .expect("Failed sending data to server...");
}

/// Read the stream from the server
///
/// This function will read the stream from the server and print the message received
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the server<br/>
/// private_key: **&PrivateKey** - The private key used to decrypt the message
fn read_stream(stream: &mut TcpStream, private_key: &PrivateKey) -> TunnelResult<()> {
    let mut buffer: [u8; MAX_PACKET_SIZE] = [0; MAX_PACKET_SIZE];
    let json_data: &str;
    let cyphered_message: Vec<u8>;
    let mut plain_message: Vec<u8>;
    let data_size: usize;

    data_size = stream
        .read(&mut buffer)
        .expect("Failed to read from server...");
    json_data = std::str::from_utf8(&buffer[0..data_size]).unwrap();
    if data_size == 0 {
        return Err(TunnelError::ServerDisconnected);
    }
    cyphered_message = serde_json::from_str(json_data).unwrap();
    plain_message = enigma(
        &cyphered_message,
        &private_key.decryption_value(),
        &private_key.modulus(),
    );
    plain_message.pop();
    println!(
        "{}: [{}]",
        stream.peer_addr().unwrap().ip(),
        std::str::from_utf8(&plain_message.iter().map(|x| *x as u8).collect::<Vec<u8>>()).unwrap()
    );
    Ok(())
}

/// Initialize the communication with the handshake protocol
///
/// This function will start the handshake protocol with the server
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the server   
///
/// # Returns
/// **Option<((PublicKey, PrivateKey), PublicKey)>** - The keys used for the communication if the handshake is successful.<br/>
/// None otherwise
fn init_communication(stream: &mut TcpStream) -> Option<((PublicKey, PrivateKey), PublicKey)> {
    let mut input: String = String::new();
    let mut keys: TunnelResult<((PublicKey, PrivateKey), PublicKey)> = handshake(stream);

    while keys.is_err() {
        println!("Handshake failed {:?}", keys.as_ref().unwrap_err());
        println!("Should we retry the process ? Y/n");
        std::io::stdin()
            .read_line(&mut input)
            .expect("Error while reading standard input...");
        if input == "Y" || input == "y" {
            keys = handshake(stream);
        } else {
            return None;
        }
    }
    return Some(keys.unwrap());
}

/// Start the client
///
/// This function will start the client and connect to the server
///
/// # Arguments
/// ip: **String** - The ip address of the server<br/>
/// port: **u16** - The port of the server
pub fn start_client(ip: String, port: u16) -> () {
    let endpoint: String = format!("{}:{}", ip, port);
    let mut stream: TcpStream =
        TcpStream::connect(endpoint.clone()).expect("Failed to connect to server...");

    println!("Client started and connected to {}!", endpoint);

    let keys: ((PublicKey, PrivateKey), PublicKey) = match init_communication(&mut stream) {
        None => return,
        Some(keys) => keys,
    };
    loop {
        send_input(&mut stream, &keys.1);
        match read_stream(&mut stream, &keys.0 .1) {
            Err(err) => {
                println!("{:?}", err);
                break;
            }
            Ok(_) => continue,
        }
    }
}
