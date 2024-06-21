use std::net::TcpStream;

use serde::Deserialize;

use crate::{
    keys_generator::keys::PublicKey,
    protocol::{
        server::errors::{TunnelError, TunnelResult},
        shared::{
            constant::{CLIENT_MASTER_KEY_SIZE, MASTER_KEY_SIZE},
            types::{HelloClientRequest, KeysValidatedRequest, SharingPubKeyRequest},
        },
    },
};

/// Read the client hello message
///
/// This function will read the hello message from the client and start the handshake protocol
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the client
///
/// # Returns
/// **TunnelResult<[u8; CLIENT_MASTER_KEY_SIZE]>** - The key sent by the client
pub fn read_client_hello(stream: &mut TcpStream) -> TunnelResult<[u8; CLIENT_MASTER_KEY_SIZE]> {
    let mut de = serde_json::Deserializer::from_reader(stream);
    match HelloClientRequest::deserialize(&mut de) {
        Ok(buffer) => Ok(buffer.key()),
        Err(_) => Err(TunnelError::InvalidData),
    }
}

/// Read the client public key
///
/// This function will read the public key from the client
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the client
///
/// # Returns
/// **TunnelResult<PublicKey>** - The public key of the client
pub fn read_client_public_key(stream: &mut TcpStream) -> TunnelResult<PublicKey> {
    let mut de = serde_json::Deserializer::from_reader(stream);
    match SharingPubKeyRequest::deserialize(&mut de) {
        Ok(buffer) => Ok(buffer.pub_key()),
        Err(_) => Err(TunnelError::InvalidData),
    }
}

/// Read the cyphered password
///
/// This function will read the cyphered password from the client
///
/// # Arguments
/// stream: **&mut TcpStream** - The stream to the client
///
/// # Returns
/// **TunnelResult<Vec<usize>>** - The cyphered password
pub fn read_cyphered_password(stream: &mut TcpStream) -> TunnelResult<Vec<usize>> {
    let mut de = serde_json::Deserializer::from_reader(stream);
    match KeysValidatedRequest::deserialize(&mut de) {
        Err(_) => Err(TunnelError::InvalidKeySize),
        Ok(buffer) => {
            if buffer.key().len() != MASTER_KEY_SIZE {
                Err(TunnelError::InvalidKeySize)
            } else {
                Ok(buffer.key())
            }
        }
    }
}
