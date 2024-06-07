use serde::{Deserialize, Serialize};

use crate::keys_generator::keys::PublicKey;

use super::constant::{CLIENT_MASTER_KEY_SIZE, MAX_PACKET_SIZE, SERVER_MASTER_KEY_SIZE};

pub type PacketData = [u8; MAX_PACKET_SIZE];

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HelloClientRequest {
    key: [u8; CLIENT_MASTER_KEY_SIZE],
}

impl HelloClientRequest {
    pub fn new(key: [u8; CLIENT_MASTER_KEY_SIZE]) -> Self {
        return Self { key };
    }
    pub fn key(self: &Self) -> [u8; CLIENT_MASTER_KEY_SIZE] {
        self.key.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HelloServerRequest {
    key: [u8; SERVER_MASTER_KEY_SIZE],
}

impl HelloServerRequest {
    pub fn new(key: [u8; SERVER_MASTER_KEY_SIZE]) -> Self {
        return Self { key };
    }
    pub fn key(self: &Self) -> [u8; SERVER_MASTER_KEY_SIZE] {
        self.key.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SharingPubKeyRequest {
    pub_key: PublicKey,
}

impl SharingPubKeyRequest {
    pub fn new(pub_key: PublicKey) -> Self {
        return Self { pub_key };
    }
    pub fn pub_key(self: &Self) -> PublicKey {
        self.pub_key.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SharingCryptedPubKeyRequest {
    crypted_pub_key: Vec<usize>,
}

impl SharingCryptedPubKeyRequest {
    pub fn new(crypted_pub_key: Vec<usize>) -> Self {
        return Self { crypted_pub_key };
    }
    pub fn crypted_pub_key(self: &Self) -> Vec<usize> {
        self.crypted_pub_key.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct KeysValidatedRequest {
    key: Vec<usize>,
}

impl KeysValidatedRequest {
    pub fn new(key: Vec<usize>) -> Self {
        return Self { key };
    }
    pub fn key(self: &Self) -> Vec<usize> {
        self.key.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HandshakeValidatedRequest {
    status: [u8; 2],
}

impl HandshakeValidatedRequest {
    pub fn new(status: [u8; 2]) -> Self {
        return Self { status };
    }
    pub fn status(self: &Self) -> [u8; 2] {
        self.status.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum PacketType {
    HELLOCLIENT(HelloClientRequest),
    HELLOSERVER(HelloServerRequest),
    SHARINGPUBKEY(SharingPubKeyRequest),
    SHARINGCRYPTEDPUBKEY(SharingCryptedPubKeyRequest),
    KEYSVALIDATED(KeysValidatedRequest),
    HANDSHAKEVALIDATED(HandshakeValidatedRequest),
}
