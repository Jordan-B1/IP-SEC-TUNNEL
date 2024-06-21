use serde::{Deserialize, Serialize};

use crate::keys_generator::keys::PublicKey;

use super::constant::{CLIENT_MASTER_KEY_SIZE, SERVER_MASTER_KEY_SIZE};

/// The hello client request
///
/// This struct is used to represent the hello client request
///
/// # Fields
/// - **key** - The key sent by the client
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HelloClientRequest {
    key: [u8; CLIENT_MASTER_KEY_SIZE],
}

impl HelloClientRequest {
    /// Create a new hello client request
    ///
    /// This function will create a new hello client request
    ///
    /// # Arguments
    /// key: **[u8; CLIENT_MASTER_KEY_SIZE]** - The key sent by the client
    ///
    /// # Returns
    /// **HelloClientRequest** - The hello client request created
    pub fn new(key: [u8; CLIENT_MASTER_KEY_SIZE]) -> Self {
        return Self { key };
    }

    /// Get the key
    ///
    /// This function will return the key sent by the client
    ///
    /// # Returns
    /// **[u8; CLIENT_MASTER_KEY_SIZE]** - The key sent by the client
    pub fn key(self: &Self) -> [u8; CLIENT_MASTER_KEY_SIZE] {
        self.key.clone()
    }
}

/// The hello server request
///
/// This struct is used to represent the hello server request
///
/// # Fields
/// - **key** - The key sent by the server
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HelloServerRequest {
    key: [u8; SERVER_MASTER_KEY_SIZE],
}

impl HelloServerRequest {
    /// Create a new hello server request
    ///
    /// This function will create a new hello server request
    ///
    /// # Arguments
    /// key: **[u8; SERVER_MASTER_KEY_SIZE]** - The key sent by the server
    ///
    /// # Returns
    /// **HelloServerRequest** - The hello server request created
    pub fn new(key: [u8; SERVER_MASTER_KEY_SIZE]) -> Self {
        return Self { key };
    }

    /// Get the key
    ///
    /// This function will return the key sent by the server
    ///
    /// # Returns
    /// **[u8; SERVER_MASTER_KEY_SIZE]** - The key sent by the server
    pub fn key(self: &Self) -> [u8; SERVER_MASTER_KEY_SIZE] {
        self.key.clone()
    }
}

/// The sharing public key request
///
/// This struct is used to represent the sharing public key request
///
/// # Fields
/// - **pub_key** - The public key of the client
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SharingPubKeyRequest {
    pub_key: PublicKey,
}

impl SharingPubKeyRequest {
    /// Create a new sharing public key request
    ///
    /// This function will create a new sharing public key request
    ///
    /// # Arguments
    /// pub_key: **PublicKey** - The public key of the client
    ///
    /// # Returns
    /// **SharingPubKeyRequest** - The sharing public key request created
    pub fn new(pub_key: PublicKey) -> Self {
        return Self { pub_key };
    }

    /// Get the public key
    ///
    /// This function will return the public key of the client
    ///
    /// # Returns
    /// **PublicKey** - The public key of the client
    pub fn pub_key(self: &Self) -> PublicKey {
        self.pub_key.clone()
    }
}

/// The sharing crypted public key request
///
/// This struct is used to represent the sharing crypted public key request
///
/// # Fields
/// - **crypted_pub_key** - The crypted public key of the server
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SharingCryptedPubKeyRequest {
    crypted_pub_key: Vec<usize>,
}

impl SharingCryptedPubKeyRequest {
    /// Create a new sharing crypted public key request
    ///
    /// This function will create a new sharing crypted public key request
    ///
    /// # Arguments
    /// crypted_pub_key: **Vec<usize>** - The crypted public key of the server
    ///
    /// # Returns
    /// **SharingCryptedPubKeyRequest** - The sharing crypted public key request created
    pub fn new(crypted_pub_key: Vec<usize>) -> Self {
        return Self { crypted_pub_key };
    }

    /// Get the crypted public key
    ///
    /// This function will return the crypted public key of the server
    ///
    /// # Returns
    /// **Vec<usize>** - The crypted public key of the server
    pub fn crypted_pub_key(self: &Self) -> Vec<usize> {
        self.crypted_pub_key.clone()
    }
}

/// The keys validated request
///
/// This struct is used to represent the keys validated request
///
/// # Fields
/// - **key** - The keys validated
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct KeysValidatedRequest {
    key: Vec<usize>,
}

impl KeysValidatedRequest {
    /// Create a new keys validated request
    ///
    /// This function will create a new keys validated request
    ///
    /// # Arguments
    /// key: **Vec<usize>** - The keys validated
    ///
    /// # Returns
    /// **KeysValidatedRequest** - The keys validated request created
    pub fn new(key: Vec<usize>) -> Self {
        return Self { key };
    }

    /// Get the keys
    ///
    /// This function will return the keys validated
    ///
    /// # Returns
    /// **Vec<usize>** - The keys validated
    pub fn key(self: &Self) -> Vec<usize> {
        self.key.clone()
    }
}

/// The handshake validated request
///
/// This struct is used to represent the handshake validated request
///
/// # Fields
/// - **status** - The status of the handshake (KO/OK)
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HandshakeValidatedRequest {
    status: [u8; 2],
}

impl HandshakeValidatedRequest {
    /// Create a new handshake validated request
    ///
    /// This function will create a new handshake validated request
    ///
    /// # Arguments
    /// status: **[u8; 2]** - The status of the handshake (KO/OK)
    ///
    /// # Returns
    /// **HandshakeValidatedRequest** - The handshake validated request created
    pub fn new(status: [u8; 2]) -> Self {
        return Self { status };
    }

    /// Get the status
    ///
    /// This function will return the status of the handshake
    ///
    /// # Returns
    /// **[u8; 2]** - The status of the handshake (KO/OK)
    pub fn status(self: &Self) -> [u8; 2] {
        self.status.clone()
    }
}

/// The type of packet
///
/// This enum is used to represent the different types of packet that can be sent
///
/// # Variants
/// - **HELLOCLIENT** - The client is saying hello
/// - **HELLOSERVER** - The server is saying hello
/// - **SHARINGPUBKEY** - The client is sharing its public key
/// - **SHARINGCRYPTEDPUBKEY** - The server is sharing its crypted public key
/// - **KEYSVALIDATED** - The keys have been validated
/// - **HANDSHAKEVALIDATED** - The handshake has been validated or the hanshake failed
/// - **LEAVE** - The server will close the connection
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum PacketType {
    HELLOCLIENT(HelloClientRequest),
    HELLOSERVER(HelloServerRequest),
    SHARINGPUBKEY(SharingPubKeyRequest),
    SHARINGCRYPTEDPUBKEY(SharingCryptedPubKeyRequest),
    KEYSVALIDATED(KeysValidatedRequest),
    HANDSHAKEVALIDATED(HandshakeValidatedRequest),
    LEAVE,
}
