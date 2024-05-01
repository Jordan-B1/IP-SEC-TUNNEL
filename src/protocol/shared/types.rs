use serde::{Deserialize, Serialize};

use super::constant::MAX_PACKET_SIZE;

pub type PacketData = [u8; MAX_PACKET_SIZE];

#[derive(Serialize, Deserialize, Debug)]

pub enum PacketType {
    HELLOCLIENT,
    HELLOSERVER,
    SHARINGPUBKEY,
    SHARINGCRYPTEDPUBKEY,
    KEYSVALIDATED,
    HANDSHAKEVALIDATED,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Packet {
    packet_type: PacketType,
    #[serde(with = "serde_bytes")]
    data: PacketData,
}

impl Packet {
    pub fn new(packet_type: PacketType, data: PacketData) -> Self {
        return Self { packet_type, data };
    }

    pub fn packet_type(self: Self) -> PacketType {
        self.packet_type
    }

    pub fn data(self: Self) -> PacketData {
        self.data
    }
}
