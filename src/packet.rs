use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PacketType {
    Handshake,
    Data,
    Ack,
    Close,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MesstarPacket {
    pub version: u8,
    pub packet_type: PacketType,
    pub session_id: [u8; 16],
    pub seq_num: u64,        // ← новое: счётчик пакетов
    pub nonce: [u8; 12],
    pub payload: Vec<u8>,
    pub tag: [u8; 16],
}

impl MesstarPacket {
    pub fn new(
        packet_type: PacketType,
        session_id: [u8; 16],
        seq_num: u64,
        nonce: [u8; 12],
        payload: Vec<u8>,
        tag: [u8; 16],
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            packet_type,
            session_id,
            seq_num,
            nonce,
            payload,
            tag,
        }
    }
}
