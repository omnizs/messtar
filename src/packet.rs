// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 omnizs — Messtar Protocol

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROTOCOL_VERSION: u8 = 2;
pub const MAX_PACKET_AGE_SECS: u64 = 30;
pub const PADDING_BLOCK: usize = 64;

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
    pub seq_num: u64,
    pub ratchet_epoch: u32,
    pub timestamp: u64,
    pub nonce: [u8; 12],
    pub payload: Vec<u8>,
    pub tag: [u8; 16],
    pub pad_len: u8,
}

pub struct PacketParams {
    pub packet_type: PacketType,
    pub session_id: [u8; 16],
    pub seq_num: u64,
    pub ratchet_epoch: u32,
    pub nonce: [u8; 12],
    pub payload: Vec<u8>,
    pub tag: [u8; 16],
    pub pad_len: u8,
}

impl MesstarPacket {
    pub fn new(p: PacketParams) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            version: PROTOCOL_VERSION,
            packet_type: p.packet_type,
            session_id: p.session_id,
            seq_num: p.seq_num,
            ratchet_epoch: p.ratchet_epoch,
            timestamp,
            nonce: p.nonce,
            payload: p.payload,
            tag: p.tag,
            pad_len: p.pad_len,
        }
    }

    pub fn is_fresh(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.timestamp) <= MAX_PACKET_AGE_SECS
    }
}

pub fn pad(data: &[u8]) -> (Vec<u8>, u8) {
    let pad_len = PADDING_BLOCK - (data.len() % PADDING_BLOCK);
    let mut padded = data.to_vec();
    padded.extend(vec![pad_len as u8; pad_len]);
    (padded, pad_len as u8)
}

pub fn unpad(data: &[u8], pad_len: u8) -> Vec<u8> {
    let end = data.len().saturating_sub(pad_len as usize);
    data[..end].to_vec()
}
