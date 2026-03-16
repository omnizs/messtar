// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 omnizs — Messtar Protocol

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::{
    cipher::{decrypt, encrypt, generate_nonce},
    error::{MesstarError, Result},
    kdf::SessionKeys,
    packet::{pad, unpad, MesstarPacket, PacketType},
};

const RATCHET_INTERVAL: u64 = 100;

pub struct Session {
    pub id:       [u8; 16],
    keys:         Mutex<SessionKeys>,
    send_counter: AtomicU64,
    recv_counter: AtomicU64,
}

impl Session {
    pub fn new(keys: SessionKeys) -> Self {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        Self {
            id,
            keys:         Mutex::new(keys),
            send_counter: AtomicU64::new(0),
            recv_counter: AtomicU64::new(0),
        }
    }

    pub fn send(&self, data: &[u8]) -> Result<MesstarPacket> {
        let seq      = self.send_counter.fetch_add(1, Ordering::SeqCst);
        let mut keys = self.keys.lock().unwrap();

        if seq > 0 && seq % RATCHET_INTERVAL == 0 {
            keys.ratchet();
        }

        let (padded, pad_len) = pad(data);
        let nonce      = generate_nonce();
        let ciphertext = encrypt(&keys.send_key, &nonce, &padded)?;
        let tag: [u8; 16] = ciphertext[ciphertext.len() - 16..]
            .try_into()
            .unwrap();

        Ok(MesstarPacket::new(
            PacketType::Data,
            self.id,
            seq,
            nonce,
            ciphertext,
            tag,
            pad_len,
        ))
    }

    pub fn receive(&self, packet: &MesstarPacket) -> Result<Vec<u8>> {
        if !packet.is_fresh() {
            return Err(MesstarError::PacketExpired);
        }

        let expected = self.recv_counter.load(Ordering::SeqCst);
        if packet.seq_num < expected {
            return Err(MesstarError::ReplayDetected);
        }
        self.recv_counter.store(packet.seq_num + 1, Ordering::SeqCst);

        let keys   = self.keys.lock().unwrap();
        let padded = decrypt(&keys.recv_key, &packet.nonce, &packet.payload)?;

        Ok(unpad(&padded, packet.pad_len))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.id.zeroize();
    }
}
