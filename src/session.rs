use std::sync::atomic::{AtomicU64, Ordering};
use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    cipher::{decrypt, encrypt, generate_nonce},
    error::{MesstarError, Result},
    packet::{MesstarPacket, PacketType},
};

pub struct Session {
    pub id: [u8; 16],
    key: Zeroizing<[u8; 32]>,   // ← ключ затирается при drop()
    send_counter: AtomicU64,
    recv_counter: AtomicU64,
}

impl Session {
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        Self {
            id,
            key,
            send_counter: AtomicU64::new(0),
            recv_counter: AtomicU64::new(0),
        }
    }

    pub fn send(&self, data: &[u8]) -> Result<MesstarPacket> {
        let seq = self.send_counter.fetch_add(1, Ordering::SeqCst);
        let nonce = generate_nonce();
        let ciphertext = encrypt(&self.key, &nonce, data)?;
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
        ))
    }

    pub fn receive(&self, packet: &MesstarPacket) -> Result<Vec<u8>> {
        let expected = self.recv_counter.load(Ordering::SeqCst);
        if packet.seq_num < expected {
            return Err(MesstarError::InvalidPacket);
        }
        self.recv_counter.store(packet.seq_num + 1, Ordering::SeqCst);
        decrypt(&self.key, &packet.nonce, &packet.payload)
    }
}

// Явно затираем id при уничтожении сессии
impl Drop for Session {
    fn drop(&mut self) {
        self.id.zeroize();
    }
}
