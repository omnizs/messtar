// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 omnizs — Messtar Protocol

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

// All labels are versioned; changing them produces incompatible keys by design
const LABEL_A2B: &[u8] = b"messtar-a2b-v2";
const LABEL_B2A: &[u8] = b"messtar-b2a-v2";
const LABEL_RATCHET_SEND: &[u8] = b"messtar-ratchet-send-v2";
const LABEL_RATCHET_RECV: &[u8] = b"messtar-ratchet-recv-v2";

fn derive_key(master: &[u8], info: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, key.as_mut()).expect("HKDF expand failed");
    key
}

pub struct SessionKeys {
    pub send_key: Zeroizing<[u8; 32]>,
    pub recv_key: Zeroizing<[u8; 32]>,
    // Salt stored for ratchet; cleared on drop via Zeroizing wrapper in SessionKeys::drop
    pub session_salt: Zeroizing<[u8; 16]>,
    // Ratchet counter for audit / anti-rollback
    pub ratchet_count: u32,
}

impl SessionKeys {
    pub fn derive(master: &[u8], salt: [u8; 16], initiator: bool) -> Self {
        let (send_label, recv_label) = if initiator {
            (LABEL_A2B, LABEL_B2A)
        } else {
            (LABEL_B2A, LABEL_A2B)
        };

        Self {
            send_key: derive_key(master, send_label, &salt),
            recv_key: derive_key(master, recv_label, &salt),
            session_salt: Zeroizing::new(salt),
            ratchet_count: 0,
        }
    }

    pub fn ratchet(&mut self) {
        self.send_key =
            derive_key(&*self.send_key, LABEL_RATCHET_SEND, &*self.session_salt);
        self.recv_key =
            derive_key(&*self.recv_key, LABEL_RATCHET_RECV, &*self.session_salt);
        self.ratchet_count = self.ratchet_count.saturating_add(1);
    }
}
