// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 omnizs — Messtar Protocol

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

fn derive_key(master: &[u8], info: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, key.as_mut()).expect("HKDF expand failed");
    key
}

pub struct SessionKeys {
    pub send_key:     Zeroizing<[u8; 32]>,
    pub recv_key:     Zeroizing<[u8; 32]>,
    pub mac_key:      Zeroizing<[u8; 32]>,
    pub session_salt: [u8; 16],
}

impl SessionKeys {
    pub fn derive(master: &[u8], salt: [u8; 16], initiator: bool) -> Self {
        // Alice (initiator): send=a2b, recv=b2a
        // Bob  (!initiator): send=b2a, recv=a2b
        let (send_label, recv_label) = if initiator {
            (b"messtar-a2b-v2" as &[u8], b"messtar-b2a-v2" as &[u8])
        } else {
            (b"messtar-b2a-v2" as &[u8], b"messtar-a2b-v2" as &[u8])
        };

        Self {
            send_key:     derive_key(master, send_label, &salt),
            recv_key:     derive_key(master, recv_label, &salt),
            mac_key:      derive_key(master, b"messtar-mac-v2", &salt),
            session_salt: salt,
        }
    }

    pub fn ratchet(&mut self) {
        self.send_key = derive_key(&*self.send_key, b"messtar-ratchet-send", &self.session_salt);
        self.recv_key = derive_key(&*self.recv_key, b"messtar-ratchet-recv", &self.session_salt);
        self.mac_key  = derive_key(&*self.mac_key,  b"messtar-ratchet-mac",  &self.session_salt);
    }
}
