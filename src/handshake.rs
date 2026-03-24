// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 omnizs — Messtar Protocol

use crate::kdf::SessionKeys;
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

pub struct Handshake {
    secret: EphemeralSecret,
    pub public_key: PublicKey,
}

impl Handshake {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self { secret, public_key }
    }

    pub fn derive_keys(self, peer_public_key: PublicKey, initiator: bool) -> SessionKeys {
        let shared_secret = self.secret.diffie_hellman(&peer_public_key);

        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

        let mut master = Zeroizing::new([0u8; 64]);
        hkdf.expand(b"messtar-master-v2", master.as_mut())
            .expect("HKDF master failed");

        // Salt derived deterministically — identical on both sides
        let mut salt = [0u8; 16];
        hkdf.expand(b"messtar-salt-v2", &mut salt)
            .expect("HKDF salt failed");

        SessionKeys::derive(&*master, salt, initiator)
    }
}

impl Default for Handshake {
    fn default() -> Self {
        Self::new()
    }
}
