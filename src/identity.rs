// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 omnizs — Messtar Protocol

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use crate::error::{MesstarError, Result};

pub struct Identity {
    pub signing_key:   SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Identity {
    pub fn generate() -> Self {
        let signing_key   = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    pub fn sign_public_key(&self, x25519_pub: &[u8; 32]) -> [u8; 64] {
        let sig: Signature = self.signing_key.sign(x25519_pub);
        sig.to_bytes()
    }

    pub fn verify_public_key(
        their_verifying_key: &VerifyingKey,
        x25519_pub:          &[u8; 32],
        signature:           &[u8; 64],
    ) -> Result<()> {
        let sig = Signature::from_bytes(signature);
        their_verifying_key
            .verify(x25519_pub, &sig)
            .map_err(|_| MesstarError::HandshakeFailed)
    }
}
