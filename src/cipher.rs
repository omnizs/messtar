// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 omnizs — Messtar Protocol

use crate::error::{MesstarError, Result};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use zeroize::Zeroizing;

// Nonce is 96-bit (12 bytes) as required by AES-256-GCM
pub fn generate_nonce() -> [u8; 12] {
    Aes256Gcm::generate_nonce(OsRng).into()
}

pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    // Key material wrapped in Zeroizing to clear on drop
    let key_bytes = Zeroizing::new(*key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key_bytes));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| MesstarError::EncryptionFailed(e.to_string()))
}

pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    // Key material wrapped in Zeroizing to clear on drop
    let key_bytes = Zeroizing::new(*key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key_bytes));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        // Deliberately opaque error: avoids leaking oracle info on decryption failure
        .map_err(|_| MesstarError::DecryptionFailed)
}
