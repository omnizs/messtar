// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 omnizs — Messtar Protocol

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MesstarError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: invalid key or corrupted data")]
    DecryptionFailed,

    #[error("Handshake failed")]
    HandshakeFailed,

    #[error("Invalid packet")]
    InvalidPacket,

    #[error("Session expired")]
    SessionExpired,

    #[error("Replay attack detected")]
    ReplayDetected,

    #[error("Packet too old")]
    PacketExpired,
}

pub type Result<T> = std::result::Result<T, MesstarError>;
