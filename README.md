# Messtar

[![Crates.io Version](https://img.shields.io/crates/v/messtar?color=orange)](https://crates.io/crates/messtar)
[![Build Status](https://img.shields.io/github/actions/workflow/status/omnizs/messtar/rust.yml?branch=main&color=orange)](https://github.com/omnizs/messtar/actions)
[![License](https://img.shields.io/crates/l/messtar?color=orange)](https://github.com/omnizs/messtar/blob/main/LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/omnizs/messtar?color=orange)](https://github.com/omnizs/messtar/commits/main)

Messtar is a custom, lightweight encryption protocol written in Rust, designed for secure end-to-end data transmission. It ensures confidentiality, integrity, and mutual authentication.

## Features
- **Key Exchange:** X25519 Diffie-Hellman for perfect forward secrecy
- **Key Derivation:** HKDF-SHA256
- **Encryption:** AES-256-GCM
- **Authentication:** Ed25519 mutual identity verification during handshake
- **Security:** Replay attack protection, strict packet freshness, and automatic key ratcheting
- **Transport:** Optional async TCP layer built on `tokio` and `postcard`

## Installation

```toml
[dependencies]
# Core protocol
messtar = "0.4.2"

# With async TCP transport layer
messtar = { version = "0.4.2", features = ["transport"] }
