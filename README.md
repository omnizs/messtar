# Messtar

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
messtar = "0.4.0"

# With async TCP transport layer
messtar = { version = "0.4.0", features = ["transport"] }
