# Messtar

[![Crates.io Version](https://img.shields.io/crates/v/messtar?color=orange)](https://crates.io/crates/messtar)
[![Build Status](https://img.shields.io/github/actions/workflow/status/omnizs/messtar/rust.yml?branch=main&color=orange)](https://github.com/omnizs/messtar/actions)
[![License](https://img.shields.io/crates/l/messtar?color=orange)](https://github.com/omnizs/messtar/blob/main/LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/omnizs/messtar?color=orange)](https://github.com/omnizs/messtar/commits/main)

Messtar is a custom, lightweight encryption protocol written in Rust, designed for secure end-to-end data transmission. It ensures confidentiality, integrity, and mutual authentication.

## Features

- **Key Exchange:** X25519 Diffie-Hellman for perfect forward secrecy
- **Key Derivation:** HKDF-SHA256 with versioned labels
- **Encryption:** AES-256-GCM via `aes-gcm` with `OsRng` nonce generation
- **Authentication:** Ed25519 mutual identity verification during handshake
- **Security:** Replay attack protection, strict packet freshness, automatic key ratcheting with rollback counter
- **Packets:** Structured via `MesstarPacket` with versioning, nonce, authenticated payload, and padding
- **Transport:** Optional async TCP layer built on `tokio` and `postcard`

## Installation

```toml
[dependencies]
# Core protocol
messtar = "0.5.0"

# With async TCP transport layer
messtar = { version = "0.5.0", features = ["transport"] }
```

## Quick Start

```rust
use messtar::handshake::perform_handshake;
use messtar::session::Session;

// 1. Perform handshake to derive shared session keys
let (alice_keys, bob_keys) = perform_handshake();

// 2. Create sessions
let alice = Session::new(alice_keys);
let bob = Session::new(bob_keys);

// 3. Send and receive
let packet = alice.send(b"hello").unwrap();
let plaintext = bob.receive(&packet).unwrap();
assert_eq!(plaintext, b"hello");
```

## Security Properties

- **Perfect Forward Secrecy** — ephemeral X25519 keys per session; past sessions are not compromised if current keys leak
- **Authenticated Encryption** — AES-256-GCM provides both encryption and tamper detection via GCM tag
- **Replay Protection** — sliding window + sequence numbers reject duplicate or out-of-order packets
- **Key Ratcheting** — session keys are ratcheted every 100 packets with a rollback counter, limiting the impact of key exposure
- **Memory Safety** — session keys and salt are zeroed on drop via `zeroize`
- **Opaque Errors** — decryption failures return no oracle-exploitable detail

## Releases

Pre-built binaries for `demo` and `tcp_demo` are attached to each [GitHub Release](https://github.com/omnizs/messtar/releases):

| Platform | File |
|----------|------|
| Linux x86-64 | `demo-linux`, `tcp_demo-linux` |
| Windows x86-64 | `demo-windows.exe`, `tcp_demo-windows.exe` |
| macOS x86-64 | `demo-macos`, `tcp_demo-macos` |
| macOS ARM64 | `demo-macos-arm64`, `tcp_demo-macos-arm64` |

## License

GPL-3.0-only
