// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 omnizs — Messtar Protocol

use messtar::{
    handshake::Handshake,
    identity::Identity,
    session::Session,
};

fn main() {
    println!("=== Messtar Protocol v0.2.1 ===\n");

    let alice_id = Identity::generate();
    let bob_id   = Identity::generate();

    let alice_hs  = Handshake::new();
    let bob_hs    = Handshake::new();
    let alice_pub = alice_hs.public_key;
    let bob_pub   = bob_hs.public_key;

    let alice_sig = alice_id.sign_public_key(alice_pub.as_bytes());
    let bob_sig   = bob_id.sign_public_key(bob_pub.as_bytes());

    Identity::verify_public_key(
        &alice_id.verifying_key, alice_pub.as_bytes(), &alice_sig,
    ).expect("❌ Alice signature is invalid");

    Identity::verify_public_key(
        &bob_id.verifying_key, bob_pub.as_bytes(), &bob_sig,
    ).expect("❌ Bob signature is invalid");

    println!("✅ Ed25519 signatures verified");

    let alice_keys = alice_hs.derive_keys(bob_pub, true);   // initiator
    let bob_keys   = bob_hs.derive_keys(alice_pub, false);  // responder
    println!("✅ Separate keys successfully negotiated\n");

    let alice_session = Session::new(alice_keys);
    let bob_session   = Session::new(bob_keys);

    let messages = [
        "Hello, Messtar!",
        "Padding hides the message size",
        "Ratchet will rotate keys after 100 packets",
    ];

    for msg in messages {
        let packet   = alice_session.send(msg.as_bytes()).unwrap();
        let received = bob_session.receive(&packet).unwrap();

        println!("📨 Alice → seq={} pad={}b payload={}b",
                 packet.seq_num, packet.pad_len, packet.payload.len());
        println!("📩 Bob   ← {:?}\n",
                 std::str::from_utf8(&received).unwrap());
    }

    println!("⚔️  Replay Attack...");
    let packet = alice_session.send(b"replayed").unwrap();
    let _ = bob_session.receive(&packet).unwrap();
    match bob_session.receive(&packet) {
        Ok(_)  => println!("⚠️  Replay succeeded!"),
        Err(e) => println!("✅ Replay rejected: {e}"),
    }

    println!("\n⚔️  Expired packet...");
    let mut old = alice_session.send(b"old").unwrap();
    old.timestamp = 0;
    match bob_session.receive(&old) {
        Ok(_)  => println!("⚠️  Accepted!"),
        Err(e) => println!("✅ Rejected: {e}"),
    }

    println!("\n✅ Messtar v0.2.1 — everything works!");
}