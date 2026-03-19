// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 omnizs — Messtar Protocol

use messtar::{identity::Identity, transport::{MesstarClient, MesstarServer}};
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() {
    println!("=== Messtar TCP Demo v0.4.0 (Mutual Auth) ===\n");

    let server_identity = Identity::generate();
    let client_identity = Identity::generate();

    // Share verifying keys out-of-band (in real use: PKI or TOFU)
    let server_vk = server_identity.verifying_key;
    let client_vk = client_identity.verifying_key;

    let server_task = tokio::spawn(async move {
        let server = MesstarServer::bind("127.0.0.1:7878").await.unwrap();
        println!("🟢 Server listening on 127.0.0.1:7878");

        let mut conn = server.accept(&server_identity).await.unwrap();

        // Verify client is who we expect
        assert_eq!(conn.peer_identity.as_bytes(), client_vk.as_bytes());
        println!("✅ Client identity verified\n");

        loop {
            match conn.recv().await {
                Ok(msg) => {
                    let text  = String::from_utf8_lossy(&msg);
                    println!("📩 Server received: {text:?}");
                    conn.send(format!("echo: {text}").as_bytes()).await.unwrap();
                }
                Err(e) => { println!("🔴 {e}"); break; }
            }
        }
    });

    sleep(Duration::from_millis(100)).await;

    let mut client = MesstarClient::connect("127.0.0.1:7878", &client_identity).await.unwrap();

    // Verify server is who we expect
    assert_eq!(client.peer_identity.as_bytes(), server_vk.as_bytes());
    println!("✅ Server identity verified");
    println!("✅ Handshake + Mutual Auth complete\n");

    for msg in ["Hello!", "Mutual Auth works!", "Both sides verified"] {
        client.send(msg.as_bytes()).await.unwrap();
        println!("📨 Client sent:  {msg:?}");
        let reply = client.recv().await.unwrap();
        println!("📩 Client got:   {:?}\n", String::from_utf8_lossy(&reply));
    }

    server_task.abort();
    println!("✅ TCP Mutual Auth demo complete!");
}
