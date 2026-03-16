// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 omnizs — Messtar Protocol

use messtar::transport::{MesstarClient, MesstarServer};
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() {
    println!("=== Messtar TCP Demo v0.3.1 ===\n");

    let server_task = tokio::spawn(async {
        let server = MesstarServer::bind("127.0.0.1:7878").await.unwrap();
        println!("🟢 Server listening on 127.0.0.1:7878");

        let mut conn = server.accept().await.unwrap();
        println!("🤝 Client connected\n");

        loop {
            match conn.recv().await {
                Ok(msg) => {
                    let text  = String::from_utf8_lossy(&msg);
                    println!("📩 Server received: {text:?}");
                    let reply = format!("echo: {text}");
                    conn.send(reply.as_bytes()).await.unwrap();
                }
                Err(e) => {
                    println!("🔴 Server closed: {e}");
                    break;
                }
            }
        }
    });

    sleep(Duration::from_millis(100)).await;

    let mut client = MesstarClient::connect("127.0.0.1:7878").await.unwrap();
    println!("✅ Handshake complete\n");

    let messages = [
        "Hello over TCP!",
        "Messtar encrypts everything",
        "Perfect Forward Secrecy",
    ];

    for msg in messages {
        client.send(msg.as_bytes()).await.unwrap();
        println!("📨 Client sent:  {msg:?}");
        let reply = client.recv().await.unwrap();
        println!("📩 Client got:   {:?}\n", String::from_utf8_lossy(&reply));
    }

    server_task.abort();
    println!("✅ TCP demo complete!");
}
