// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 omnizs — Messtar Protocol

use crate::{
    error::{MesstarError, Result},
    handshake::Handshake,
    identity::Identity,
    packet::MesstarPacket,
    session::Session,
};
use ed25519_dalek::VerifyingKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::PublicKey;

async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|_| MesstarError::HandshakeFailed)?;
    stream
        .write_all(data)
        .await
        .map_err(|_| MesstarError::HandshakeFailed)
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|_| MesstarError::HandshakeFailed)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|_| MesstarError::HandshakeFailed)?;
    Ok(buf)
}

// Authenticated handshake frame layout:
// [x25519_pub: 32][ed25519_verifying_key: 32][signature_of_x25519_pub: 64]
async fn send_auth_frame(
    stream: &mut TcpStream,
    hs: &Handshake,
    identity: &Identity,
) -> Result<()> {
    let x25519_pub = hs.public_key.as_bytes();
    let verifying = identity.verifying_key.as_bytes();
    let signature = identity.sign_public_key(x25519_pub);

    let mut frame = Vec::with_capacity(32 + 32 + 64);
    frame.extend_from_slice(x25519_pub);
    frame.extend_from_slice(verifying);
    frame.extend_from_slice(&signature);
    write_frame(stream, &frame).await
}

async fn recv_auth_frame(stream: &mut TcpStream) -> Result<(PublicKey, VerifyingKey)> {
    let frame = read_frame(stream).await?;
    if frame.len() != 128 {
        return Err(MesstarError::HandshakeFailed);
    }

    let x25519_bytes: [u8; 32] = frame[0..32].try_into().unwrap();
    let verifying_bytes: [u8; 32] = frame[32..64].try_into().unwrap();
    let sig_bytes: [u8; 64] = frame[64..128].try_into().unwrap();

    let peer_x25519 = PublicKey::from(x25519_bytes);
    let peer_verifying =
        VerifyingKey::from_bytes(&verifying_bytes).map_err(|_| MesstarError::HandshakeFailed)?;

    // Verify peer signed their own x25519 public key with their Ed25519 key
    Identity::verify_public_key(&peer_verifying, &x25519_bytes, &sig_bytes)?;

    Ok((peer_x25519, peer_verifying))
}

pub struct MesstarConn {
    stream: TcpStream,
    session: Session,
    pub peer_identity: VerifyingKey,
}

impl MesstarConn {
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        let packet = self.session.send(data)?;
        let encoded = postcard::to_allocvec(&packet).map_err(|_| MesstarError::InvalidPacket)?;
        write_frame(&mut self.stream, &encoded).await
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let frame = read_frame(&mut self.stream).await?;
        let packet: MesstarPacket =
            postcard::from_bytes(&frame).map_err(|_| MesstarError::InvalidPacket)?;
        self.session.receive(&packet)
    }
}

pub struct MesstarClient;

impl MesstarClient {
    pub async fn connect(addr: &str, identity: &Identity) -> Result<MesstarConn> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|_| MesstarError::HandshakeFailed)?;

        let hs = Handshake::new();

        // Send our auth frame, receive peer auth frame
        send_auth_frame(&mut stream, &hs, identity).await?;
        let (peer_x25519, peer_identity) = recv_auth_frame(&mut stream).await?;

        let session = Session::new(hs.derive_keys(peer_x25519, true));
        Ok(MesstarConn {
            stream,
            session,
            peer_identity,
        })
    }
}

pub struct MesstarServer {
    listener: TcpListener,
}

impl MesstarServer {
    pub async fn bind(addr: &str) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|_| MesstarError::HandshakeFailed)?;
        Ok(Self { listener })
    }

    pub async fn accept(&self, identity: &Identity) -> Result<MesstarConn> {
        let (mut stream, _) = self
            .listener
            .accept()
            .await
            .map_err(|_| MesstarError::HandshakeFailed)?;

        let hs = Handshake::new();

        // Receive client auth frame first, then send ours
        let (peer_x25519, peer_identity) = recv_auth_frame(&mut stream).await?;
        send_auth_frame(&mut stream, &hs, identity).await?;

        let session = Session::new(hs.derive_keys(peer_x25519, false));
        Ok(MesstarConn {
            stream,
            session,
            peer_identity,
        })
    }
}
