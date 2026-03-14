use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

pub struct Handshake {
    secret: EphemeralSecret,
    pub public_key: PublicKey,
}

impl Handshake {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self { secret, public_key }
    }

    pub fn derive_key(self, peer_public_key: PublicKey) -> Zeroizing<[u8; 32]> {
        let shared_secret = self.secret.diffie_hellman(&peer_public_key);

        // Zeroizing<> автоматически затирает память при drop()
        let mut key = Zeroizing::new([0u8; 32]);
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        hkdf.expand(b"messtar-v1", key.as_mut())
            .expect("HKDF expand failed");

        key
    }
}
