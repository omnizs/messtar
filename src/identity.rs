use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use rand::rngs::OsRng;
use crate::error::{MesstarError, Result};

pub struct Identity {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Identity {
    /// Генерируем пару ключей Ed25519 для стороны
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    /// Подписываем публичный ключ X25519 перед отправкой
    pub fn sign_public_key(&self, x25519_pub: &[u8; 32]) -> [u8; 64] {
        let sig: Signature = self.signing_key.sign(x25519_pub);
        sig.to_bytes()
    }

    /// Проверяем подпись чужого публичного ключа X25519
    pub fn verify_public_key(
        their_verifying_key: &VerifyingKey,
        x25519_pub: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<()> {
        let sig = Signature::from_bytes(signature);
        their_verifying_key
            .verify(x25519_pub, &sig)
            .map_err(|_| MesstarError::HandshakeFailed)
    }
}
