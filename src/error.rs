use thiserror::Error;

#[derive(Debug, Error)]
pub enum MesstarError {
    #[error("Ошибка шифрования: {0}")]
    EncryptionFailed(String),

    #[error("Ошибка дешифрования: неверный ключ или данные повреждены")]
    DecryptionFailed,

    #[error("Ошибка рукопожатия")]
    HandshakeFailed,

    #[error("Недопустимый пакет")]
    InvalidPacket,

    #[error("Сессия не активна")]
    SessionExpired,
}

pub type Result<T> = std::result::Result<T, MesstarError>;
