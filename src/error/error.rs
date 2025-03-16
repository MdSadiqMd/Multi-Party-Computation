use thiserror::Error;

#[derive(Error, Debug)]
pub enum MpcError {
    #[error("Invalid metadata configuration")]
    InvalidMetadata,

    #[error("Invalid secret")]
    InvalidSecret,

    #[error("Invalid share")]
    InvalidShare,

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Cryptography error: {0}")]
    CryptoError(String),

    #[error("Queue processing error: {0}")]
    QueueError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, MpcError>;
