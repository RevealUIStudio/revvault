use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RevaultError {
    #[error("identity file not found: {0}")]
    IdentityNotFound(PathBuf),

    #[error("recipients file not found: {0}")]
    RecipientsNotFound(PathBuf),

    #[error("store directory not found: {0}")]
    StoreNotFound(PathBuf),

    #[error("secret not found: {0}")]
    SecretNotFound(String),

    #[error("secret already exists: {0}")]
    SecretAlreadyExists(String),

    #[error("invalid secret path: {0}")]
    InvalidPath(String),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("invalid namespace: {0}")]
    InvalidNamespace(String),

    #[error("rotation failed for {provider}: {reason}")]
    RotationFailed { provider: String, reason: String },

    #[error("migration failed: {0}")]
    MigrationFailed(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, RevaultError>;
