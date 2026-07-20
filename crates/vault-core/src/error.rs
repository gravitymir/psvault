use thiserror::Error;

/// Errors that can occur while opening, decrypting, or saving a vault.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("not a password_store vault file (bad magic header)")]
    BadMagic,

    #[error("unsupported vault format version: {0}")]
    UnsupportedVersion(u8),

    #[error("file is truncated or corrupted")]
    Truncated,

    #[error("wrong master password or corrupted data")]
    Decrypt,

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("could not gather secure randomness: {0}")]
    Random(String),

    #[error("vault content is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;
