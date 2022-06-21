use std::array::TryFromSliceError;
use thiserror::Error;
use std::io;
use ed25519_dalek::SignatureError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Method provided is not supported")]
    Unsupported,
    #[error("Unable to encrypt data provided")]
    EncryptionError,
    #[error("Unable to decrypt data provided")]
    DecryptionError,
    #[error("Unable to encrypt data stream")]
    EncryptionStreamError,
    #[error("Unable to decrypt data stream")]
    DecryptionStreamError,
    #[error("Invalid Signature")]
    InvalidSignature,
    #[error("Unable to convert slice: {0}")]
    InvalidLength(#[from] TryFromSliceError),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
}