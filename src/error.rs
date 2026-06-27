use core::array::TryFromSliceError;
use ed25519_dalek::SignatureError;
#[cfg(feature = "std")]
use std::io;
use thiserror::Error;

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
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Recipients was not set or available")]
    RecipientsNotAvailable,
    #[error("Unable to convert slice: {0}")]
    InvalidLength(#[from] TryFromSliceError),
    #[error("{0}")]
    SignatureError(SignatureError),
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[cfg(feature = "json")]
    #[cfg_attr(docsrs, doc(cfg(feature = "json")))]
    #[error("{0}")]
    SerdeJsonError(serde_json::Error),
    #[error(transparent)]
    PostcardError(#[from] postcard::Error),
}

impl From<SignatureError> for Error {
    fn from(value: SignatureError) -> Self {
        Error::SignatureError(value)
    }
}

#[cfg(feature = "json")]
impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Error::SerdeJsonError(value)
    }
}
