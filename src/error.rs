use ed25519_dalek::SignatureError;
use std::array::TryFromSliceError;
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
    #[error("Invalid Package")]
    InvalidPackage,
    #[error("Invalid public key")]
    InvalidPublickey,
    #[error("Invalid private key")]
    InvalidPrivatekey,
    #[error("Recipients was not set or available")]
    RecipientsNotAvailable,
    #[error("Unable to convert slice: {0}")]
    InvalidLength(#[from] TryFromSliceError),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    Secp256k1Error(#[from] secp256k1::Error),
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
    #[error(transparent)]
    Base58EncodeError(#[from] bs58::encode::Error),
    #[error(transparent)]
    Base58DecodeError(#[from] bs58::decode::Error),
    #[cfg(feature = "libp2p-identity")]
    #[error(transparent)]
    OtherVariantError(#[from] libp2p_identity::OtherVariantError),
    #[cfg(feature = "libp2p-identity")]
    #[error(transparent)]
    DecodingError(#[from] libp2p_identity::DecodingError),
}
