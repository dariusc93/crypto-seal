use crate::{error::Error, Result};
use aes_gcm::{
    aead::{
        stream::{DecryptorBE32, EncryptorBE32},
        Aead, NewAead,
    },
    Aes256Gcm, Key, Nonce,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Digest, Keypair, Sha512, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use std::io;
use zeroize::Zeroize;

/// Container of private keys
/// The following is supported
/// - [`ed25519_dalek`]
/// - [`secp256k1`]
/// - [`aes_gcm::Aes256Gcm`]
#[derive(Debug)]
pub enum PrivateKey {
    Ed25519(Keypair),
    Secp256k1(secp256k1::SecretKey),
    Aes256([u8; 32]),
}

impl Default for PrivateKey {
    fn default() -> Self {
        Self::new_with(PrivateKeyType::default())
    }
}

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        match self {
            PrivateKey::Ed25519(kp) => {
                kp.secret.zeroize();
            }
            PrivateKey::Secp256k1(_kp) => {
                //TODO: Zeroize or destroy key
            }
            PrivateKey::Aes256(key) => {
                key.zeroize();
            }
        }
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.zeroize()
    }
}

/// Container of public keys
/// The following is supported
/// - [`ed25519_dalek::PublicKey`]
#[derive(Debug, Clone)]
pub enum PublicKey {
    Ed25519(ed25519_dalek::PublicKey),
    Secp256k1(secp256k1::PublicKey),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PublicKeyType {
    /// Ed25519 Public Key
    Ed25519,

    /// Secp256k1 Public Key
    Secp256k1,
}

impl TryFrom<u8> for PublicKeyType {
    type Error = Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            b'e' => Ok(PublicKeyType::Ed25519),
            b's' => Ok(PublicKeyType::Secp256k1),
            _ => Err(Error::InvalidPublickey),
        }
    }
}

impl From<PublicKeyType> for u8 {
    fn from(value: PublicKeyType) -> Self {
        match value {
            PublicKeyType::Ed25519 => b'e',
            PublicKeyType::Secp256k1 => b's',
        }
    }
}

impl From<ed25519_dalek::PublicKey> for PublicKey {
    fn from(pk: ed25519_dalek::PublicKey) -> Self {
        PublicKey::Ed25519(pk)
    }
}

impl From<secp256k1::PublicKey> for PublicKey {
    fn from(pk: secp256k1::PublicKey) -> Self {
        PublicKey::Secp256k1(pk)
    }
}

impl TryFrom<PublicKey> for secp256k1::PublicKey {
    type Error = Error;

    fn try_from(value: PublicKey) -> std::result::Result<Self, Self::Error> {
        match value {
            PublicKey::Secp256k1(pk) => Ok(pk),
            PublicKey::Ed25519(_) => Err(Error::InvalidPublickey),
        }
    }
}

impl TryFrom<&PrivateKey> for x25519_dalek::StaticSecret {
    type Error = Error;

    fn try_from(value: &PrivateKey) -> std::result::Result<Self, Self::Error> {
        match value {
            PrivateKey::Ed25519(kp) => {
                let mut hasher: Sha512 = Sha512::new();
                hasher.update(kp.secret.as_ref());
                let hash = hasher.finalize().to_vec();
                let mut new_sk: [u8; 32] = [0; 32];
                new_sk.copy_from_slice(&hash[..32]);
                let sk = x25519_dalek::StaticSecret::from(new_sk);
                new_sk.zeroize();
                Ok(sk)
            }
            _ => Err(Error::Unsupported),
        }
    }
}

impl TryFrom<PrivateKey> for x25519_dalek::StaticSecret {
    type Error = Error;

    fn try_from(value: PrivateKey) -> std::result::Result<Self, Self::Error> {
        match &value {
            PrivateKey::Ed25519(kp) => {
                let mut hasher: Sha512 = Sha512::new();
                hasher.update(kp.secret.as_ref());
                let hash = hasher.finalize().to_vec();
                let mut new_sk: [u8; 32] = [0; 32];
                new_sk.copy_from_slice(&hash[..32]);
                let sk = x25519_dalek::StaticSecret::from(new_sk);
                new_sk.zeroize();
                Ok(sk)
            }
            _ => Err(Error::Unsupported),
        }
    }
}

impl TryFrom<PublicKey> for ed25519_dalek::PublicKey {
    type Error = Error;

    fn try_from(value: PublicKey) -> std::result::Result<Self, Self::Error> {
        match value {
            PublicKey::Secp256k1(_) => Err(Error::InvalidPublickey),
            PublicKey::Ed25519(pk) => Ok(pk),
        }
    }
}

impl TryFrom<PublicKey> for x25519_dalek::PublicKey {
    type Error = Error;

    fn try_from(value: PublicKey) -> std::result::Result<Self, Self::Error> {
        match value {
            PublicKey::Secp256k1(_) => Err(Error::InvalidPublickey),
            PublicKey::Ed25519(pk) => {
                let ep = CompressedEdwardsY(pk.to_bytes())
                    .decompress()
                    .ok_or(Error::Unsupported)?; //Note: This should not error here
                let mon = ep.to_montgomery();
                Ok(x25519_dalek::PublicKey::from(mon.0))
            }
        }
    }
}

impl PublicKey {
    pub fn from_bytes(key_type: PublicKeyType, bytes: &[u8]) -> Result<PublicKey> {
        match key_type {
            PublicKeyType::Ed25519 => Self::from_ed25519_bytes(bytes),
            PublicKeyType::Secp256k1 => Self::from_secp256k1_bytes(bytes),
        }
    }

    pub fn from_ed25519_bytes(bytes: &[u8]) -> Result<PublicKey> {
        let pk = ed25519_dalek::PublicKey::from_bytes(bytes)?;
        Ok(PublicKey::Ed25519(pk))
    }

    pub fn from_secp256k1_bytes(bytes: &[u8]) -> Result<PublicKey> {
        let public_key = secp256k1::PublicKey::from_slice(bytes)?;
        Ok(PublicKey::Secp256k1(public_key))
    }

    pub fn decode(bytes: &[u8]) -> Result<PublicKey> {
        if bytes.is_empty() {
            return Err(Error::InvalidPublickey);
        }

        let mut encoded_key = bytes.to_vec();
        let ktype = encoded_key.remove(0).try_into()?;
        Self::from_bytes(ktype, &encoded_key)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut data = vec![self.key_type().into()];
        data.extend(self.to_bytes());
        data
    }

    /// Convert the [`PublicKey`] to a byte array
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::Ed25519(public_key) => public_key.to_bytes().to_vec(),
            PublicKey::Secp256k1(public_key) => public_key.serialize().to_vec(),
        }
    }

    pub fn key_type(&self) -> PublicKeyType {
        match self {
            PublicKey::Ed25519(_) => PublicKeyType::Ed25519,
            PublicKey::Secp256k1(_) => PublicKeyType::Secp256k1,
        }
    }
}

impl PublicKey {
    /// Verify the signature of the data provided using [`PrivateKey`]
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            PublicKey::Ed25519(pubkey) => {
                let signature = Signature::from_bytes(signature)?;
                pubkey.verify(data, &signature)?;
                Ok(())
            }
            PublicKey::Secp256k1(pubkey) => {
                let secp = secp256k1::Secp256k1::new();

                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                let hash = hasher.finalize().to_vec();
                let msg = secp256k1::Message::from_slice(&hash)?;

                let sig = secp256k1::ecdsa::Signature::from_compact(signature)?;
                secp.verify_ecdsa(&msg, &sig, pubkey)?;
                Ok(())
            }
        }
    }
}

impl PublicKey {
    /// Verify the signature of the data from [`std::io::Read`] using [`PrivateKey`]
    pub fn verify_reader(
        &self,
        reader: &mut impl io::Read,
        signature: &[u8],
        context: Option<&[u8]>,
    ) -> Result<()> {
        match self {
            PublicKey::Ed25519(key) => {
                let mut hasher: Sha512 = Sha512::new();
                io::copy(reader, &mut hasher)?;
                let signature = Signature::from_bytes(signature)?;
                key.verify_prehashed(hasher, context, &signature)?;
                Ok(())
            }
            PublicKey::Secp256k1(key) => {
                let secp = secp256k1::Secp256k1::new();
                let mut hasher: Sha512 = Sha512::new();
                io::copy(reader, &mut hasher)?;
                let hash = hasher.finalize().to_vec();
                let msg = secp256k1::Message::from_slice(&hash)?;

                let sig = secp256k1::ecdsa::Signature::from_compact(signature)?;
                secp.verify_ecdsa(&msg, &sig, key)?;
                Ok(())
            }
        }
    }
}
/// [`PrivateKey`] Types
#[derive(Debug, Copy, Clone)]
pub enum PrivateKeyType {
    /// ED25519 Private Key
    Ed25519,

    /// AES-256 Private Key
    Aes256,

    /// Secp256k1 Private Key
    Secp256k1,
}

impl Default for PrivateKeyType {
    fn default() -> Self {
        Self::Ed25519
    }
}

const WRITE_BUFFER_SIZE: usize = 512;
const READ_BUFFER_SIZE: usize = 528;

impl PrivateKey {
    /// Generates a new [`PrivateKey`] with randomly generated key
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a [`PrivateKey`] using [`PrivateKeyType`]
    pub fn new_with(key_type: PrivateKeyType) -> Self {
        match key_type {
            PrivateKeyType::Ed25519 => {
                let mut csprng = OsRng {};
                let key = Keypair::generate(&mut csprng);
                PrivateKey::Ed25519(key)
            }
            PrivateKeyType::Aes256 => {
                let mut key_sized = [0u8; 32];
                key_sized.copy_from_slice(&generate(32));
                PrivateKey::Aes256(key_sized)
            }
            PrivateKeyType::Secp256k1 => {
                let mut rng = secp256k1::rand::thread_rng();
                PrivateKey::Secp256k1(secp256k1::SecretKey::new(&mut rng))
            }
        }
    }

    /// Import private key which is identified with [`PrivateKeyType`]
    pub fn import(key_type: PrivateKeyType, key: Vec<u8>) -> Result<Self> {
        match key_type {
            PrivateKeyType::Ed25519 => Keypair::from_bytes(&key)
                .map(PrivateKey::Ed25519)
                .map_err(Error::from),
            PrivateKeyType::Aes256 => key
                .as_slice()
                .try_into()
                .map(PrivateKey::Aes256)
                .map_err(Error::from),
            PrivateKeyType::Secp256k1 => secp256k1::SecretKey::from_slice(&key)
                .map(PrivateKey::Secp256k1)
                .map_err(Error::from),
        }
    }

    /// Provides the [`PrivateKeyType`] of the [`PrivateKey`]
    pub fn key_type(&self) -> PrivateKeyType {
        match self {
            PrivateKey::Aes256(_) => PrivateKeyType::Aes256,
            PrivateKey::Ed25519(_) => PrivateKeyType::Ed25519,
            PrivateKey::Secp256k1(_) => PrivateKeyType::Secp256k1,
        }
    }

    /// Provides the [`PublicKey`] of the [`PrivateKey`]
    /// Note: This will only work with asymmetric keys. Any symmetric keys will
    ///       return [`Error::Unsupported`]
    pub fn public_key(&self) -> Result<PublicKey> {
        match self {
            PrivateKey::Aes256(_) => Err(Error::Unsupported),
            PrivateKey::Ed25519(key) => Ok(key.public.into()),
            PrivateKey::Secp256k1(pk) => {
                let secp = secp256k1::Secp256k1::new();
                Ok(secp256k1::PublicKey::from_secret_key(&secp, pk).into())
            }
        }
    }

    /// Sign the data provided using [`PrivateKey`]
    /// Note: If a symmetric key is used, it will encrypt the hash.
    ///       This will change in the future to use HMAC instead
    //TODO: Use HMAC for AES
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            PrivateKey::Aes256(_) => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(data);
                let hash = hasher.finalize().to_vec();
                let enc_hash = self.encrypt(&hash, None)?;
                Ok(enc_hash)
            }
            PrivateKey::Ed25519(key) => {
                let signature = key.sign(data);
                Ok(signature.to_bytes().to_vec())
            }
            PrivateKey::Secp256k1(key) => {
                let secp = secp256k1::Secp256k1::new();
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                let hash = hasher.finalize().to_vec();
                let msg = secp256k1::Message::from_slice(&hash)?;
                Ok(secp.sign_ecdsa(&msg, key).serialize_compact().to_vec())
            }
        }
    }

    /// Sign the data from [`std::io::Read`] using [`PrivateKey`]
    /// Note: If a symmetric key is used, it will encrypt the hash.
    ///       This will change in the future to use HMAC instead
    //TODO: Use HMAC for AES
    pub fn sign_reader(
        &self,
        reader: &mut impl io::Read,
        context: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self {
            PrivateKey::Aes256(_) => {
                let mut hasher: Sha512 = Sha512::new();
                io::copy(reader, &mut hasher)?;
                let hash = hasher.finalize().to_vec();
                let enc_hash = self.encrypt(&hash, None)?;
                Ok(enc_hash)
            }
            PrivateKey::Ed25519(key) => {
                let mut hasher: Sha512 = Sha512::new();
                io::copy(reader, &mut hasher)?;
                let signature = key.sign_prehashed(hasher, context)?;
                Ok(signature.to_bytes().to_vec())
            }
            PrivateKey::Secp256k1(key) => {
                let secp = secp256k1::Secp256k1::new();
                let mut hasher: Sha512 = Sha512::new();
                io::copy(reader, &mut hasher)?;
                let hash = hasher.finalize().to_vec();
                let msg = secp256k1::Message::from_slice(&hash)?;
                Ok(secp.sign_ecdsa(&msg, key).serialize_compact().to_vec())
            }
        }
    }

    /// Verify the signature of the data provided using [`PrivateKey`]
    /// Note: If a symmetric key is used, it will decrypt the hash.
    ///       This will change in the future to use HMAC instead
    //TODO: Use HMAC for AES
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            PrivateKey::Aes256(_) => {
                let mut hasher: Sha512 = Sha512::new();
                hasher.update(data);
                let hash = hasher.finalize().to_vec();
                let dec_hash = self.decrypt(signature, None)?;
                if dec_hash == hash {
                    return Ok(());
                }
                Err(Error::InvalidSignature)
            }
            _ => {
                let public_key = self.public_key()?;
                public_key.verify(data, signature)
            }
        }
    }

    /// Verify the signature of the data from [`std::io::Read`] using [`PrivateKey`]
    /// Note: If a symmetric key is used, it will decrypt the hash.
    ///       This will change in the future to use HMAC instead
    //TODO: Use HMAC for AES
    pub fn verify_reader(
        &self,
        reader: &mut impl io::Read,
        signature: &[u8],
        context: Option<&[u8]>,
    ) -> Result<()> {
        match self {
            PrivateKey::Aes256(_) => {
                let mut hasher: Sha512 = Sha512::new();
                io::copy(reader, &mut hasher)?;
                let hash = hasher.finalize().to_vec();
                let dec_hash = self.decrypt(signature, None)?;
                if dec_hash == hash {
                    return Ok(());
                }
                Err(Error::InvalidSignature)
            }
            _ => {
                let public_key = self.public_key()?;
                public_key.verify_reader(reader, signature, context)
            }
        }
    }
}

impl PrivateKey {
    /// Encrypt the data using [`PrivateKey`].
    ///
    /// If `pubkey` is supplied while [`PrivateKeyType::Ed25519`], a key exchange will be performed
    /// If `pubkey` is not supplied while [`PrivateKeyType::Ed25519`], a key will be produced between our private and public key
    /// If [`PrivateKeyType::Aes256`] is used, the `pubkey` not impact encryption
    pub fn encrypt(&self, data: &[u8], pubkey: Option<PublicKey>) -> Result<Vec<u8>> {
        let key = self.fetch_encryption_key(pubkey)?;
        let raw_nonce = generate(12);
        let key = Key::from_slice(&key);
        let nonce = Nonce::from_slice(&raw_nonce);
        let cipher = Aes256Gcm::new(key);
        let mut data = cipher
            .encrypt(nonce, data)
            .map_err(|_| Error::EncryptionError)?;
        data.extend(nonce);
        Ok(data)
    }

    /// Decrypt the data using [`PrivateKey`].
    ///
    /// If `pubkey` is supplied while [`PrivateKeyType::Ed25519`], a key exchange will be performed
    /// If `pubkey` is not supplied while [`PrivateKeyType::Ed25519`], a key will be produced between our private and public key
    /// If [`PrivateKeyType::Aes256`] is used, the `pubkey` not impact decryption
    pub fn decrypt(&self, data: &[u8], pubkey: Option<PublicKey>) -> Result<Vec<u8>> {
        let key = self.fetch_encryption_key(pubkey)?;
        let (nonce, data) = extract_data_slice(data, 12);
        let key = Key::from_slice(&key);
        let nonce = Nonce::from_slice(nonce);
        let cipher = Aes256Gcm::new(key);
        cipher
            .decrypt(nonce, data)
            .map_err(|_| Error::DecryptionError)
    }
}

impl PrivateKey {
    /// Encrypt the data stream from [`std::io::Read`] to [`std::io::Write`] using [`PrivateKey`].
    ///
    /// If `pubkey` is supplied while [`PrivateKeyType::Ed25519`], a key exchange will be performed
    /// If `pubkey` is not supplied while [`PrivateKeyType::Ed25519`], a key will be produced between our private and public key
    /// If [`PrivateKeyType::Aes256`] is used, the `pubkey` not impact encryption
    pub fn encrypt_stream(
        &self,
        reader: &mut impl io::Read,
        writer: &mut impl io::Write,
        pubkey: Option<PublicKey>,
    ) -> Result<()> {
        let key = self.fetch_encryption_key(pubkey)?;
        let nonce = generate(7);

        let key = Key::from_slice(&key);
        let cipher = Aes256Gcm::new(key);
        let mut buffer = [0u8; WRITE_BUFFER_SIZE];
        let mut stream = EncryptorBE32::from_aead(cipher, nonce.as_slice().into());
        writer.write_all(&nonce)?;
        loop {
            match reader.read(&mut buffer) {
                Ok(WRITE_BUFFER_SIZE) => {
                    let ciphertext = stream
                        .encrypt_next(buffer.as_slice())
                        .map_err(|_| Error::EncryptionStreamError)?;
                    writer.write_all(&ciphertext)?;
                }
                Ok(read_count) => {
                    let ciphertext = stream
                        .encrypt_last(&buffer[..read_count])
                        .map_err(|_| Error::EncryptionStreamError)?;
                    writer.write_all(&ciphertext)?;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::from(e)),
            }
        }
        Ok(())
    }

    /// Decrypt the data stream from [`std::io::Read`] to [`std::io::Write`] using [`PrivateKey`].
    ///
    /// If `pubkey` is supplied while [`PrivateKeyType::Ed25519`], a key exchange will be performed
    /// If `pubkey` is not supplied while [`PrivateKeyType::Ed25519`], a key will be produced between our private and public key
    /// If [`PrivateKeyType::Aes256`] is used, the `pubkey` not impact decryption
    pub fn decrypt_stream(
        &self,
        reader: &mut impl io::Read,
        writer: &mut impl io::Write,
        pubkey: Option<PublicKey>,
    ) -> Result<()> {
        let key = self.fetch_encryption_key(pubkey)?;
        let mut nonce = vec![0u8; 7];
        reader.read_exact(&mut nonce)?;

        let key = Key::from_slice(&key);
        let cipher = Aes256Gcm::new(key);

        let mut stream = DecryptorBE32::from_aead(cipher, nonce.as_slice().into());
        let mut buffer = [0u8; READ_BUFFER_SIZE];
        loop {
            match reader.read(&mut buffer) {
                Ok(READ_BUFFER_SIZE) => {
                    let plaintext = stream
                        .decrypt_next(buffer.as_slice())
                        .map_err(|_| Error::DecryptionStreamError)?;

                    writer.write_all(&plaintext)?
                }
                Ok(read_count) if read_count == 0 => break,
                Ok(read_count) => {
                    let plaintext = stream
                        .decrypt_last(&buffer[..read_count])
                        .map_err(|_| Error::DecryptionStreamError)?;
                    writer.write_all(&plaintext)?;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::from(e)),
            };
        }
        writer.flush()?;
        Ok(())
    }

    /// Used internally to obtain the encryption key
    /// If the key type is [`PrivateKeyType::Aes256`], it will use the key directly from [`PrivateKey::Aes256`],
    /// If the key type is [`PrivateKeyType::Ed25519`],it will convert our private key to [`x25519_dalek::StaticSecret`]
    /// and perform a check on the pubkey input to determine if its [`Option::is_some`]. If true it will perform a key exchange between our
    /// [`x25519_dalek::StaticSecret`] and the supplied [`PublicKey`], which is converted to [`x25519_dalek::PublicKey`]. If false,
    /// we perform a key exchange with our own [`x25519_dalek::PublicKey`] derived from generated [`x25519_dalek::StaticSecret`]
    /// and return the key.
    fn fetch_encryption_key(&self, pubkey: Option<PublicKey>) -> Result<Vec<u8>> {
        match self {
            PrivateKey::Aes256(key) => Ok(key.to_vec()),
            PrivateKey::Secp256k1(pk) => {
                let public_key: secp256k1::PublicKey = match pubkey {
                    Some(pubkey) => pubkey.try_into()?,
                    None => {
                        let secp = secp256k1::Secp256k1::new();
                        secp256k1::PublicKey::from_secret_key(&secp, pk)
                    }
                };
                let shared_key = secp256k1::ecdh::SharedSecret::new(&public_key, pk);
                Ok(shared_key.as_ref().to_vec())
            }
            PrivateKey::Ed25519(_) => {
                let static_key: x25519_dalek::StaticSecret = self.try_into()?;
                let public_key: x25519_dalek::PublicKey = match pubkey {
                    //Note: This may not be ideal to use one own key for
                    //      performing a ecdh exchange. While there is no known
                    //      attack, we should still be cautious of performing
                    //      this and might be wise in the future to have dual
                    //      keys. One ed25519 and another x25519
                    Some(pubkey) => pubkey.try_into()?,
                    None => x25519_dalek::PublicKey::from(&static_key),
                };
                let enc_key = static_key.diffie_hellman(&public_key);
                Ok(enc_key.as_bytes().to_vec())
            }
        }
    }
}

/// Used internally to split data based on the supplied sized.
fn extract_data_slice(data: &[u8], size: usize) -> (&[u8], &[u8]) {
    let extracted = &data[data.len() - size..];
    let payload = &data[..data.len() - size];
    (extracted, payload)
}

/// Used to generate random amount of data and store it in a Vec with a specific capacity
fn generate(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buffer = vec![0u8; size];
    OsRng.fill_bytes(&mut buffer);
    buffer
}
