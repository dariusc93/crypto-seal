
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, NewAead, stream::{DecryptorBE32, EncryptorBE32}}};
use anyhow::{anyhow, bail};
use ed25519_dalek::{Sha512, Digest, Keypair, Signature, Signer};
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;
use rand::rngs::OsRng;
use std::io;

#[derive(Debug)]
pub enum PrivateKey {
    Ed25519(Keypair),
    Aes256([u8; 32]),
}

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        match self {
            PrivateKey::Ed25519(kp) => {
                kp.secret.zeroize();
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

pub enum PublicKey {
    Ed25519(ed25519_dalek::PublicKey),
}

#[derive(Debug, Copy, Clone)]
pub enum PrivateKeyType {
    Ed25519,
    Aes256,
}

impl Default for PrivateKeyType {
    fn default() -> Self {
        Self::Ed25519
    }
}

const WRITE_BUFFER_SIZE: usize = 512;
const READ_BUFFER_SIZE: usize = 528;

impl PrivateKey {
    pub fn new() -> Self {
        Self::new_with(PrivateKeyType::default())
    }

    pub fn new_with(key_type: PrivateKeyType) -> Self {
        match key_type {
            PrivateKeyType::Ed25519 => {
                let mut csprng = OsRng {};
                let key = ed25519_dalek::Keypair::generate(&mut csprng);
                PrivateKey::Ed25519(key)
            }
            PrivateKeyType::Aes256 => {
                let mut key_sized = [0u8; 32];
                key_sized.copy_from_slice(&crate::generate(32));
                PrivateKey::Aes256(key_sized)
            }
        }
    }

    pub fn import(key_type: PrivateKeyType, key: Vec<u8>) -> anyhow::Result<Self> {
        match key_type {
            PrivateKeyType::Ed25519 => Ok(Keypair::from_bytes(&key).map(PrivateKey::Ed25519)?),
            PrivateKeyType::Aes256 => {
                let key: [u8; 32] = key
                    .as_slice()
                    .try_into()
                    .map_err(|e| anyhow!("Unable to parse key: {}", e))?;
                Ok(PrivateKey::Aes256(key))
            }
        }
    }

    pub fn key_type(&self) -> PrivateKeyType {
        match self {
            PrivateKey::Aes256(_) => PrivateKeyType::Aes256,
            PrivateKey::Ed25519(_) => PrivateKeyType::Ed25519,
        }
    }

    pub fn public_key(&self) -> anyhow::Result<PublicKey> {
        match self {
            PrivateKey::Aes256(_) => bail!("Unsupported"),
            PrivateKey::Ed25519(key) => Ok(PublicKey::Ed25519(key.public)),
        }
    }

    //TODO: Use HMAC for AES
    pub fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            PrivateKey::Aes256(_) => {
                let mut hasher: Sha512 = Sha512::new();
                hasher.update(data);
                let hash = hasher.finalize().to_vec();
                let enc_hash = self.encrypt(&hash, None)?;
                Ok(enc_hash)
            }
            PrivateKey::Ed25519(key) => {
                let signature = key.sign(data);
                Ok(signature.to_bytes().to_vec())
            }
        }
    }

    //TODO: Use HMAC for AES
    pub fn sign_reader(
        &self,
        reader: &mut impl io::Read,
        context: Option<&[u8]>,
    ) -> anyhow::Result<Vec<u8>> {
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
        }
    }

    //TODO: Use HMAC for AES
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        match self {
            PrivateKey::Aes256(_) => {
                let mut hasher: Sha512 = Sha512::new();
                hasher.update(data);
                let hash = hasher.finalize().to_vec();
                let dec_hash = self.decrypt(&signature, None)?;
                if dec_hash == hash {
                    return Ok(());
                }
                bail!("Signature is invalid")
            }
            PrivateKey::Ed25519(key) => {
                let signature = Signature::from_bytes(signature)?;
                key.verify(data, &signature)?;
                Ok(())
            }
        }
    }

    //TODO: Use HMAC for AES
    pub fn verify_reader(
        &self,
        reader: &mut impl io::Read,
        signature: &[u8],
        context: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        match self {
            PrivateKey::Aes256(_) => {
                let mut hasher: Sha512 = Sha512::new();
                io::copy(reader, &mut hasher)?;
                let hash = hasher.finalize().to_vec();
                let dec_hash = self.decrypt(&signature, None)?;
                if dec_hash == hash {
                    return Ok(());
                }
                bail!("Signature is invalid")
            }
            PrivateKey::Ed25519(key) => {
                let mut hasher: Sha512 = Sha512::new();
                io::copy(reader, &mut hasher)?;
                let signature = Signature::from_bytes(signature)?;
                key.verify_prehashed(hasher, context, &signature)?;
                Ok(())
            }
        }
    }
}

impl PrivateKey {
    pub fn encrypt(
        &self,
        data: &[u8],
        pubkey: Option<x25519_dalek::PublicKey>,
    ) -> anyhow::Result<Vec<u8>> {
        let key = self.fetch_encryption_key(pubkey);
        let raw_nonce = crate::generate(12);
        let key = Key::from_slice(&key);
        let nonce = Nonce::from_slice(&raw_nonce);
        let cipher = Aes256Gcm::new(key);
        let mut data = cipher
            .encrypt(nonce, data)
            .map_err(|e| anyhow::anyhow!(e))?;
        data.extend(nonce);
        Ok(data)
    }

    pub fn decrypt(
        &self,
        data: &[u8],
        pubkey: Option<x25519_dalek::PublicKey>,
    ) -> anyhow::Result<Vec<u8>> {
        let key = self.fetch_encryption_key(pubkey);
        let (nonce, data) = Self::extract_data_slice(data, 12);
        let key = Key::from_slice(&key);
        let nonce = Nonce::from_slice(&nonce);
        let cipher = Aes256Gcm::new(key);
        let data = cipher
            .decrypt(nonce, data)
            .map_err(|e| anyhow::anyhow!(e))?;
        Ok(data)
    }
}

impl PrivateKey {
    pub fn encrypt_stream(
        &self,
        reader: &mut impl io::Read,
        writer: &mut impl io::Write,
        pubkey: Option<x25519_dalek::PublicKey>,
    ) -> anyhow::Result<()> {
        let key = self.fetch_encryption_key(pubkey);
        let nonce = crate::generate(7);

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
                        .map_err(|err| anyhow::anyhow!(err))?;
                    writer.write_all(&ciphertext)?;
                }
                Ok(read_count) => {
                    let ciphertext = stream
                        .encrypt_last(&buffer[..read_count])
                        .map_err(|err| anyhow::anyhow!(err))?;
                    writer.write_all(&ciphertext)?;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => bail!(e),
            }
        }
        Ok(())
    }

    pub fn decrypt_stream(
        &self,
        reader: &mut impl io::Read,
        writer: &mut impl io::Write,
        pubkey: Option<x25519_dalek::PublicKey>,
    ) -> anyhow::Result<()> {
        let key = self.fetch_encryption_key(pubkey);
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
                        .map_err(|e| anyhow::anyhow!(e))?;

                    writer.write_all(&plaintext)?
                }
                Ok(read_count) if read_count == 0 => break,
                Ok(read_count) => {
                    let plaintext = stream
                        .decrypt_last(&buffer[..read_count])
                        .map_err(|e| anyhow::anyhow!(e))?;
                    writer.write_all(&plaintext)?;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => bail!(e),
            };
        }
        writer.flush()?;
        Ok(())
    }

    fn fetch_encryption_key(&self, pubkey: Option<x25519_dalek::PublicKey>) -> Vec<u8> {
        match self {
            PrivateKey::Aes256(key) => key.to_vec(),
            PrivateKey::Ed25519(key) => {
                //TODO: Check to determine if this would be the right method of
                //      converting E25519 to X25519
                let static_key = StaticSecret::from(key.secret.to_bytes());
                let public_key = match pubkey {
                    //Note: This may not be ideal to use one own public key for
                    //      performing a ecdh exchange. While there is no known
                    //      attack, we should still be cautious of performing
                    //      this and might be wise in the future to have dual
                    //      keys. One ed25519 and another x25519
                    Some(pubkey) => pubkey,
                    None => x25519_dalek::PublicKey::from(&static_key),
                };
                let enc_key = static_key.diffie_hellman(&public_key);
                enc_key.as_bytes().to_vec()
            }
        }
    }

    fn extract_data_slice(data: &[u8], size: usize) -> (&[u8], &[u8]) {
        let extracted = &data[data.len() - size..];
        let payload = &data[..data.len() - size];
        (extracted, payload)
    }
}
