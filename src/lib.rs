#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub mod format;
pub mod key;

use core::marker::PhantomData;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::Error;
use crate::format::postcard::Postcard;
use crate::format::Format;
use crate::key::{PrivateKey, PrivateKeyType, PublicKey, PublicKeyType};

pub type Result<T> = std::result::Result<T, Error>;

fn recipients_aad(ephemeral: &PublicKey, recipients: &HashMap<PublicKey, Vec<u8>>) -> Vec<u8> {
    let mut entries = recipients
        .iter()
        .map(|(public_key, wrapped)| (public_key.encode(), wrapped))
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut aad = ephemeral.encode();
    for (key, wrapped) in entries {
        aad.extend_from_slice(&(key.len() as u64).to_le_bytes());
        aad.extend_from_slice(&key);
        aad.extend_from_slice(&(wrapped.len() as u64).to_le_bytes());
        aad.extend_from_slice(wrapped);
    }
    aad
}

fn signing_transcript(data: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(16 + data.len() + aad.len());
    transcript.extend_from_slice(&(data.len() as u64).to_le_bytes());
    transcript.extend_from_slice(data);
    transcript.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    transcript.extend_from_slice(aad);
    transcript
}

pub trait Seal: Sized {
    /// Encrypt with a freshly generated [`PrivateKey`], returning it alongside the [`Package`]
    fn seal(&self) -> Result<(PrivateKey, Package<Self>)>;

    /// Encrypt with the supplied [`PrivateKey`]
    fn seal_with(&self, private_key: &PrivateKey) -> Result<Package<Self>>;

    /// Encrypt for the given recipients using the supplied sender [`PrivateKey`]
    fn seal_shared(
        &self,
        private_key: &PrivateKey,
        recipients: Vec<PublicKey>,
    ) -> Result<Package<Self>>;
}

#[derive(Deserialize, Serialize)]
struct Signed {
    data: Vec<u8>,
    public_key: Option<PublicKey>,
    signature: Vec<u8>,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Debug)]
pub struct Package<T, F = Postcard> {
    data: Vec<u8>,
    public_key: Option<PublicKey>,
    recipients: HashMap<PublicKey, Vec<u8>>,
    #[serde(skip)]
    marker0: PhantomData<T>,
    #[serde(skip)]
    marker1: PhantomData<F>,
}

impl<T, F> Default for Package<T, F> {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            public_key: None,
            recipients: HashMap::new(),
            marker0: PhantomData,
            marker1: PhantomData,
        }
    }
}

impl<T, F> Package<T, F> {
    pub fn import(
        data: Vec<u8>,
        public_key: Option<PublicKey>,
        recipients: HashMap<PublicKey, Vec<u8>>,
    ) -> Self {
        Self {
            data,
            public_key,
            recipients,
            marker0: PhantomData,
            marker1: PhantomData,
        }
    }

    pub fn has_recipient(&self, public_key: &PublicKey) -> bool {
        self.recipients.contains_key(public_key)
    }

    pub fn recipients(&self) -> Vec<PublicKey> {
        self.recipients.keys().copied().collect::<Vec<_>>()
    }
}

impl<T, F> Package<T, F>
where
    T: Serialize,
    F: Format,
{
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        F::serialize(self)
    }
}

impl<T, F> Package<T, F>
where
    T: DeserializeOwned,
    F: Format,
{
    pub fn from_bytes<A: AsRef<[u8]>>(data: A) -> Result<Self> {
        F::deserialize(data.as_ref())
    }
}

impl<T> Seal for T
where
    T: Serialize + DeserializeOwned,
{
    fn seal(&self) -> Result<(PrivateKey, Package<T>)> {
        let private_key = PrivateKey::new();
        let package = self.seal_with(&private_key)?;
        Ok((private_key, package))
    }

    fn seal_with(&self, private_key: &PrivateKey) -> Result<Package<T>> {
        let mut package = Package::default();
        let inner = Postcard::serialize(self)?;
        let signed = Signed {
            signature: private_key.sign(&inner)?,
            public_key: None,
            data: inner,
        };
        let signed = Postcard::serialize(&signed)?;
        package.data = private_key.encrypt(&signed, Default::default())?;
        Ok(package)
    }

    fn seal_shared(
        &self,
        private_key: &PrivateKey,
        recipients: Vec<PublicKey>,
    ) -> Result<Package<T>> {
        if recipients.is_empty() {
            return Err(Error::RecipientsNotAvailable);
        }
        let mut package = Package::default();
        let sender = private_key.public_key()?;
        let ptype = sender.key_type();

        let inner = Postcard::serialize(self)?;
        let data_key: [u8; 32] = key::generate::<32>().as_slice().try_into()?;

        let ephemeral = PrivateKey::new_with(match ptype {
            PublicKeyType::Ed25519 => PrivateKeyType::Ed25519,
            PublicKeyType::Secp256k1 => PrivateKeyType::Secp256k1,
            PublicKeyType::P256 => PrivateKeyType::P256,
            PublicKeyType::P384 => PrivateKeyType::P384,
        });
        let ephemeral_pub = ephemeral.public_key()?;

        let mut public_keys = HashMap::new();
        for recipient in &recipients {
            if recipient.key_type() != ptype {
                return Err(Error::InvalidPublicKey);
            }
            let wrapped = ephemeral.encrypt(
                &data_key,
                key::CarrierKeyType::Exchange {
                    public_key: *recipient,
                },
            )?;
            public_keys.insert(*recipient, wrapped);
        }

        let aad = recipients_aad(&ephemeral_pub, &public_keys);

        let signed = Signed {
            signature: private_key.sign(signing_transcript(&inner, &aad))?,
            public_key: Some(sender),
            data: inner,
        };
        let signed = Postcard::serialize(&signed)?;

        package.data = private_key.encrypt_with_aad(
            &signed,
            key::CarrierKeyType::Direct { key: data_key },
            &aad,
        )?;
        package.recipients = public_keys;
        package.public_key = Some(ephemeral_pub);
        Ok(package)
    }
}

impl<T, F> Package<T, F>
where
    T: DeserializeOwned,
{
    pub fn open(&self, key: &PrivateKey) -> Result<T> {
        if self.recipients.is_empty() {
            let signed = key.decrypt(&self.data, Default::default())?;
            let signed: Signed = Postcard::deserialize(&signed)?;
            key.verify(&signed.data, &signed.signature)?;
            return Postcard::deserialize(&signed.data);
        }
        self.open_shared_inner(key, None)
    }

    pub fn open_shared(&self, key: &PrivateKey, sender: &PublicKey) -> Result<T> {
        self.open_shared_inner(key, Some(sender))
    }

    fn open_shared_inner(&self, key: &PrivateKey, expect: Option<&PublicKey>) -> Result<T> {
        let own_pk = key.public_key()?;
        let ephemeral = self.public_key.as_ref().ok_or(Error::InvalidPublicKey)?;

        let enc_k = self
            .recipients
            .get(&own_pk)
            .ok_or(Error::InvalidPublicKey)?;

        let data_key = key.decrypt(
            enc_k,
            key::CarrierKeyType::Exchange {
                public_key: *ephemeral,
            },
        )?;

        let aad = recipients_aad(ephemeral, &self.recipients);
        let signed = key.decrypt_with_aad(
            &self.data,
            key::CarrierKeyType::Direct {
                key: data_key.as_slice().try_into()?,
            },
            &aad,
        )?;
        let signed: Signed = Postcard::deserialize(&signed)?;

        let sender = signed.public_key.ok_or(Error::InvalidPublicKey)?;
        if let Some(expect) = expect
            && sender != *expect
        {
            return Err(Error::InvalidPublicKey);
        }
        sender.verify(&signing_transcript(&signed.data, &aad), &signed.signature)?;

        Postcard::deserialize(&signed.data)
    }
}
