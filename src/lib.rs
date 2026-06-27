pub mod error;
pub mod key;

use core::marker::PhantomData;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::Error;
use crate::key::{PrivateKey, PrivateKeyType, PublicKey, PublicKeyType};

pub type Result<T> = std::result::Result<T, Error>;

pub trait Format {
    fn serialize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>>;
    fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T>;
}

pub struct Postcard;

impl Format for Postcard {
    fn serialize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
        postcard::to_allocvec(value).map_err(Error::from)
    }

    fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        postcard::from_bytes(bytes).map_err(Error::from)
    }
}

#[cfg(feature = "json")]
pub struct Json;

#[cfg(feature = "json")]
impl Format for Json {
    fn serialize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
        serde_json::to_vec(value).map_err(Error::from)
    }

    fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        serde_json::from_slice(bytes).map_err(Error::from)
    }
}

#[derive(Default, Deserialize, Serialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum RecipientCarrier {
    Direct {
        public_key: PublicKey,
    },
    Bundle {
        public_keys: HashMap<PublicKey, Vec<u8>>,
    },
    #[default]
    None,
}

impl RecipientCarrier {
    fn recipients(&self) -> Vec<PublicKey> {
        match self {
            RecipientCarrier::Direct { public_key } => vec![*public_key],
            RecipientCarrier::Bundle { public_keys } => {
                public_keys.keys().copied().collect::<Vec<_>>()
            }
            RecipientCarrier::None => vec![],
        }
    }

    fn is_none(&self) -> bool {
        matches!(self, RecipientCarrier::None)
    }
}

fn recipients_aad(ephemeral: &PublicKey, recipients: &[PublicKey]) -> Vec<u8> {
    let mut keys = recipients.iter().map(PublicKey::encode).collect::<Vec<_>>();
    keys.sort();
    let mut aad = ephemeral.encode();
    for key in keys {
        aad.extend_from_slice(&key);
    }
    aad
}

pub trait Seal {
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
pub struct Package<T: ?Sized> {
    data: Vec<u8>,
    public_key: Option<PublicKey>,
    recipients: RecipientCarrier,
    #[serde(skip)]
    marker: PhantomData<T>,
}

impl<T: ?Sized> Default for Package<T> {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            public_key: None,
            recipients: RecipientCarrier::None,
            marker: PhantomData,
        }
    }
}

impl<T> Package<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    pub fn import(
        data: Vec<u8>,
        public_key: Option<PublicKey>,
        recipients: RecipientCarrier,
    ) -> Self {
        Self {
            data,
            public_key,
            recipients,
            marker: PhantomData,
        }
    }

    pub fn from_bytes<A: AsRef<[u8]>>(data: A) -> Result<Self> {
        Postcard::deserialize(data.as_ref())
    }

    pub fn from_bytes_as<F: Format, A: AsRef<[u8]>>(data: A) -> Result<Self> {
        F::deserialize(data.as_ref())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Postcard::serialize(self)
    }

    pub fn to_bytes_as<F: Format>(&self) -> Result<Vec<u8>> {
        F::serialize(self)
    }
}

impl<T> Package<T> {
    pub fn has_recipient(&self, public_key: &PublicKey) -> bool {
        let list = self.recipients();
        list.contains(public_key)
    }

    pub fn recipients(&self) -> Vec<PublicKey> {
        self.recipients.recipients()
    }
}

impl<T> Seal for T
where
    T: Serialize,
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
            public_key: private_key.public_key().ok(),
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
        let mut package = Package::default();
        let sender = private_key.public_key()?;
        let ptype = sender.key_type();

        let inner = Postcard::serialize(self)?;
        let signed = Signed {
            signature: private_key.sign(&inner)?,
            public_key: Some(sender),
            data: inner,
        };
        let signed = Postcard::serialize(&signed)?;

        let data_key: [u8; 32] = key::generate::<32>().as_slice().try_into()?;

        let ephemeral = PrivateKey::new_with(match ptype {
            PublicKeyType::Ed25519 => PrivateKeyType::Ed25519,
            PublicKeyType::Secp256k1 => PrivateKeyType::Secp256k1,
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

        let aad = recipients_aad(
            &ephemeral_pub,
            &public_keys.keys().copied().collect::<Vec<_>>(),
        );

        package.data = private_key.encrypt_with_aad(
            &signed,
            key::CarrierKeyType::Direct { key: data_key },
            &aad,
        )?;
        package.recipients = RecipientCarrier::Bundle { public_keys };
        package.public_key = Some(ephemeral_pub);
        Ok(package)
    }
}

impl<T> Package<T>
where
    T: DeserializeOwned,
{
    pub fn open(&self, key: &PrivateKey) -> Result<T> {
        if self.recipients.is_none() {
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
        if !self.has_recipient(&own_pk) {
            return Err(Error::InvalidPublicKey);
        }

        let ephemeral = self.public_key.as_ref().ok_or(Error::InvalidPublicKey)?;

        let enc_k = match &self.recipients {
            RecipientCarrier::Bundle { public_keys } => public_keys
                .get(&own_pk)
                .ok_or(Error::RecipientsNotAvailable)?,
            _ => return Err(Error::RecipientsNotAvailable),
        };

        let data_key = key.decrypt(
            enc_k,
            key::CarrierKeyType::Exchange {
                public_key: *ephemeral,
            },
        )?;

        let aad = recipients_aad(ephemeral, &self.recipients());
        let signed = key.decrypt_with_aad(
            &self.data,
            key::CarrierKeyType::Direct {
                key: data_key.as_slice().try_into()?,
            },
            &aad,
        )?;
        let signed: Signed = Postcard::deserialize(&signed)?;

        let sender = signed.public_key.ok_or(Error::InvalidPublicKey)?;
        if let Some(expect) = expect {
            if sender != *expect {
                return Err(Error::InvalidPublicKey);
            }
        }
        sender.verify(&signed.data, &signed.signature)?;

        Postcard::deserialize(&signed.data)
    }
}
