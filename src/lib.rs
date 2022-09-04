pub mod error;
pub mod key;

use core::marker::PhantomData;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::error::Error;
use crate::key::{PrivateKey, PublicKey};

pub type Result<T> = std::result::Result<T, Error>;

pub trait ToSeal {
    /// Consume and encrypt a [`serde::Serialize`] compatible type and return a [`Package`] along with a generated [`PrivateKey`]
    fn seal(self) -> Result<(PrivateKey, Package<Self>)>;
}

pub trait ToSealRef {
    /// Borrow and encrypt a [`serde::Serialize`] compatible type and return a [`Package`] along with a generated [`PrivateKey`]
    fn seal(&self) -> Result<(PrivateKey, Package<Self>)>;
}

pub trait ToSealWithKey {
    /// Consume and encrypt a [`serde::Serialize`] compatible type with the supplied [`PrivateKey`] and return a [`Package`]
    fn seal(self, private_key: &PrivateKey) -> Result<Package<Self>>;
}

pub trait ToSealRefWithKey {
    /// Borrow and encrypt a [`serde::Serialize`] compatible type with the supplied [`PrivateKey`] and return a [`Package`]
    fn seal(&self, private_key: &PrivateKey) -> Result<Package<Self>>;
}

pub trait ToSealWithSharedKey {
    /// Consume and encrypt a [`serde::Serialize`] compatible type with a [`PrivateKey`] using the multiple [`PublicKey`] and return a [`Package`]
    fn seal(self, private_key: &PrivateKey, public_key: Vec<PublicKey>) -> Result<Package<Self>>;
}

pub trait ToSealRefWithSharedKey {
    /// Borrow and encrypt a [`serde::Serialize`] compatible type with a [`PrivateKey`] using the multiple [`PublicKey`] and return a [`Package`]
    fn seal(&self, private_key: &PrivateKey, public_key: Vec<PublicKey>) -> Result<Package<Self>>;
}

pub trait ToOpen<T> {
    /// Decrypts [`Package`] using [`PrivateKey`] and returns defined type
    fn open(&self, key: &PrivateKey) -> Result<T>;
}

pub trait ToOpenWithPublicKey<T> {
    /// Decrypts [`Package`] using [`PrivateKey`] and internal [`PublicKey`] and returns defined type
    fn open(&self, key: &PrivateKey) -> Result<T>;
}

pub trait ToOpenWithSharedKey<T> {
    /// Decrypts [`Package`] using [`PrivateKey`] using the recipient [`PublicKey`] and returns defined type
    fn open(&self, key: &PrivateKey, public_key: &PublicKey) -> Result<T>;
}

#[derive(Default, Deserialize, Serialize, Clone, Debug)]
pub struct Package<T: ?Sized> {
    data: Vec<Vec<u8>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    signature: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipients: Option<Vec<PublicKey>>,
    #[serde(skip_serializing, skip_deserializing)]
    marker: PhantomData<T>,
}

impl<T> Package<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    pub fn import(
        data: Vec<Vec<u8>>,
        public_key: Option<PublicKey>,
        recipients: Option<Vec<PublicKey>>,
        signature: Option<Vec<u8>>,
    ) -> Self {
        let signature = signature.unwrap_or_default();
        Self {
            data,
            signature,
            public_key,
            recipients,
            marker: PhantomData,
        }
    }

    pub fn deserialize(data: &str) -> Result<Self> {
        serde_json::from_str(data).map_err(Error::from)
    }

    pub fn serialize(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Error::from)
    }

    pub fn from_slice<A: AsRef<[u8]>>(data: A) -> Result<Self> {
        serde_json::from_slice(data.as_ref()).map_err(Error::from)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(Error::from)
    }
}

impl<T> Package<T> {
    pub fn has_recipient(&self, public_key: &PublicKey) -> bool {
        if let Some(list) = &self.recipients {
            return list.contains(public_key)
        }
        false
    }
}

impl<T> ToSeal for T
where
    T: Serialize + Default,
{
    fn seal(self) -> Result<(PrivateKey, Package<T>)> {
        ToSealRef::seal(&self)
    }
}

impl<T> ToSealRef for T
where
    T: Serialize + Default,
{
    fn seal(&self) -> Result<(PrivateKey, Package<T>)> {
        let private_key = PrivateKey::new();
        let package = ToSealRefWithKey::seal(self, &private_key)?;
        Ok((private_key, package))
    }
}

impl<T> ToSealWithKey for T
where
    T: Serialize + Default,
{
    fn seal(self, private_key: &PrivateKey) -> Result<Package<T>> {
        ToSealRefWithKey::seal(&self, private_key)
    }
}

impl<T> ToSealRefWithKey for T
where
    T: Serialize + Default,
{
    fn seal(&self, private_key: &PrivateKey) -> Result<Package<T>> {
        let mut package = Package::default();
        let inner_data = serde_json::to_vec(self)?;
        package.signature = private_key.sign(&inner_data)?;
        package.data = vec![private_key.encrypt(&inner_data, None)?];
        if let Ok(public_key) = private_key.public_key() {
            package.public_key = Some(public_key)
        }
        Ok(package)
    }
}

impl<T> ToSealWithSharedKey for T
where
    T: Serialize + Default,
{
    fn seal(self, private_key: &PrivateKey, public_key: Vec<PublicKey>) -> Result<Package<T>> {
        ToSealRefWithSharedKey::seal(&self, private_key, public_key)
    }
}

impl<T> ToSealRefWithSharedKey for T
where
    T: Serialize + Default,
{
    fn seal(&self, private_key: &PrivateKey, public_key: Vec<PublicKey>) -> Result<Package<T>> {
        let mut package = Package::default();
        let inner_data = serde_json::to_vec(self)?;
        let sig = private_key.sign(&inner_data)?;
        let ptype = private_key.public_key()?.key_type();
        package.signature = sig;
        package.data = public_key
            .iter()
            .filter(|public_key| public_key.key_type() == ptype)
            .filter_map(|public_key| {
                private_key
                    .encrypt(&inner_data, Some(public_key.clone()))
                    .ok()
            })
            .collect::<Vec<_>>();
        package.recipients = Some(public_key);
        package.public_key = Some(private_key.public_key()?);
        Ok(package)
    }
}

impl<T> ToOpen<T> for Package<T>
where
    T: DeserializeOwned,
{
    fn open(&self, key: &PrivateKey) -> Result<T> {
        let data = self.data.first().ok_or(Error::InvalidPackage)?;
        let data = key.decrypt(data, None)?;
        key.verify(&data, &self.signature)?;
        serde_json::from_slice(&data).map_err(Error::from)
    }
}

impl<T> ToOpenWithPublicKey<T> for Package<T>
where
    T: DeserializeOwned,
{
    fn open(&self, key: &PrivateKey) -> Result<T> {

        if !self.has_recipient(&key.public_key()?) {
            return Err(Error::InvalidPublickey);
        }

        let pk = self.public_key.as_ref().ok_or(Error::InvalidPublickey)?;
        for data in &self.data {
            if let Ok(data) = key.decrypt(data, Some(pk.clone())) {
                pk.verify(&data, &self.signature)?;
                return serde_json::from_slice(&data).map_err(Error::from);
            }
        }
        Err(Error::DecryptionError)
    }
}