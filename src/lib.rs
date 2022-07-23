pub mod error;
pub mod key;

use core::marker::PhantomData;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::Zeroize;

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

#[derive(Default, Deserialize, Serialize, Clone, Debug, Zeroize)]
pub struct Package<T: ?Sized> {
    data: Vec<Vec<u8>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    signature: Vec<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    public_key: Vec<u8>,
    #[serde(skip_serializing, skip_deserializing)]
    marker: PhantomData<T>,
}

impl<T> Package<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    pub fn import(
        data: Vec<Vec<u8>>,
        public_key: Option<Vec<u8>>,
        signature: Option<Vec<u8>>,
    ) -> Self {
        let signature = signature.unwrap_or_default();
        let public_key = public_key.unwrap_or_default();
        Self {
            data,
            signature,
            public_key,
            marker: PhantomData,
        }
    }

    pub fn decode(data: &str) -> Result<Self> {
        let entry: Vec<_> = data.split('.').collect();
        let (data, sig, pk) = match (entry.get(0), entry.get(1), entry.get(2)) {
            (Some(data), None, None) => {
                if data.is_empty() {
                    return Err(Error::InvalidPackage);
                }
                let step_1_decode = bs58::decode(data)
                    .into_vec()
                    .map(|s| String::from_utf8_lossy(&s).to_string())?;
                let decoded_data = step_1_decode
                    .split('/')
                    .into_iter()
                    .filter_map(|data| bs58::decode(data).into_vec().ok())
                    .collect();
                (decoded_data, None, None)
            }
            (Some(data), Some(sig), None) => {
                let step_1_decode = bs58::decode(data)
                    .into_vec()
                    .map(|s| String::from_utf8_lossy(&s).to_string())?;
                let decoded_data = step_1_decode
                    .split('/')
                    .into_iter()
                    .filter_map(|data| bs58::decode(data).into_vec().ok())
                    .collect();
                let decoded_sig = bs58::decode(sig).into_vec()?;
                (decoded_data, Some(decoded_sig), None)
            }
            (Some(data), Some(sig), Some(pk)) => {
                let step_1_decode = bs58::decode(data)
                    .into_vec()
                    .map(|s| String::from_utf8_lossy(&s).to_string())?;
                let decoded_data = step_1_decode
                    .split('/')
                    .into_iter()
                    .filter_map(|data| bs58::decode(data).into_vec().ok())
                    .collect();
                let decoded_sig = bs58::decode(sig).into_vec()?;
                let decoded_pk = bs58::decode(pk).into_vec()?;
                (decoded_data, Some(decoded_sig), Some(decoded_pk))
            }
            _ => return Err(Error::InvalidPackage),
        };
        Ok(Self::import(data, pk, sig))
    }

    pub fn encode(&self) -> Result<String> {
        let data = bs58::encode(
            self.data
                .iter()
                .map(|data| bs58::encode(data).into_string())
                .collect::<Vec<_>>()
                .join("/"),
        )
        .into_string();
        let encoded_data = match (self.signature.is_empty(), self.public_key.is_empty()) {
            (false, false) => {
                let sig = bs58::encode(&self.signature).into_string();
                let pk = bs58::encode(&self.public_key).into_string();
                format!("{data}.{sig}.{pk}")
            }
            (false, true) => {
                let sig = bs58::encode(&self.signature).into_string();
                format!("{data}.{sig}")
            }
            _ => return Err(Error::InvalidPackage),
        };

        Ok(encoded_data)
    }
}

impl<T> ToSeal for T
where
    T: Serialize + Default,
{
    fn seal(self) -> Result<(PrivateKey, Package<T>)> {
        let private_key = PrivateKey::new();
        let mut package = Package::default();
        let inner_data = serde_json::to_vec(&self)?;
        package.signature = private_key.sign(&inner_data)?;
        package.data = vec![private_key.encrypt(&inner_data, None)?];
        if let Ok(public_key) = private_key.public_key() {
            package.public_key = public_key.encode();
        }
        Ok((private_key, package))
    }
}

impl<T> ToSealRef for T
where
    T: Serialize + Default,
{
    fn seal(&self) -> Result<(PrivateKey, Package<T>)> {
        let private_key = PrivateKey::new();
        let mut package = Package::default();
        let inner_data = serde_json::to_vec(&self)?;
        package.signature = private_key.sign(&inner_data)?;
        package.data = vec![private_key.encrypt(&inner_data, None)?];
        if let Ok(public_key) = private_key.public_key() {
            package.public_key = public_key.encode();
        }
        Ok((private_key, package))
    }
}

impl<T> ToSealWithKey for T
where
    T: Serialize + Default,
{
    fn seal(self, private_key: &PrivateKey) -> Result<Package<T>> {
        let mut package = Package::default();
        let inner_data = serde_json::to_vec(&self)?;
        package.signature = private_key.sign(&inner_data)?;
        package.data = vec![private_key.encrypt(&inner_data, None)?];
        if let Ok(public_key) = private_key.public_key() {
            package.public_key = public_key.encode();
        }
        Ok(package)
    }
}

impl<T> ToSealRefWithKey for T
where
    T: Serialize + Default,
{
    fn seal(&self, private_key: &PrivateKey) -> Result<Package<T>> {
        let mut package = Package::default();
        let inner_data = serde_json::to_vec(&self)?;
        package.signature = private_key.sign(&inner_data)?;
        package.data = vec![private_key.encrypt(&inner_data, None)?];
        if let Ok(public_key) = private_key.public_key() {
            package.public_key = public_key.encode();
        }
        Ok(package)
    }
}

impl<T> ToSealWithSharedKey for T
where
    T: Serialize + Default,
{
    fn seal(self, private_key: &PrivateKey, public_key: Vec<PublicKey>) -> Result<Package<T>> {
        let mut package = Package::default();
        let inner_data = serde_json::to_vec(&self)?;
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
        package.public_key = private_key.public_key()?.encode();
        Ok(package)
    }
}

impl<T> ToSealRefWithSharedKey for T
where
    T: Serialize + Default,
{
    fn seal(&self, private_key: &PrivateKey, public_key: Vec<PublicKey>) -> Result<Package<T>> {
        let mut package = Package::default();
        let inner_data = serde_json::to_vec(&self)?;
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
        package.public_key = private_key.public_key()?.encode();
        Ok(package)
    }
}

impl<T> ToOpen<T> for Package<T>
where
    T: DeserializeOwned,
{
    fn open(&self, key: &PrivateKey) -> Result<T> {
        let data = self.data.get(0).cloned().ok_or(Error::InvalidPackage)?;
        let data = key.decrypt(&data, None)?;
        key.verify(&data, &self.signature)?;
        serde_json::from_slice(&data).map_err(Error::from)
    }
}

impl<T> ToOpenWithPublicKey<T> for Package<T>
where
    T: DeserializeOwned,
{
    fn open(&self, key: &PrivateKey) -> Result<T> {
        let pk = PublicKey::decode(&self.public_key)?;
        for data in &self.data {
            if let Ok(data) = key.decrypt(data, Some(pk.clone())) {
                pk.verify(&data, &self.signature)?;
                return serde_json::from_slice(&data).map_err(Error::from);
            }
        }
        Err(Error::DecryptionError)
    }
}

impl<T> ToOpenWithSharedKey<T> for Package<T>
where
    T: DeserializeOwned,
{
    fn open(&self, key: &PrivateKey, public_key: &PublicKey) -> Result<T> {
        // Since this should be used in the event the public_key field is empty, we will make it so it will return an error if it exist
        // TODO: return specific/correct error
        if key.public_key()?.key_type() != public_key.key_type() {
            return Err(Error::InvalidPublickey);
        }
        if self.public_key.is_empty() {
            for data in &self.data {
                if let Ok(data) = key.decrypt(data, Some(public_key.clone())) {
                    let pk = PublicKey::decode(&self.public_key)?;
                    pk.verify(&data, &self.signature)?;
                    return serde_json::from_slice(&data).map_err(Error::from);
                }
            }
        }
        Err(Error::DecryptionError)
    }
}
