pub mod error;
pub mod key;

use core::marker::PhantomData;
use rand::{rngs::OsRng, RngCore};
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
    /// Consume and encrypt a [`serde::Serialize`] compatible type with a [`PrivateKey`] using the recipient [`PublicKey`] and return a [`Package`]
    fn seal(self, private_key: &PrivateKey, public_key: &PublicKey) -> Result<Package<Self>>;
}

pub trait ToSealRefWithSharedKey {
    /// Borrow and encrypt a [`serde::Serialize`] compatible type with a [`PrivateKey`] using the recipient [`PublicKey`] and return a [`Package`]
    fn seal(&self, private_key: &PrivateKey, public_key: &PublicKey) -> Result<Package<Self>>;
}

pub trait ToOpen<T>: DeserializeOwned {
    /// Decrypts [`Package`] using [`PrivateKey`] and returns defined type
    fn open(&self, key: &PrivateKey) -> Result<T>;
}

pub trait ToOpenWithSharedKey<T>: DeserializeOwned {
    /// Decrypts [`Package`] using [`PrivateKey`] using the recipient [`PublicKey`] and returns defined type
    fn open(&self, key: &PrivateKey, public_key: &PublicKey) -> Result<T>;
}

pub trait ToSignWithKey {
    /// Sign the [`Package`] with [`PrivateKey`]
    fn sign(&mut self, key: &PrivateKey) -> Result<()>;
}

pub trait ToVerify<T> {
    /// Verify the [`Package`] with embedded [`PublicKey`]
    fn verify(&self) -> Result<()>;
}

pub trait ToVerifyWithKey<T> {
    /// Verify the [`Package`] with [`PrivateKey`]
    fn verify(&self, key: &PrivateKey) -> Result<()>;
}

#[derive(Default, Deserialize, Serialize, Clone, Debug, Zeroize)]
pub struct Package<T: ?Sized> {
    data: Vec<u8>,
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
    pub fn import(data: Vec<u8>, public_key: Option<Vec<u8>>, signature: Option<Vec<u8>>) -> Self {
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
                if data.is_empty() { return Err(Error::InvalidPackage) }
                let decoded_data = bs58::decode(data).into_vec()?;
                (decoded_data, None, None)
            },
            (Some(data), Some(sig), None) => {
                let decoded_data = bs58::decode(data).into_vec()?;
                let decoded_sig = bs58::decode(sig).into_vec()?;
                (decoded_data, Some(decoded_sig), None)
            },
            (Some(data), Some(sig), Some(pk)) => {
                let decoded_data = bs58::decode(data).into_vec()?;
                let decoded_sig = bs58::decode(sig).into_vec()?;
                let decoded_pk = bs58::decode(pk).into_vec()?;
                (decoded_data, Some(decoded_sig), Some(decoded_pk))
            },
            _ => return Err(Error::InvalidPackage)
        };
        Ok(Self::import(data, pk, sig))
    }

    pub fn encode(&self) -> Result<String> {
        let data = bs58::encode(&self.data).into_string();
        let encoded_data = match (self.signature.is_empty(), self.public_key.is_empty()) {
            (false, false) => {
                let sig = bs58::encode(&self.signature).into_string();
                let pk = bs58::encode(&self.public_key).into_string();
                format!("{data}.{sig}.{pk}")
            },
            (false, true) => {
                let sig = bs58::encode(&self.signature).into_string();
                format!("{data}.{sig}")
            },
            _ => {
                return Err(Error::InvalidPackage)
            }
        };

        Ok(encoded_data)
    }
}

impl<T> ToSeal for T
where
    T: Serialize + DeserializeOwned + Default + Sized,
{
    fn seal(self) -> Result<(PrivateKey, Package<T>)> {
        let private_key = PrivateKey::new();
        let mut package = Package::default();
        let inner_data = serde_json::to_vec(&self)?;
        package.data = private_key.encrypt(&inner_data, None)?;
        let sig = private_key.sign(&package.data)?;
        package.signature = sig;
        if let Ok(public_key) = private_key.public_key() {
            package.public_key = public_key.to_bytes();
        }
        Ok((private_key, package))
    }
}

impl<T> ToSealRef for T
where
    T: Serialize + DeserializeOwned + Default + Sized,
{
    fn seal(&self) -> Result<(PrivateKey, Package<T>)> {
        let private_key = PrivateKey::new();
        let mut package = Package::default();
        let inner_data = serde_json::to_vec(&self)?;
        package.data = private_key.encrypt(&inner_data, None)?;
        let sig = private_key.sign(&package.data)?;
        package.signature = sig;
        if let Ok(public_key) = private_key.public_key() {
            package.public_key = public_key.to_bytes();
        }
        Ok((private_key, package))
    }
}

impl<T> ToSealWithKey for T
where
    T: Serialize + Default + Sized,
{
    fn seal(self, private_key: &PrivateKey) -> Result<Package<T>> {
        let mut package = Package::default();
        let inner_data = serde_json::to_vec(&self)?;
        package.data = private_key.encrypt(&inner_data, None)?;
        let sig = private_key.sign(&package.data)?;
        package.signature = sig;
        if let Ok(public_key) = private_key.public_key() {
            package.public_key = public_key.to_bytes();
        }
        Ok(package)
    }
}

impl<T> ToSealRefWithKey for T
where
    T: Serialize + Default + Sized,
{
    fn seal(&self, private_key: &PrivateKey) -> Result<Package<T>> {
        let mut package = Package::default();
        let inner_data = serde_json::to_vec(&self)?;
        package.data = private_key.encrypt(&inner_data, None)?;
        let sig = private_key.sign(&package.data)?;
        package.signature = sig;
        if let Ok(public_key) = private_key.public_key() {
            package.public_key = public_key.to_bytes();
        }
        Ok(package)
    }
}

impl<T> ToSealWithSharedKey for T
where
    T: Serialize + Default + Sized,
{
    fn seal(self, private_key: &PrivateKey, public_key: &PublicKey) -> Result<Package<T>> {
        let mut package = Package::default();
        let inner_data = serde_json::to_vec(&self)?;
        package.data = private_key.encrypt(&inner_data, Some(public_key.clone()))?;
        let sig = private_key.sign(&package.data)?;
        package.signature = sig;
        package.public_key = private_key.public_key()?.to_bytes();
        Ok(package)
    }
}

impl<T> ToSealRefWithSharedKey for T
where
    T: Serialize + Default + Sized,
{
    fn seal(&self, private_key: &PrivateKey, public_key: &PublicKey) -> Result<Package<T>> {
        let mut package = Package::default();
        let inner_data = serde_json::to_vec(&self)?;
        package.data = private_key.encrypt(&inner_data, Some(public_key.clone()))?;
        let sig = private_key.sign(&package.data)?;
        package.signature = sig;
        package.public_key = private_key.public_key()?.to_bytes();
        Ok(package)
    }
}

impl<T> ToOpen<T> for Package<T>
where
    T: DeserializeOwned,
{
    fn open(&self, key: &PrivateKey) -> Result<T> {
        key.verify(&self.data, &self.signature)?;
        key.decrypt(&self.data, None)
            .and_then(|ptext| serde_json::from_slice(&ptext[..]).map_err(Error::from))
    }
}

impl<T> ToOpenWithSharedKey<T> for Package<T>
where
    T: DeserializeOwned,
{
    fn open(&self, key: &PrivateKey, public_key: &PublicKey) -> Result<T> {
        ToVerify::<T>::verify(self)?;
        key.decrypt(&self.data, Some(public_key.clone()))
            .and_then(|ptext| serde_json::from_slice(&ptext[..]).map_err(Error::from))
    }
}

impl<T> ToSignWithKey for Package<T> {
    fn sign(&mut self, key: &PrivateKey) -> Result<()> {
        self.signature = key.sign(&self.data)?;
        self.public_key = key.public_key()?.to_bytes();
        Ok(())
    }
}

impl<T> ToVerify<T> for Package<T> {
    fn verify(&self) -> Result<()> {
        let pk = PublicKey::from_bytes(&self.public_key)?;
        pk.verify(&self.data, &self.signature)
    }
}

impl<T> ToVerifyWithKey<T> for Package<T> {
    fn verify(&self, key: &PrivateKey) -> Result<()> {
        key.verify(&self.data, &self.signature)
    }
}

pub fn generate(size: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; size];
    OsRng.fill_bytes(&mut buffer);
    buffer
}
