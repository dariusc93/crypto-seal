pub mod key;
pub mod error;

use core::marker::PhantomData;
use zeroize::Zeroize;
use rand::{rngs::OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use crate::error::Error;

use crate::key::PrivateKey;

pub type Result<T> = std::result::Result<T, Error>;

pub trait ToSeal {
    fn seal(self) -> Result<(PrivateKey, Package<Self>)>;
}

pub trait ToSealRef {
    fn seal(&self) -> Result<(PrivateKey, Package<Self>)>;
}

pub trait ToOpen<T>: DeserializeOwned {
    fn open(&self, key: &PrivateKey) -> Result<T>;
}

pub trait ToSealWithKey {
    fn seal(self, private_key: &PrivateKey) -> Result<Package<Self>>;
}

pub trait ToSealRefWithKey {
    fn seal(&self, private_key: &PrivateKey) -> Result<Package<Self>>;
}

pub trait ToOpenWithKey<T>: DeserializeOwned {
    fn open(&self) -> Result<T>;
}

pub trait ToSignWithKey {
    fn sign(&mut self, key: &PrivateKey) -> Result<()>;
}

pub trait ToVerify<T> {
    fn verify(&self, key: &PrivateKey) -> Result<()>;
}

#[derive(Default, Deserialize, Serialize, Clone, Debug, Zeroize)]
pub struct Package<T: ?Sized> {
    data: Vec<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    signature: Vec<u8>,
    #[serde(skip_serializing, skip_deserializing)]
    marker: PhantomData<T>,
}

impl<T> ToString for Package<T> {
    fn to_string(&self) -> String {
        let data_hex = hex::encode(&self.data);
        let sig_hex = hex::encode(&self.signature);
        format!("{data_hex}.{sig_hex}")
    }
}

impl<T> Package<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    pub fn import(data: Vec<u8>, signature: Option<Vec<u8>>) -> Self {
        let signature = signature.unwrap_or_default();
        Self {
            data,
            signature,
            marker: PhantomData,
        }
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

impl<T> ToSignWithKey for Package<T>
{
    fn sign(&mut self, key: &PrivateKey) -> Result<()> {
        self.signature = key.sign(&self.data)?;
        Ok(())
    }
}

impl<T> ToVerify<T> for Package<T>
{
    fn verify(&self, key: &PrivateKey) -> Result<()> {
        key.verify(&self.data, &self.signature)
    }
}

pub fn generate(size: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; size];
    OsRng.fill_bytes(&mut buffer);
    buffer
}
