pub mod postcard;

#[cfg(feature = "json")]
pub mod json;

use serde::de::DeserializeOwned;
use serde::Serialize;

pub trait Format {
    fn serialize<T: Serialize + ?Sized>(value: &T) -> crate::Result<Vec<u8>>;
    fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> crate::Result<T>;
}
