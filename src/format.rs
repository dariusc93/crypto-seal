pub mod postcard;

#[cfg(feature = "json")]
#[cfg_attr(docsrs, doc(cfg(feature = "json")))]
pub mod json;

use alloc::vec::Vec;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub trait Format {
    fn serialize<T: Serialize + ?Sized>(value: &T) -> crate::Result<Vec<u8>>;
    fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> crate::Result<T>;
}
