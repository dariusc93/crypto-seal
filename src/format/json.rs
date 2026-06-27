use crate::error::Error;
use crate::format::Format;
use alloc::vec::Vec;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Json;

impl Format for Json {
    fn serialize<T: Serialize + ?Sized>(value: &T) -> crate::Result<Vec<u8>> {
        serde_json::to_vec(value).map_err(Error::from)
    }

    fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> crate::Result<T> {
        serde_json::from_slice(bytes).map_err(Error::from)
    }
}
