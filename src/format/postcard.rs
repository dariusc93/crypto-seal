use crate::error::Error;
use crate::format::Format;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub struct Postcard;

impl Format for Postcard {
    fn serialize<T: Serialize + ?Sized>(value: &T) -> crate::Result<Vec<u8>> {
        postcard::to_allocvec(value).map_err(Error::from)
    }

    fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> crate::Result<T> {
        postcard::from_bytes(bytes).map_err(Error::from)
    }
}
