use crypto_seal::{ToOpen, ToSeal, ToVerify, error::Error};

fn main() -> Result<(), Error> {

    let my_data = b"Hello, World!";

    let (my_key, sealed_data) = my_data.seal()?;

    sealed_data.verify(&my_key)?;

    let unsealed_data = sealed_data.open(&my_key)?;

    assert_eq!(b"Hello, World!", &unsealed_data);
    Ok(())
}