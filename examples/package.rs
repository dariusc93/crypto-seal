use crypto_seal::{error::Error, ToOpen, ToSeal};

fn main() -> Result<(), Error> {
    let my_data = b"Hello, World!";

    let (my_key, sealed_data) = my_data.seal()?;

    let unsealed_data = sealed_data.open(&my_key)?;

    assert_eq!(b"Hello, World!", &unsealed_data);
    Ok(())
}
