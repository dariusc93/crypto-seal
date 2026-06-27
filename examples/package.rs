use crypto_seal::{Seal, error::Error};

fn main() -> Result<(), Error> {
    let my_data = String::from("Hello, World!");

    let (my_key, sealed_data) = my_data.seal()?;

    let unsealed_data = sealed_data.open(&my_key)?;

    assert_eq!(my_data, unsealed_data);
    Ok(())
}
