use crypto_seal::key::PrivateKey;
use crypto_seal::error::Error;

fn main() -> Result<(), Error> {
    let private_key = PrivateKey::new();

    let plaintext = b"Hello, World!";

    let ciphertext = private_key.encrypt(plaintext, Default::default())?;

    let decryptedtext = private_key.decrypt(&ciphertext, Default::default())?;

    assert_eq!(plaintext, &decryptedtext[..]);
    Ok(())
}