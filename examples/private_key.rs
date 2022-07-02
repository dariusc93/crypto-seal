use crypto_seal::key::PrivateKey;
use crypto_seal::error::Error;

fn main() -> Result<(), Error> {
    let private_key = PrivateKey::new();

    let plaintext = b"Hello, World!";

    let ciphertext = private_key.encrypt(plaintext, None)?;

    let decryptedtext = private_key.decrypt(&ciphertext, None)?;

    assert_eq!(plaintext, &decryptedtext[..]);
    Ok(())
}