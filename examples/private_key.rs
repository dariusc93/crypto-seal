use crypto_seal::key::PrivateKey;

fn main() -> anyhow::Result<()> {
    let private_key = PrivateKey::new();

    let plaintext = b"Hello, World!";

    let ciphertext = private_key.encrypt(plaintext, None)?;

    let decryptedtext = private_key.decrypt(&ciphertext, None)?;

    assert_eq!(plaintext, &decryptedtext[..]);
    Ok(())
}