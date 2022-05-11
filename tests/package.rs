#[cfg(test)]
mod test {
    use crypto_seal::{ToOpen, ToVerify, key::PrivateKey};
    use crypto_seal::key::PrivateKeyType;

    #[test]
    fn default_package() -> anyhow::Result<()> {
        use crypto_seal::ToSeal;
        let my_data = String::from("Hello, World!");
        let (key, sealed_data) = my_data.seal()?;
        sealed_data.verify(&key)?;
        let unsealed_data = sealed_data.open(&key)?;
        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn package_with_ec25519_key() -> anyhow::Result<()> {
        use crypto_seal::ToSealWithKey;
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal(&private_key)?;
        sealed_data.verify(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn package_with_aes256_key() -> anyhow::Result<()> {
        use crypto_seal::ToSealWithKey;
        let private_key = PrivateKey::new_with(PrivateKeyType::Aes256);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal(&private_key)?;
        sealed_data.verify(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

}