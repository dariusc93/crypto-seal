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
    fn default_package_ref() -> anyhow::Result<()> {
        use crypto_seal::ToSealRef;
        let my_data = String::from("Hello, World!");
        let (key, sealed_data) = my_data.seal()?;
        sealed_data.verify(&key)?;
        let unsealed_data = sealed_data.open(&key)?;
        assert_eq!(my_data, unsealed_data);
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
    fn package_ref_with_ec25519_key() -> anyhow::Result<()> {
        use crypto_seal::ToSealRefWithKey;
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal(&private_key)?;
        sealed_data.verify(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(my_data, unsealed_data);
        Ok(())
    }

    #[test]
    fn open_with_invalid_ec25519_key() -> anyhow::Result<()> {
        use crypto_seal::ToSealRef;
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let private_key_1 = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let my_data = String::from("Hello, World!");
        let (_, sealed_data) = my_data.seal()?;
        assert!(sealed_data.verify(&private_key_1).is_err());
        assert!(sealed_data.open(&private_key).is_err());
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