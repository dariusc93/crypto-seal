#[cfg(test)]
mod test {
    use crypto_seal::key::PrivateKey;
    use crypto_seal::key::PrivateKeyType;
    use crypto_seal::Package;

    #[test]
    fn default_package() -> anyhow::Result<()> {
        use crypto_seal::ToSeal;
        use crypto_seal::{ToOpen, ToVerify};
        let my_data = String::from("Hello, World!");
        let (key, sealed_data) = my_data.seal()?;
        sealed_data.verify()?;
        let unsealed_data = sealed_data.open(&key)?;
        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn default_package_ref() -> anyhow::Result<()> {
        use crypto_seal::ToSealRef;
        use crypto_seal::{ToOpen, ToVerify};
        let my_data = String::from("Hello, World!");
        let (key, sealed_data) = my_data.seal()?;
        sealed_data.verify()?;
        let unsealed_data = sealed_data.open(&key)?;
        assert_eq!(my_data, unsealed_data);
        Ok(())
    }


    #[test]
    fn package_encode_decode() -> anyhow::Result<()> {
        use crypto_seal::ToSeal;
        use crypto_seal::{ToOpen, ToVerify};
        let my_data = String::from("Hello, World!");
        let (key, sealed_data) = my_data.seal()?;
        sealed_data.verify()?;

        let encoded_package = sealed_data.encode()?;
        let decoded_package = Package::<String>::decode(&encoded_package)?;

        decoded_package.verify()?;
        let unsealed_data = decoded_package.open(&key)?;

        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn package_with_ec25519_key() -> anyhow::Result<()> {
        use crypto_seal::ToSealWithKey;
        use crypto_seal::{ToOpen, ToVerify};
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal(&private_key)?;
        sealed_data.verify()?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn package_ref_with_ec25519_key() -> anyhow::Result<()> {
        use crypto_seal::ToSealRefWithKey;
        use crypto_seal::{ToOpen, ToVerify};
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal(&private_key)?;
        sealed_data.verify()?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(my_data, unsealed_data);
        Ok(())
    }

    #[test]
    fn open_with_invalid_ec25519_key() -> anyhow::Result<()> {
        use crypto_seal::ToSealRef;
        use crypto_seal::{ToOpen, ToVerifyWithKey};
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
        use crypto_seal::{ToOpen, ToVerifyWithKey};
        let private_key = PrivateKey::new_with(PrivateKeyType::Aes256);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal(&private_key)?;
        sealed_data.verify(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn shared_package() -> anyhow::Result<()> {
        use crypto_seal::{ToVerify};
        use crypto_seal::ToSealWithSharedKey;
        use crypto_seal::ToOpenWithSharedKey;

        let alice_pk = PrivateKey::new();
        let bob_pk = PrivateKey::new();

        let message_for_bob = String::from("Hello, Bob!");
        let sealed_for_bob = message_for_bob.seal(&alice_pk, &bob_pk.public_key()?)?;

        sealed_for_bob.verify()?;

        let unsealed_from_alice = sealed_for_bob.open(&bob_pk, &alice_pk.public_key()?)?;
        assert_eq!(String::from("Hello, Bob!"), unsealed_from_alice);
        Ok(())
    }
}