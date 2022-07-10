#[cfg(test)]
mod test {
    use crypto_seal::key::PrivateKey;
    use crypto_seal::key::PrivateKeyType;
    use crypto_seal::Package;

    #[test]
    fn default_package() -> anyhow::Result<()> {
        use crypto_seal::ToSeal;
        use crypto_seal::{ToOpen};
        let my_data = String::from("Hello, World!");
        let (key, sealed_data) = my_data.seal()?;
        let unsealed_data = sealed_data.open(&key)?;
        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn default_package_ref() -> anyhow::Result<()> {
        use crypto_seal::ToSealRef;
        use crypto_seal::{ToOpen};
        let my_data = String::from("Hello, World!");
        let (key, sealed_data) = my_data.seal()?;
        let unsealed_data = sealed_data.open(&key)?;
        assert_eq!(my_data, unsealed_data);
        Ok(())
    }


    #[test]
    fn package_encode_decode() -> anyhow::Result<()> {
        use crypto_seal::ToSeal;
        use crypto_seal::{ToOpen};
        let my_data = String::from("Hello, World!");
        let (key, sealed_data) = my_data.seal()?;

        let encoded_package = sealed_data.encode()?;
        let decoded_package = Package::<String>::decode(&encoded_package)?;

        let unsealed_data = decoded_package.open(&key)?;

        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn package_with_ec25519_key() -> anyhow::Result<()> {
        use crypto_seal::ToSealWithKey;
        use crypto_seal::{ToOpen};
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn package_ref_with_ec25519_key() -> anyhow::Result<()> {
        use crypto_seal::ToSealRefWithKey;
        use crypto_seal::{ToOpen};
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(my_data, unsealed_data);
        Ok(())
    }

    #[test]
    fn open_with_invalid_ec25519_key() -> anyhow::Result<()> {
        use crypto_seal::ToSealRef;
        use crypto_seal::{ToOpen};
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let my_data = String::from("Hello, World!");
        let (_, sealed_data) = my_data.seal()?;
        assert!(sealed_data.open(&private_key).is_err());
        Ok(())
    }

    #[test]
    fn package_with_aes256_key() -> anyhow::Result<()> {
        use crypto_seal::ToSealWithKey;
        use crypto_seal::{ToOpen};
        let private_key = PrivateKey::new_with(PrivateKeyType::Aes256);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn shared_package() -> anyhow::Result<()> {
        use crypto_seal::ToSealWithSharedKey;
        use crypto_seal::ToOpenWithPublicKey;

        let alice_pk = PrivateKey::new();
        let bob_pk = PrivateKey::new();

        let message_for_bob = String::from("Hello, Bob!");
        let sealed_for_bob = message_for_bob.seal(&alice_pk, &bob_pk.public_key()?)?;

        let unsealed_from_alice = sealed_for_bob.open(&bob_pk)?;
        assert_eq!(String::from("Hello, Bob!"), unsealed_from_alice);
        Ok(())
    }

    #[test]
    fn multiple_shared_package() -> anyhow::Result<()> {
        use crypto_seal::ToSealRefWithMultiSharedKey;
        use crypto_seal::ToOpenWithPublicKey;
        let alice_pk = PrivateKey::new();
        let bob_pk = PrivateKey::new();
        let john_pk = PrivateKey::new();

        let message = String::from("Hello Everyone!");
        let sealed_for_many = message.seal(&alice_pk, vec![alice_pk.public_key()?, bob_pk.public_key()?, john_pk.public_key()?])?;

        let unsealed_by_alice = sealed_for_many.open(&alice_pk)?;
        let unsealed_by_bob = sealed_for_many.open(&bob_pk)?;
        let unsealed_by_john = sealed_for_many.open(&john_pk)?;
        assert_eq!(String::from("Hello Everyone!"), unsealed_by_alice);
        assert_eq!(String::from("Hello Everyone!"), unsealed_by_bob);
        assert_eq!(String::from("Hello Everyone!"), unsealed_by_john);
        Ok(())
    }
}