#[cfg(test)]
mod test {
    use crypto_seal::key::PrivateKey;
    use crypto_seal::key::PrivateKeyType;
    use crypto_seal::Package;

    #[test]
    fn default_package() -> anyhow::Result<()> {
        use crypto_seal::ToOpen;
        use crypto_seal::ToSeal;
        let my_data = String::from("Hello, World!");
        let (key, sealed_data) = my_data.seal()?;
        let unsealed_data = sealed_data.open(&key)?;
        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn default_package_ref() -> anyhow::Result<()> {
        use crypto_seal::ToOpen;
        use crypto_seal::ToSealRef;
        let my_data = String::from("Hello, World!");
        let (key, sealed_data) = my_data.seal()?;
        let unsealed_data = sealed_data.open(&key)?;
        assert_eq!(my_data, unsealed_data);
        Ok(())
    }

    #[test]
    fn package_from_to_slice() -> anyhow::Result<()> {
        use crypto_seal::ToOpen;
        use crypto_seal::ToSeal;
        let my_data = String::from("Hello, World!");
        let (key, sealed_data) = my_data.seal()?;

        let encoded_package = sealed_data.to_bytes()?;
        let decoded_package = Package::<String>::from_bytes(encoded_package)?;

        let unsealed_data = decoded_package.open(&key)?;

        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn multi_package_from_to_slice() -> anyhow::Result<()> {
        use crypto_seal::ToOpenWithPublicKey;
        use crypto_seal::ToSealRefWithSharedKey;
        let alice_pk = PrivateKey::new();

        let random_pk = (0..50).map(|_| PrivateKey::new()).collect::<Vec<_>>();

        let message = String::from("Hello Everyone!");
        let sealed_for_many = message.seal(
            &alice_pk,
            random_pk
                .iter()
                .filter_map(|p| p.public_key().ok())
                .collect(),
        )?;

        let encoded_package = sealed_for_many.to_bytes()?;
        let decoded_package = Package::<String>::from_bytes(encoded_package)?;

        for pk in &random_pk {
            let unsealed = decoded_package.open(pk)?;
            assert_eq!(String::from("Hello Everyone!"), unsealed);
        }

        Ok(())
    }

    #[test]
    fn package_with_ec25519_key() -> anyhow::Result<()> {
        use crypto_seal::ToOpen;
        use crypto_seal::ToSealWithKey;
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn package_ref_with_ec25519_key() -> anyhow::Result<()> {
        use crypto_seal::ToOpen;
        use crypto_seal::ToSealRefWithKey;
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(my_data, unsealed_data);
        Ok(())
    }

    #[test]
    fn package_with_secp256k1_key() -> anyhow::Result<()> {
        use crypto_seal::ToOpen;
        use crypto_seal::ToSealWithKey;
        let private_key = PrivateKey::new_with(PrivateKeyType::Secp256k1);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn package_ref_with_secp256k1_key() -> anyhow::Result<()> {
        use crypto_seal::ToOpen;
        use crypto_seal::ToSealRefWithKey;
        let private_key = PrivateKey::new_with(PrivateKeyType::Secp256k1);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(my_data, unsealed_data);
        Ok(())
    }

    #[test]
    fn open_with_invalid_ec25519_key() -> anyhow::Result<()> {
        use crypto_seal::ToOpen;
        use crypto_seal::ToSealRef;
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let my_data = String::from("Hello, World!");
        let (_, sealed_data) = my_data.seal()?;
        assert!(sealed_data.open(&private_key).is_err());
        Ok(())
    }

    #[test]
    fn package_with_aes256_key() -> anyhow::Result<()> {
        use crypto_seal::ToOpen;
        use crypto_seal::ToSealWithKey;
        let private_key = PrivateKey::new_with(PrivateKeyType::Aes256);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(String::from("Hello, World!"), unsealed_data);
        Ok(())
    }

    #[test]
    fn single_shared_package() -> anyhow::Result<()> {
        use crypto_seal::ToOpenWithPublicKey;
        use crypto_seal::ToSealWithSharedKey;

        let alice_pk = PrivateKey::new();
        let bob_pk = PrivateKey::new();

        let message_for_bob = String::from("Hello, Bob!");
        let sealed_for_bob = message_for_bob.seal(&alice_pk, vec![bob_pk.public_key()?])?;

        let unsealed_from_alice = sealed_for_bob.open(&bob_pk)?;
        assert_eq!(String::from("Hello, Bob!"), unsealed_from_alice);
        Ok(())
    }

    #[test]
    fn multiple_shared_package() -> anyhow::Result<()> {
        use crypto_seal::ToOpenWithPublicKey;
        use crypto_seal::ToSealRefWithSharedKey;
        let alice_pk = PrivateKey::new();
        let bob_pk = PrivateKey::new();
        let john_pk = PrivateKey::new();

        let message = String::from("Hello Everyone!");
        let sealed_for_many = message.seal(
            &alice_pk,
            vec![
                alice_pk.public_key()?,
                bob_pk.public_key()?,
                john_pk.public_key()?,
            ],
        )?;

        let unsealed_by_alice = sealed_for_many.open(&alice_pk)?;
        let unsealed_by_bob = sealed_for_many.open(&bob_pk)?;
        let unsealed_by_john = sealed_for_many.open(&john_pk)?;
        assert_eq!(String::from("Hello Everyone!"), unsealed_by_alice);
        assert_eq!(String::from("Hello Everyone!"), unsealed_by_bob);
        assert_eq!(String::from("Hello Everyone!"), unsealed_by_john);
        Ok(())
    }

    #[test]
    fn random_shared_package() -> anyhow::Result<()> {
        use crypto_seal::ToOpenWithPublicKey;
        use crypto_seal::ToSealRefWithSharedKey;
        let alice_pk = PrivateKey::new();

        let random_pk = (0..50).map(|_| PrivateKey::new()).collect::<Vec<_>>();

        let message = String::from("Hello Everyone!");
        let sealed_for_many = message.seal(
            &alice_pk,
            random_pk
                .iter()
                .filter_map(|p| p.public_key().ok())
                .collect(),
        )?;

        for pk in &random_pk {
            let unsealed = sealed_for_many.open(pk)?;
            assert_eq!(String::from("Hello Everyone!"), unsealed);
        }

        Ok(())
    }

    #[test]
    fn multiple_shared_package_secp256k1() -> anyhow::Result<()> {
        use crypto_seal::ToOpenWithPublicKey;
        use crypto_seal::ToSealRefWithSharedKey;
        let alice_pk = PrivateKey::new_with(PrivateKeyType::Secp256k1);
        let bob_pk = PrivateKey::new_with(PrivateKeyType::Secp256k1);
        let john_pk = PrivateKey::new_with(PrivateKeyType::Secp256k1);

        let message = String::from("Hello Everyone!");
        let sealed_for_many = message.seal(
            &alice_pk,
            vec![
                alice_pk.public_key()?,
                bob_pk.public_key()?,
                john_pk.public_key()?,
            ],
        )?;

        let unsealed_by_alice = sealed_for_many.open(&alice_pk)?;
        let unsealed_by_bob = sealed_for_many.open(&bob_pk)?;
        let unsealed_by_john = sealed_for_many.open(&john_pk)?;
        assert_eq!(String::from("Hello Everyone!"), unsealed_by_alice);
        assert_eq!(String::from("Hello Everyone!"), unsealed_by_bob);
        assert_eq!(String::from("Hello Everyone!"), unsealed_by_john);
        Ok(())
    }

    #[test]
    fn random_shared_package_with_secp256k1() -> anyhow::Result<()> {
        use crypto_seal::ToOpenWithPublicKey;
        use crypto_seal::ToSealRefWithSharedKey;

        let alice_pk = PrivateKey::new_with(PrivateKeyType::Secp256k1);

        let random_pk = (0..50)
            .map(|_| PrivateKey::new_with(PrivateKeyType::Secp256k1))
            .collect::<Vec<_>>();

        let message = String::from("Hello Everyone!");
        let sealed_for_many = message.seal(
            &alice_pk,
            random_pk
                .iter()
                .filter_map(|p| p.public_key().ok())
                .collect(),
        )?;

        for pk in &random_pk {
            let unsealed = sealed_for_many.open(pk)?;
            assert_eq!(String::from("Hello Everyone!"), unsealed);
        }

        Ok(())
    }
}
