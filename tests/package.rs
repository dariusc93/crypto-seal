#[cfg(test)]
mod test {
    use crypto_seal::key::PrivateKey;
    use crypto_seal::key::PrivateKeyType;
    use crypto_seal::Package;
    use crypto_seal::Seal;

    #[test]
    fn default_package() -> anyhow::Result<()> {
        let my_data = String::from("Hello, World!");
        let (key, sealed_data) = my_data.seal()?;
        let unsealed_data = sealed_data.open(&key)?;
        assert_eq!(my_data, unsealed_data);
        Ok(())
    }

    #[test]
    fn package_from_to_slice() -> anyhow::Result<()> {
        let my_data = String::from("Hello, World!");
        let (key, sealed_data) = my_data.seal()?;

        let encoded_package = sealed_data.to_bytes()?;
        let decoded_package = Package::<String>::from_bytes(encoded_package)?;

        let unsealed_data = decoded_package.open(&key)?;

        assert_eq!(my_data, unsealed_data);
        Ok(())
    }

    #[test]
    fn multi_package_from_to_slice() -> anyhow::Result<()> {
        let alice_pk = PrivateKey::new();

        let random_pk = (0..50).map(|_| PrivateKey::new()).collect::<Vec<_>>();

        let message = String::from("Hello Everyone!");
        let sealed_for_many = message.seal_shared(
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
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal_with(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(my_data, unsealed_data);
        Ok(())
    }

    #[test]
    fn package_with_secp256k1_key() -> anyhow::Result<()> {
        let private_key = PrivateKey::new_with(PrivateKeyType::Secp256k1);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal_with(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(my_data, unsealed_data);
        Ok(())
    }

    #[test]
    fn package_with_aes256_key() -> anyhow::Result<()> {
        let private_key = PrivateKey::new_with(PrivateKeyType::Aes256);
        let my_data = String::from("Hello, World!");
        let sealed_data = my_data.seal_with(&private_key)?;
        let unsealed_data = sealed_data.open(&private_key)?;
        assert_eq!(my_data, unsealed_data);
        Ok(())
    }

    #[test]
    fn open_with_invalid_ec25519_key() -> anyhow::Result<()> {
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let my_data = String::from("Hello, World!");
        let (_, sealed_data) = my_data.seal()?;
        assert!(sealed_data.open(&private_key).is_err());
        Ok(())
    }

    #[test]
    fn single_shared_package() -> anyhow::Result<()> {
        let alice_pk = PrivateKey::new();
        let bob_pk = PrivateKey::new();

        let message_for_bob = String::from("Hello, Bob!");
        let sealed_for_bob = message_for_bob.seal_shared(&alice_pk, vec![bob_pk.public_key()?])?;

        let unsealed_from_alice = sealed_for_bob.open(&bob_pk)?;
        assert_eq!(String::from("Hello, Bob!"), unsealed_from_alice);
        Ok(())
    }

    #[test]
    fn multiple_shared_package() -> anyhow::Result<()> {
        let alice_pk = PrivateKey::new();
        let bob_pk = PrivateKey::new();
        let john_pk = PrivateKey::new();

        let message = String::from("Hello Everyone!");
        let sealed_for_many = message.seal_shared(
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
    fn shared_open_with_sender() -> anyhow::Result<()> {
        let alice = PrivateKey::new();
        let bob = PrivateKey::new();
        let sealed = String::from("Hello, Bob!").seal_shared(&alice, vec![bob.public_key()?])?;
        let opened = sealed.open_shared(&bob, &alice.public_key()?)?;
        assert_eq!(String::from("Hello, Bob!"), opened);
        Ok(())
    }

    #[test]
    fn shared_open_rejects_wrong_sender() -> anyhow::Result<()> {
        let alice = PrivateKey::new();
        let bob = PrivateKey::new();
        let charlie = PrivateKey::new();
        let sealed = String::from("Hello, Bob!").seal_shared(&alice, vec![bob.public_key()?])?;
        assert!(sealed.open_shared(&bob, &charlie.public_key()?).is_err());
        Ok(())
    }

    #[test]
    fn seal_shared_rejects_mismatched_recipient_type() -> anyhow::Result<()> {
        let alice = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let bob = PrivateKey::new_with(PrivateKeyType::Secp256k1);
        let result = String::from("Hello!").seal_shared(&alice, vec![bob.public_key()?]);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn shared_seal_hides_sender() -> anyhow::Result<()> {
        let alice = PrivateKey::new();
        let bob = PrivateKey::new();
        let sealed = String::from("Hello, Bob!").seal_shared(&alice, vec![bob.public_key()?])?;
        let bytes = sealed.to_bytes()?;
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(&alice.public_key()?.to_string()));
        Ok(())
    }

    #[cfg(feature = "json")]
    #[test]
    fn shared_recipient_tampering_fails_open() -> anyhow::Result<()> {
        use crypto_seal::format::{json::Json, Format};
        let alice = PrivateKey::new();
        let bob = PrivateKey::new();
        let john = PrivateKey::new();
        let sealed = String::from("Hello!")
            .seal_shared(&alice, vec![bob.public_key()?, john.public_key()?])?;
        let mut value: serde_json::Value = serde_json::from_slice(&Json::serialize(&sealed)?)?;
        let bundle = value["recipients"]
            .as_object_mut()
            .expect("recipients");
        bundle.remove(&john.public_key()?.to_string());
        let bytes = serde_json::to_vec(&value)?;
        let tampered: Package<String> = Json::deserialize(&bytes)?;
        assert!(tampered.open(&bob).is_err());
        Ok(())
    }

    #[cfg(feature = "json")]
    #[test]
    fn tampered_ciphertext_fails_open() -> anyhow::Result<()> {
        use crypto_seal::format::{json::Json, Format};
        let key = PrivateKey::new();
        let sealed = String::from("secret").seal_with(&key)?;
        let mut value: serde_json::Value = serde_json::from_slice(&Json::serialize(&sealed)?)?;
        let byte = value["data"][0].as_u64().expect("ciphertext byte") as u8;
        value["data"][0] = serde_json::json!(byte ^ 0xff);
        let bytes = serde_json::to_vec(&value)?;
        let tampered: Package<String> = Json::deserialize(&bytes)?;
        assert!(tampered.open(&key).is_err());
        Ok(())
    }

    #[test]
    fn multiple_shared_package_secp256k1() -> anyhow::Result<()> {
        let alice_pk = PrivateKey::new_with(PrivateKeyType::Secp256k1);
        let bob_pk = PrivateKey::new_with(PrivateKeyType::Secp256k1);
        let john_pk = PrivateKey::new_with(PrivateKeyType::Secp256k1);

        let message = String::from("Hello Everyone!");
        let sealed_for_many = message.seal_shared(
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
        let alice_pk = PrivateKey::new();

        let random_pk = (0..50).map(|_| PrivateKey::new()).collect::<Vec<_>>();

        let message = String::from("Hello Everyone!");
        let sealed_for_many = message.seal_shared(
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
    fn random_shared_package_with_secp256k1() -> anyhow::Result<()> {
        let alice_pk = PrivateKey::new_with(PrivateKeyType::Secp256k1);

        let random_pk = (0..50)
            .map(|_| PrivateKey::new_with(PrivateKeyType::Secp256k1))
            .collect::<Vec<_>>();

        let message = String::from("Hello Everyone!");
        let sealed_for_many = message.seal_shared(
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
