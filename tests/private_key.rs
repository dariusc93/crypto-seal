#[cfg(test)]
mod test {
    use crypto_seal::key::PrivateKey;
    use crypto_seal::key::PrivateKeyType;

    #[test]
    fn aes256_encryption() -> anyhow::Result<()> {
        let private_key = PrivateKey::new_with(PrivateKeyType::Aes256);

        let plaintext = b"Hello, World!";

        let ciphertext = private_key.encrypt(plaintext, Default::default())?;

        let decryptedtext = private_key.decrypt(&ciphertext, Default::default())?;

        assert_eq!(plaintext, &decryptedtext[..]);
        Ok(())
    }

    #[test]
    fn ed25519_encryption() -> anyhow::Result<()> {
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);

        let plaintext = b"Hello, World!";

        let ciphertext = private_key.encrypt(plaintext, Default::default())?;

        let decryptedtext = private_key.decrypt(&ciphertext, Default::default())?;

        assert_eq!(plaintext, &decryptedtext[..]);
        Ok(())
    }

    #[test]
    fn secp256k1_encryption() -> anyhow::Result<()> {
        let private_key = PrivateKey::new_with(PrivateKeyType::Secp256k1);

        let plaintext = b"Hello, World!";

        let ciphertext = private_key.encrypt(plaintext, Default::default())?;

        let decryptedtext = private_key.decrypt(&ciphertext, Default::default())?;

        assert_eq!(plaintext, &decryptedtext[..]);
        Ok(())
    }

    #[test]
    fn encrypt_tamper_fails() -> anyhow::Result<()> {
        for key_type in [
            PrivateKeyType::Ed25519,
            PrivateKeyType::Secp256k1,
            PrivateKeyType::P256,
            PrivateKeyType::P384,
            PrivateKeyType::Aes256,
        ] {
            let key = PrivateKey::new_with(key_type);
            let base = key.encrypt(b"secret", Default::default())?;
            for pos in [0, base.len() - 13, base.len() - 1] {
                let mut tampered = base.clone();
                tampered[pos] ^= 0xff;
                assert!(key.decrypt(&tampered, Default::default()).is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn aes256_sign() -> anyhow::Result<()> {
        let private_key = PrivateKey::new_with(PrivateKeyType::Aes256);
        let plaintext = b"Hello, World!";
        let signature = private_key.sign(plaintext)?;
        assert!(private_key.verify(plaintext, &signature).is_ok());
        assert!(private_key.verify(b"tampered", &signature).is_err());
        Ok(())
    }

    #[test]
    fn stream_roundtrip() -> anyhow::Result<()> {
        use std::io::Cursor;
        for key_type in [
            PrivateKeyType::Ed25519,
            PrivateKeyType::Secp256k1,
            PrivateKeyType::P256,
            PrivateKeyType::P384,
            PrivateKeyType::Aes256,
        ] {
            let key = PrivateKey::new_with(key_type);
            let plaintext = vec![7u8; 5000];
            let mut ciphertext = Vec::new();
            key.encrypt_stream(
                &mut Cursor::new(&plaintext),
                &mut ciphertext,
                Default::default(),
            )?;
            let mut decrypted = Vec::new();
            key.decrypt_stream(
                &mut Cursor::new(&ciphertext),
                &mut decrypted,
                Default::default(),
            )?;
            assert_eq!(plaintext, decrypted);
        }
        Ok(())
    }

    #[test]
    fn ed25519_sign() -> anyhow::Result<()> {
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);

        let plaintext = b"Hello, World!";

        let signature = private_key.sign(plaintext)?;

        assert!(private_key.verify(plaintext, &signature).is_ok());
        Ok(())
    }

    #[test]
    fn secp256k1_sign() -> anyhow::Result<()> {
        let private_key = PrivateKey::new_with(PrivateKeyType::Secp256k1);

        let plaintext = b"Hello, World!";

        let signature = private_key.sign(plaintext)?;

        assert!(private_key.verify(plaintext, &signature).is_ok());

        Ok(())
    }

    #[test]
    fn p256_sign() -> anyhow::Result<()> {
        let private_key = PrivateKey::new_with(PrivateKeyType::P256);
        let plaintext = b"Hello, World!";
        let signature = private_key.sign(plaintext)?;
        assert!(private_key.verify(plaintext, &signature).is_ok());
        Ok(())
    }

    #[test]
    fn p384_sign() -> anyhow::Result<()> {
        let private_key = PrivateKey::new_with(PrivateKeyType::P384);
        let plaintext = b"Hello, World!";
        let signature = private_key.sign(plaintext)?;
        assert!(private_key.verify(plaintext, &signature).is_ok());
        Ok(())
    }

    #[test]
    fn decrypt_short_input_errors() -> anyhow::Result<()> {
        let private_key = PrivateKey::new_with(PrivateKeyType::Aes256);
        assert!(private_key.decrypt(&[], Default::default()).is_err());
        assert!(private_key.decrypt(&[0u8; 4], Default::default()).is_err());
        Ok(())
    }

    #[test]
    fn private_key_encode_decode_roundtrip() -> anyhow::Result<()> {
        for key_type in [
            PrivateKeyType::Ed25519,
            PrivateKeyType::Secp256k1,
            PrivateKeyType::P256,
            PrivateKeyType::P384,
            PrivateKeyType::Aes256,
        ] {
            let private_key = PrivateKey::new_with(key_type);
            let decoded = PrivateKey::decode(private_key.encode())?;
            assert_eq!(private_key.encode(), decoded.encode());
        }
        Ok(())
    }

    #[test]
    fn ed25519_sign_reader() -> anyhow::Result<()> {
        let private_key = PrivateKey::new_with(PrivateKeyType::Ed25519);
        let data = b"Hello, World!";
        let signature = private_key.sign_reader(&mut &data[..])?;
        assert!(private_key
            .verify_reader(&mut &data[..], &signature)
            .is_ok());
        Ok(())
    }

    #[test]
    fn secp256k1_sign_reader() -> anyhow::Result<()> {
        let private_key = PrivateKey::new_with(PrivateKeyType::Secp256k1);
        let data = b"Hello, World!";
        let signature = private_key.sign_reader(&mut &data[..])?;
        assert!(private_key
            .verify_reader(&mut &data[..], &signature)
            .is_ok());
        Ok(())
    }
}
