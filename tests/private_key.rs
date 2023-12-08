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


}