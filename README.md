# crypto-seal

## Overview 

crypto-seal is a small utility designed to securely "package" or seal serde-compatible data type that can passed around in an uncompromised manner. 

## Usage

*Note: ED25519 is the default key type. With the AES-256 key type, signing uses HMAC-SHA256 (with a MAC key derived separately from the encryption key), which is a symmetric authenticator and is not publicly verifiable like the ED25519/secp256k1 signatures.*

```rust
use crypto_seal::{Seal, error::Error};

fn main() -> Result<(), Error> {

    let my_data = String::from("Hello, World!");

    let (my_key, sealed_data) = my_data.seal()?;

    let unsealed_data = sealed_data.open(&my_key)?;

    assert_eq!(my_data, unsealed_data);
    Ok(())
}
```

## MSRV

The minimum supported rust version is 1.74, which can be changed in the future. There is no guarantee that this library will work on older versions of rust.


## License

This crate is licensed under either Apache 2.0 or MIT. 