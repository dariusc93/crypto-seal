# crypto-seal

## Overview 

crypto-seal is a small utility designed to securely "package" or seal serde-compatible data type that can passed around in an uncompromised manner. 

## Usage

*Note: ED25519 is used by default for encryption and signing. If AES256-GCM is used, signing will only supply an encrypted SHA512 hash using the key. This will be replaced in the future as this may not be a desirable option*

```rust
use crypto_seal::{ToOpen, ToSeal, error::Error};

fn main() -> Result<(), Error> {

    let my_data = b"Hello, World!";

    let (my_key, sealed_data) = my_data.seal()?;

    let unsealed_data = sealed_data.open(&my_key)?;

    assert_eq!(b"Hello, World!", &unsealed_data);
    Ok(())
}
```

## MSRV

The minimum supported rust version is 1.60, which can be changed in the future. There is no guarantee that this library will work on older versions of rust.


## License

This crate is licensed under either Apache 2.0 or MIT. 