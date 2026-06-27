use crypto_seal::{Package, Seal, error::Error, key::PrivateKey};

fn main() -> Result<(), Error> {
    let alice = PrivateKey::new();
    let bob = PrivateKey::new();
    let john = PrivateKey::new();

    let message = String::from("Hello, Bob and John!");
    let sealed = message.seal_shared(&alice, vec![bob.public_key()?, john.public_key()?])?;

    let bytes = sealed.to_bytes()?;
    let received = Package::<String>::from_bytes(bytes)?;

    let by_bob = received.open_shared(&bob, &alice.public_key()?)?;
    let by_john = received.open_shared(&john, &alice.public_key()?)?;

    assert_eq!(message, by_bob);
    assert_eq!(message, by_john);
    Ok(())
}
