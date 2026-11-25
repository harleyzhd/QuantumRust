//! Crate B — where key material built in `keyring` is used.

use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::signature::{RandomizedSigner, SignatureEncoding};

/// The taint *sink*, in a different crate from the key's construction.
fn sign_detached(signing_key: &SigningKey<Sha256>, msg: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    signing_key.sign_with_rng(&mut rng, msg).to_vec()
}

fn main() {
    // The crate boundary the chain has to cross.
    let key = keyring::make_signing_key();
    let sig = sign_detached(&key, b"payload");
    println!("cross-crate signature: {} bytes", sig.len());
}
