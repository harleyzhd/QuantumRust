//! Crate A — where key material is created.
//!
//! The taint *source* lives here and the sink lives in `signer`, so a chain
//! linking them has crossed a crate boundary rather than a function or a
//! compilation-unit one.

use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::RsaPrivateKey;

/// Build a signing key and hand it to another crate.
///
/// The key never touches a signing API here — that happens in `signer` — so
/// nothing about this function alone shows a complete chain.
pub fn make_signing_key() -> SigningKey<Sha256> {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
    SigningKey::<Sha256>::new(key)
}
