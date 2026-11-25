//! Rule coverage: `ring`. Each call line names, after
//! `// expect:`, the rules that must fire on it.
#![allow(dead_code, unused_must_use, unused_variables)]

use ring::rand::SystemRandom;

pub fn signatures(pkcs8_rsa: &[u8], public_key: &[u8], message: &[u8], signature: &[u8]) {
    let rng = SystemRandom::new();
    let rsa = ring::signature::RsaKeyPair::from_pkcs8(pkcs8_rsa).unwrap(); // expect: R-RING-001
    let mut out = vec![0u8; rsa.public().modulus_len()];
    rsa.sign(&ring::signature::RSA_PKCS1_SHA256, &rng, message, &mut out); // expect: R-RING-001, R-RING-ALG-001
    let key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key); // expect: R-RING-002
    key.verify(message, signature); // expect: R-RING-002
    let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap(); // expect: R-RING-003
    let ed = ring::signature::Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap(); // expect: R-RING-003
    let _sig = ed.sign(message); // expect: R-RING-003
}

pub fn agreement() {
    let rng = SystemRandom::new();
    let mine = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng).unwrap(); // expect: R-RING-004
    let _public = mine.compute_public_key().unwrap(); // expect: R-RING-004
}

pub fn symmetric(key_bytes: &[u8; 32], in_out: &mut Vec<u8>) {
    let unbound = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key_bytes).unwrap(); // expect: R-RING-005, R-RING-ALG-002
    let key = ring::aead::LessSafeKey::new(unbound); // expect: R-RING-005
    let nonce = ring::aead::Nonce::assume_unique_for_key([0u8; 12]);
    key.seal_in_place_append_tag(nonce, ring::aead::Aad::empty(), in_out); // expect: R-RING-005
    let _legacy = ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &key_bytes[..16]); // expect: R-RING-005, R-RING-ALG-003
    let _digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, b"m"); // expect: R-RING-006, R-RING-ALG-003
}

/// Digests, HMAC and key derivation: each has its own rule and class, not the
/// AEAD one.
pub fn hashing(key_bytes: &[u8; 32], out: &mut [u8; 32]) {
    let mac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key_bytes); // expect: R-RING-007
    let _tag = ring::hmac::sign(&mac_key, b"m"); // expect: R-RING-007
    let _salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"salt"); // expect: R-RING-008
    let rounds = std::num::NonZeroU32::new(100_000).unwrap();
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, rounds, b"salt", b"pw", out); // expect: R-RING-008
}
