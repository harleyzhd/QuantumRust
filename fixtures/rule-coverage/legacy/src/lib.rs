//! Rule coverage: symmetric ciphers, hashes and KDFs.
//! Each call line names, after `// expect:`, the rules that must fire on it.
#![allow(dead_code, unused_must_use)]

use aes::cipher::{BlockEncrypt, KeyInit};

pub fn block_ciphers() {
    let key16 = [0u8; 16];
    let key24 = [0u8; 24];
    let key32 = [0u8; 32];
    let _a = aes::Aes128::new(&key16.into()); // expect: R-AES-002
    let _b = aes::Aes192::new(&key24.into()); // expect: R-AES-003
    let _c = aes::Aes256::new(&key32.into()); // expect: R-AES-001
    let _d = camellia::Camellia128::new(&key16.into()); // expect: R-CAMELLIA-002
    let _d2 = camellia::Camellia192::new(&key24.into()); // expect: R-CAMELLIA-003
    let _e = camellia::Camellia256::new(&key32.into()); // expect: R-CAMELLIA-001
    let _f: Result<blowfish::Blowfish, _> = blowfish::Blowfish::new_from_slice(&key16); // expect: R-BLOWFISH-001
    let _g = des::TdesEde3::new(&key24.into()); // expect: R-3DES-001
    let _h = idea::Idea::new(&key16.into()); // expect: R-IDEA-001
    let _i = cast5::Cast5::new(&key16.into()); // expect: R-CAST5-001
    let _j = twofish::Twofish::new(&key32.into()); // expect: R-TWOFISH-001
}

/// Generic and never instantiated: only the source-level view sees the call,
/// and nothing names the cipher, so the fallback is all that can fire.
pub fn a_cipher_call_no_rule_names<C: BlockEncrypt>(cipher: &C, block: &mut aes::cipher::Block<C>) {
    cipher.encrypt_block(block); // expect: R-SYM-999
}

pub fn aeads() {
    use aes_gcm::aead::KeyInit as _;
    let _a = aes_gcm::Aes128Gcm::new(&[0u8; 16].into()); // expect: R-AES-002
    let _b = aes_gcm::Aes256Gcm::new(&[0u8; 32].into()); // expect: R-AES-001
    let _c = chacha20poly1305::ChaCha20Poly1305::new(&[0u8; 32].into()); // expect: R-CHACHA-002
}

pub fn hashes() {
    use sha2::Digest;
    let _a = sha1::Sha1::digest(b"m"); // expect: R-SHA1-001
    let _b = sha2::Sha224::digest(b"m"); // expect: R-SHA2-004
    let _c = sha2::Sha256::digest(b"m"); // expect: R-SHA2-001
    let _d = sha2::Sha384::digest(b"m"); // expect: R-SHA2-002
    let _e = sha2::Sha512::digest(b"m"); // expect: R-SHA2-003
    let _f = sha3::Sha3_224::digest(b"m"); // expect: R-SHA3-002
    let _g = sha3::Sha3_256::digest(b"m"); // expect: R-SHA3-001
    let _h = md5::Md5::digest(b"m"); // expect: R-MD5-001
    let _i = blake2::Blake2b512::digest(b"m"); // expect: R-BLAKE-001
    let _k = blake2::Blake2s256::new(); // expect: R-BLAKE-001
    let _l = blake3::hash(b"m"); // expect: R-BLAKE-002
    let _j = sha1collisiondetection::Sha1CD::default(); // expect: R-SHA1-001
}

/// Generic and never instantiated, as above, for a hash.
pub fn a_hash_call_no_rule_names<D: sha2::Digest>(message: &[u8]) {
    let _k = D::digest(message); // expect: R-HASH-999
}

pub fn kdfs() {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"pw", b"salt", 600_000, &mut out); // expect: R-PBKDF2-001
    let params = scrypt::Params::new(15, 8, 1, 32).unwrap();
    scrypt::scrypt(b"pw", b"salt", &params, &mut out); // expect: R-SCRYPT-001
    argon2::Argon2::default().hash_password_into(b"pw", b"saltsalt", &mut out); // expect: R-ARGON2-001
}
