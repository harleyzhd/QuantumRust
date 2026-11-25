//! Rule coverage: `openssl`, built vendored. Each call line
//! names, after `// expect:`, the rules that must fire on it.
#![allow(dead_code, unused_must_use, unused_variables)]

pub fn calls() {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap(); // expect: R-OPENSSL-001
    let _aes256 = openssl::symm::Cipher::aes_256_gcm(); // expect: R-OPENSSL-002
    let _aes128 = openssl::symm::Cipher::aes_128_cbc(); // expect: R-OPENSSL-003
    let _sha256 = openssl::sha::sha256(b"m"); // expect: R-OPENSSL-004
    let _sha1 = openssl::sha::sha1(b"m"); // expect: R-OPENSSL-005
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let digest = openssl::hash::MessageDigest::sha256(); // expect: R-OPENSSL-004
    let mut signer = openssl::sign::Signer::new(digest, &pkey).unwrap(); // expect: R-OPENSSL-006
    let _sig = signer.sign_oneshot_to_vec(b"m"); // expect: R-OPENSSL-006
}
