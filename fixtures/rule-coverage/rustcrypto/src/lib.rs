//! Rule coverage: public-key algorithms through RustCrypto. Each call line
//! names, after `// expect:`, the rules that must fire.
#![allow(dead_code, unused_must_use, unused_variables)]

use rand_core::OsRng;
use sha2::Digest;

pub fn rsa_calls() {
    use rsa::signature::{Keypair, RandomizedSigner, Signer};
    use rsa::{pkcs1v15, pss, Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey};
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 2048).unwrap(); // expect: R-RSA-001
    let public = key.to_public_key(); // expect: R-RSA-001
    let ct = public.encrypt(&mut rng, Pkcs1v15Encrypt, b"m").unwrap(); // expect: R-RSA-004
    let _pt = key.decrypt(Pkcs1v15Encrypt, &ct).unwrap(); // expect: R-RSA-004
    let hashed = sha2::Sha256::digest(b"m");
    let scheme = Pkcs1v15Sign::new::<sha2::Sha256>(); // expect: R-RSA-005
    let sig = key.sign(scheme, &hashed).unwrap(); // expect: R-RSA-002
    let scheme = Pkcs1v15Sign::new::<sha2::Sha256>(); // expect: R-RSA-005
    public.verify(scheme, &hashed, &sig); // expect: R-RSA-003
    let signer = pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone()); // expect: R-RSA-005
    let _s = signer.sign(b"m"); // expect: R-RSA-002
    let _vk = signer.verifying_key(); // expect: R-RSA-007
    let pss_signer = pss::SigningKey::<sha2::Sha256>::new(key.clone()); // expect: R-RSA-006
    let _p = pss_signer.sign_with_rng(&mut rng, b"m"); // expect: R-RSA-002
    let _pvk = pss_signer.verifying_key(); // expect: R-RSA-008
    key.validate(); // expect: R-RSA-999
}

pub fn ecdsa_and_ecdh_calls() {
    use p256::ecdsa::signature::{Signer, Verifier};
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    let sk = SigningKey::random(&mut OsRng); // expect: R-ECDSA-001
    let sig: Signature = sk.sign(b"m"); // expect: R-ECDSA-002
    let vk = VerifyingKey::from(&sk); // expect: R-ECDSA-004
    vk.verify(b"m", &sig); // expect: R-ECDSA-003
    let secret = p384::SecretKey::random(&mut OsRng); // expect: R-ECDSA-001
    let _public = secret.public_key(); // expect: R-EC-999
    let eph = p256::ecdh::EphemeralSecret::random(&mut OsRng); // expect: R-ECDH-001
    let eph_public = eph.public_key(); // expect: R-ECDH-001
    let _shared = eph.diffie_hellman(&eph_public); // expect: R-ECDH-001
}

pub fn ed25519_and_x25519_calls() {
    use ed25519_dalek::{Signer, Verifier};
    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng); // expect: R-ED25519-001
    let sig = sk.sign(b"m"); // expect: R-ED25519-002
    let vk = sk.verifying_key(); // expect: R-ED25519-001
    vk.verify(b"m", &sig); // expect: R-ED25519-003
    let _vk2 = ed25519_dalek::VerifyingKey::from(&sk); // expect: R-ED25519-004
    let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng); // expect: R-X25519-001
    let public = x25519_dalek::PublicKey::from(&secret); // expect: R-X25519-999
    let _shared = secret.diffie_hellman(&public); // expect: R-X25519-002
}

pub fn ed448_and_x448_calls() {
    let sk = cx448::SigningKey::generate(&mut OsRng); // expect: R-ED448-001
    let vk = sk.verifying_key(); // expect: R-ED448-001
    let sig = sk.sign_raw(b"m"); // expect: R-ED448-001
    vk.verify_raw(&sig, b"m"); // expect: R-ED448-001
    let secret = cx448::x448::Secret::new(&mut OsRng); // expect: R-X448-001
    let public = cx448::x448::PublicKey::from(&secret); // expect: R-X448-001
    let _shared = secret.as_diffie_hellman(&public); // expect: R-X448-001
}

pub fn dsa_calls() {
    use dsa::signature::hazmat::PrehashSigner;
    let components = dsa::Components::generate(&mut OsRng, dsa::KeySize::DSA_2048_256); // expect: R-DSA-001
    let sk = dsa::SigningKey::generate(&mut OsRng, components); // expect: R-DSA-001
    let sig: dsa::Signature = sk.sign_prehash(&[0u8; 32]).unwrap(); // expect: R-DSA-001
    let _again = dsa::Signature::try_from(&b"not a signature"[..]); // expect: R-DSA-002
    let _vk = sk.verifying_key(); // expect: R-DSA-001
}

pub fn post_quantum_calls() {
    use ml_kem::kem::{Decapsulate, Encapsulate};
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng); // expect: R-MLKEM-001
    let (ct, _k) = ek.encapsulate(&mut rng).unwrap(); // expect: R-MLKEM-001
    let _k2 = dk.decapsulate(&ct).unwrap(); // expect: R-MLKEM-001
    let _ek2 = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek.as_bytes()); // expect: R-PQC-999

    use ml_dsa::signature::Signer as _;
    let keypair = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&[0u8; 32].into()); // expect: R-MLDSA-001
    let _sig = keypair.sign(b"m"); // expect: R-MLDSA-001

    use slh_dsa::signature::Signer as _;
    let sk = slh_dsa::SigningKey::<slh_dsa::Shake128s>::new(&mut OsRng); // expect: R-SLHDSA-001
    let _s = sk.sign(b"m"); // expect: R-SLHDSA-001
}

/// Generic and never instantiated, so only the source-level view sees these
/// calls, and the crate fallbacks are all that can fire. In a compiled
/// function the machine-level twin names the type, and the rule for that
/// type wins.
pub fn fallbacks_only<T>(
    sig: &ed25519_dalek::Signature,
    vk: &dsa::VerifyingKey,
    ecdsa_sig: &p256::ecdsa::Signature,
    _t: T,
) {
    let _r = sig.r_bytes(); // expect: R-ED25519-999
    let _c = vk.components(); // expect: R-DSA-999
    let _n = ecdsa_sig.normalize_s(); // expect: R-ECDSA-999
}

/// A call in the `signature` crate on a type no rule names.
pub fn a_signature_call_no_rule_names<S: signature::SignatureEncoding>(sig: S) {
    let _r = sig.encoded_len(); // expect: R-SIG-999
}
