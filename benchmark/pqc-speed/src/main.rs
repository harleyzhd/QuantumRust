//! Time each scheme in `data/pqc_replacements.toml` on this machine, with the
//! crates a Rust project would migrate between.
//!
//! Prints JSON: scheme -> operation -> {median_us, mean_us, min_us, iterations}.
//! `docs/scripts/pqc_speed.py` builds this in release, runs it and records the
//! result, with the machine and crate versions, as `data/pqc_speed.json`.
//!
//! Each operation runs once untimed, then until it has at least
//! [`MIN_SAMPLES`] samples and [`TARGET`] of wall time (at most
//! [`MAX_SAMPLES`]). The report uses the median. The minimum is a check on
//! noise. The mean is kept because a signature made by rejection sampling
//! (ML-DSA) costs its mean on average, which is above its median. Key
//! generation is reported separately: a long-lived key is generated once, an
//! ephemeral one per exchange.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};

const MIN_SAMPLES: usize = 3;
const MAX_SAMPLES: usize = 20_000;
const TARGET: Duration = Duration::from_secs(1);

/// The message signed to make the signature each verify times: the size of a
/// SHA-256 digest, which is what a signing call in a protocol receives.
const MSG: [u8; 32] = [0x5a; 32];

/// Distinct messages each sign timing cycles through.
const MESSAGES: usize = 1024;

/// Random digest-sized messages, handed out in turn to the sign timings.
///
/// ML-DSA signs by rejection sampling, and its `Signer` is deterministic, so
/// one key and one message repeat the same number of rounds on every call.
/// Signing one fixed message would time a single draw of that count; cycling
/// through many messages times the distribution.
struct Messages {
    pool: Vec<[u8; 32]>,
    at: usize,
}

impl Messages {
    fn new() -> Self {
        Self {
            pool: (0..MESSAGES).map(|_| random::<32>()).collect(),
            at: 0,
        }
    }

    fn next(&mut self) -> &[u8; 32] {
        self.at = (self.at + 1) % self.pool.len();
        &self.pool[self.at]
    }
}

fn time(mut op: impl FnMut()) -> Value {
    op();
    let mut samples = Vec::new();
    let start = Instant::now();
    while samples.len() < MIN_SAMPLES || (start.elapsed() < TARGET && samples.len() < MAX_SAMPLES) {
        let t = Instant::now();
        op();
        samples.push(t.elapsed().as_secs_f64() * 1e6);
    }
    samples.sort_by(f64::total_cmp);
    json!({
        "median_us": samples[samples.len() / 2],
        "mean_us": samples.iter().sum::<f64>() / samples.len() as f64,
        "min_us": samples[0],
        "iterations": samples.len(),
    })
}

fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

type Results = BTreeMap<&'static str, BTreeMap<&'static str, Value>>;

fn rsa(results: &mut Results, name: &'static str, bits: usize) {
    use rsa::pkcs1v15::{SigningKey, VerifyingKey};
    use rsa::signature::{Signer, Verifier};
    use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;

    let key = RsaPrivateKey::new(&mut OsRng, bits).expect("RSA keygen");
    let public = RsaPublicKey::from(&key);
    let signer = SigningKey::<Sha256>::new(key.clone());
    let verifier = VerifyingKey::<Sha256>::new(public.clone());
    let sig = signer.sign(&MSG);
    let ct = public
        .encrypt(&mut OsRng, Oaep::new::<Sha256>(), &MSG)
        .expect("RSA encrypt");
    let r = results.entry(name).or_default();
    r.insert(
        "keygen",
        time(|| {
            black_box(RsaPrivateKey::new(&mut OsRng, bits).expect("keygen"));
        }),
    );
    let mut msgs = Messages::new();
    r.insert(
        "sign",
        time(|| {
            black_box(signer.sign(black_box(msgs.next())));
        }),
    );
    r.insert(
        "verify",
        time(|| verifier.verify(black_box(&MSG), &sig).expect("valid")),
    );
    r.insert(
        "encrypt",
        time(|| {
            black_box(
                public
                    .encrypt(&mut OsRng, Oaep::new::<Sha256>(), black_box(&MSG))
                    .expect("encrypt"),
            );
        }),
    );
    r.insert(
        "decrypt",
        time(|| {
            black_box(key.decrypt(Oaep::new::<Sha256>(), &ct).expect("decrypt"));
        }),
    );
}

macro_rules! ecdsa {
    ($results:expr, $name:literal, $curve:ident) => {{
        use $curve::ecdsa::signature::{Signer, Verifier};
        use $curve::ecdsa::{Signature, SigningKey, VerifyingKey};
        let key = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&key);
        let sig: Signature = key.sign(&MSG);
        let r = $results.entry($name).or_default();
        r.insert(
            "keygen",
            time(|| {
                let k = SigningKey::random(&mut OsRng);
                black_box(VerifyingKey::from(&k));
            }),
        );
        let mut msgs = Messages::new();
        r.insert(
            "sign",
            time(|| {
                let s: Signature = key.sign(black_box(msgs.next()));
                black_box(s);
            }),
        );
        r.insert(
            "verify",
            time(|| vk.verify(black_box(&MSG), &sig).expect("valid")),
        );
    }};
}

fn ed25519(results: &mut Results) {
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    let key = SigningKey::generate(&mut OsRng);
    let vk = key.verifying_key();
    let sig = key.sign(&MSG);
    let r = results.entry("Ed25519").or_default();
    r.insert(
        "keygen",
        time(|| {
            black_box(SigningKey::generate(&mut OsRng).verifying_key());
        }),
    );
    let mut msgs = Messages::new();
    r.insert(
        "sign",
        time(|| {
            black_box(key.sign(black_box(msgs.next())));
        }),
    );
    r.insert(
        "verify",
        time(|| vk.verify(black_box(&MSG), &sig).expect("valid")),
    );
}

fn x25519(results: &mut Results) {
    use x25519_dalek::{PublicKey, StaticSecret};
    let mine = StaticSecret::random_from_rng(OsRng);
    let theirs = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
    let r = results.entry("X25519").or_default();
    r.insert(
        "keygen",
        time(|| {
            let s = StaticSecret::random_from_rng(OsRng);
            black_box(PublicKey::from(&s));
        }),
    );
    r.insert(
        "dh",
        time(|| {
            black_box(mine.diffie_hellman(black_box(&theirs)));
        }),
    );
}

macro_rules! ecdh {
    ($results:expr, $name:literal, $curve:ident) => {{
        use $curve::ecdh::EphemeralSecret;
        let mine = EphemeralSecret::random(&mut OsRng);
        let theirs = EphemeralSecret::random(&mut OsRng).public_key();
        let r = $results.entry($name).or_default();
        r.insert(
            "keygen",
            time(|| {
                black_box(EphemeralSecret::random(&mut OsRng).public_key());
            }),
        );
        r.insert(
            "dh",
            time(|| {
                black_box(mine.diffie_hellman(black_box(&theirs)));
            }),
        );
    }};
}

fn x448(results: &mut Results) {
    use cx448::x448::{PublicKey, Secret};
    let mine = Secret::new(&mut OsRng);
    let theirs = PublicKey::from(&Secret::new(&mut OsRng));
    let r = results.entry("X448").or_default();
    r.insert(
        "keygen",
        time(|| {
            let s = Secret::new(&mut OsRng);
            black_box(PublicKey::from(&s));
        }),
    );
    r.insert(
        "dh",
        time(|| {
            black_box(
                mine.as_diffie_hellman(black_box(&theirs))
                    .expect("not low order"),
            );
        }),
    );
}

fn ed448(results: &mut Results) {
    use cx448::crypto_signature::{Signer, Verifier};
    use cx448::{Signature, SigningKey};
    let key = SigningKey::generate(&mut OsRng);
    let vk = key.verifying_key();
    let sig: Signature = key.sign(&MSG);
    let r = results.entry("Ed448").or_default();
    r.insert(
        "keygen",
        time(|| {
            black_box(SigningKey::generate(&mut OsRng).verifying_key());
        }),
    );
    let mut msgs = Messages::new();
    r.insert(
        "sign",
        time(|| {
            let s: Signature = key.sign(black_box(msgs.next()));
            black_box(s);
        }),
    );
    r.insert(
        "verify",
        time(|| vk.verify(black_box(&MSG), &sig).expect("valid")),
    );
}

/// DSA with a 2048-bit p and 256-bit q, so r||s is 64 bytes, as the table
/// records. The domain parameters are generated once, untimed: they are
/// shared and take seconds to find. "keygen" is a key pair over them.
fn dsa_2048(results: &mut Results) {
    use dsa::signature::{Signer, Verifier};
    use dsa::{Components, KeySize, Signature, SigningKey};
    let components = Components::generate(&mut OsRng, KeySize::DSA_2048_256);
    let key = SigningKey::generate(&mut OsRng, components.clone());
    let vk = key.verifying_key().clone();
    let sig: Signature = key.sign(&MSG);
    let r = results.entry("DSA-2048").or_default();
    r.insert(
        "keygen",
        time(|| {
            let _ = black_box(SigningKey::generate(&mut OsRng, components.clone()));
        }),
    );
    let mut msgs = Messages::new();
    r.insert(
        "sign",
        time(|| {
            let s: Signature = key.sign(black_box(msgs.next()));
            let _ = black_box(s);
        }),
    );
    r.insert(
        "verify",
        time(|| vk.verify(black_box(&MSG), &sig).expect("valid")),
    );
}

macro_rules! mlkem {
    ($results:expr, $name:literal, $params:ident) => {{
        use ml_kem::kem::Decapsulate;
        use ml_kem::{$params, DecapsulationKey};
        let fresh = || {
            DecapsulationKey::<$params>::from_seed(
                random::<64>().as_slice().try_into().expect("64 bytes"),
            )
        };
        let dk = fresh();
        let ek = dk.encapsulation_key().clone();
        let m = random::<32>();
        let (ct, _) = ek.encapsulate_deterministic(&m.as_slice().try_into().expect("32 bytes"));
        let r = $results.entry($name).or_default();
        r.insert(
            "keygen",
            time(|| {
                let k = fresh();
                black_box(k.encapsulation_key());
            }),
        );
        r.insert(
            "encaps",
            time(|| {
                let m = random::<32>();
                black_box(
                    ek.encapsulate_deterministic(&m.as_slice().try_into().expect("32 bytes")),
                );
            }),
        );
        r.insert(
            "decaps",
            time(|| {
                black_box(dk.decapsulate(black_box(&ct)));
            }),
        );
    }};
}

macro_rules! mldsa {
    ($results:expr, $name:literal, $params:ident) => {{
        use ml_dsa::signature::{Keypair, Signer, Verifier};
        use ml_dsa::{$params, SigningKey};
        let fresh = || {
            SigningKey::<$params>::from_seed(
                &random::<32>().as_slice().try_into().expect("32 bytes"),
            )
        };
        let key = fresh();
        let vk = key.verifying_key();
        let sig = key.sign(&MSG);
        let r = $results.entry($name).or_default();
        r.insert(
            "keygen",
            time(|| {
                black_box(fresh().verifying_key());
            }),
        );
        let mut msgs = Messages::new();
        r.insert(
            "sign",
            time(|| {
                black_box(key.sign(black_box(msgs.next())));
            }),
        );
        r.insert(
            "verify",
            time(|| vk.verify(black_box(&MSG), &sig).expect("valid")),
        );
    }};
}

macro_rules! slhdsa {
    ($results:expr, $name:literal, $params:ident) => {{
        use slh_dsa::signature::{Signer, Verifier};
        use slh_dsa::{$params, SigningKey};
        let key = SigningKey::<$params>::new(&mut OsRng);
        let sig = key.sign(&MSG);
        let r = $results.entry($name).or_default();
        r.insert(
            "keygen",
            time(|| {
                black_box(SigningKey::<$params>::new(&mut OsRng));
            }),
        );
        let mut msgs = Messages::new();
        r.insert(
            "sign",
            time(|| {
                black_box(key.sign(black_box(msgs.next())));
            }),
        );
        r.insert(
            "verify",
            time(|| key.as_ref().verify(black_box(&MSG), &sig).expect("valid")),
        );
    }};
}

fn main() {
    let mut results: Results = BTreeMap::new();
    let step = |name: &str| eprintln!("  timing {name}");

    step("RSA");
    rsa(&mut results, "RSA-2048", 2048);
    rsa(&mut results, "RSA-3072", 3072);
    rsa(&mut results, "RSA-4096", 4096);
    step("ECDSA");
    ecdsa!(results, "ECDSA-P256", p256);
    ecdsa!(results, "ECDSA-P384", p384);
    ecdsa!(results, "ECDSA-P521", p521);
    ecdsa!(results, "ECDSA-secp256k1", k256);
    step("DSA");
    dsa_2048(&mut results);
    step("Ed25519 / Ed448");
    ed25519(&mut results);
    ed448(&mut results);
    step("X25519 / X448 / ECDH");
    x25519(&mut results);
    x448(&mut results);
    ecdh!(results, "ECDH-P256", p256);
    ecdh!(results, "ECDH-P384", p384);
    ecdh!(results, "ECDH-P521", p521);
    ecdh!(results, "ECDH-secp256k1", k256);
    step("ML-KEM");
    mlkem!(results, "ML-KEM-512", MlKem512);
    mlkem!(results, "ML-KEM-768", MlKem768);
    mlkem!(results, "ML-KEM-1024", MlKem1024);
    step("ML-DSA");
    mldsa!(results, "ML-DSA-44", MlDsa44);
    mldsa!(results, "ML-DSA-65", MlDsa65);
    mldsa!(results, "ML-DSA-87", MlDsa87);
    step("SLH-DSA");
    slhdsa!(results, "SLH-DSA-SHA2-128s", Sha2_128s);
    slhdsa!(results, "SLH-DSA-SHA2-192s", Sha2_192s);
    slhdsa!(results, "SLH-DSA-SHA2-256s", Sha2_256s);

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({ "schemes": results })).expect("serialises")
    );
}
