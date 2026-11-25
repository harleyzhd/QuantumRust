use std::collections::BTreeSet;

use qr_rules::RuleSet;

const SINKS: &[&str] = &[
    "DSA_sign",
    "PEM_write_bio_RSAPrivateKey",
    "RSA_private_decrypt",
    "RSA_private_encrypt",
    "RSA_public_encrypt",
    "RSA_sign",
    "agree_ephemeral",
    "apply_keystream",
    "apply_keystream_b2b",
    "as_bytes",
    "as_diffie_hellman",
    "as_keypair_bytes",
    "compute_key",
    "decapsulate",
    "decrypt",
    "decrypt_blinded",
    "decrypt_block",
    "decrypt_block_b2b",
    "decrypt_blocks",
    "decrypt_in_place",
    "decrypt_in_place_detached",
    "detached_sign",
    "diffie_hellman",
    "encapsulate",
    "encrypt",
    "encrypt_block",
    "encrypt_block_b2b",
    "encrypt_blocks",
    "encrypt_in_place",
    "encrypt_in_place_detached",
    "i2d_RSAPrivateKey",
    "open_in_place",
    "private_decrypt",
    "private_encrypt",
    "seal_in_place_append_tag",
    "seal_in_place_separate_tag",
    "sign",
    "sign_ctx",
    "sign_digest",
    "sign_digest_recoverable",
    "sign_digest_with_rng",
    "sign_oneshot_to_vec",
    "sign_prehash",
    "sign_prehash_recoverable",
    "sign_prehash_with_rng",
    "sign_prehashed",
    "sign_raw",
    "sign_recoverable",
    "sign_to_vec",
    "sign_with_rng",
    "to_bytes",
    "to_bytes_be",
    "to_keypair_bytes",
    "to_pkcs1_der",
    "to_pkcs1_pem",
    "to_pkcs8_der",
    "to_pkcs8_pem",
    "to_sec1_der",
    "to_sec1_pem",
    "try_decaps",
    "try_encaps",
    "try_sign",
    "try_sign_digest",
    "try_sign_digest_with_rng",
    "try_sign_prehash",
    "try_sign_prehashed",
    "try_sign_with_rng",
    "x25519",
];

#[test]
fn the_builtin_sink_set_is_pinned() {
    let rules = RuleSet::builtin();
    let got: BTreeSet<&str> = rules
        .rules
        .iter()
        .flat_map(|r| r.taint.sinks.iter().map(String::as_str))
        .collect();
    let want: BTreeSet<&str> = SINKS.iter().copied().collect();
    let missing: Vec<_> = want.difference(&got).collect();
    let extra: Vec<_> = got.difference(&want).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "missing {missing:?}, unlisted {extra:?}"
    );
}

#[test]
fn aead_in_place_and_stream_cipher_calls_are_sinks() {
    let rules = RuleSet::builtin();
    for symbol in [
        "aead::AeadInPlace::encrypt_in_place",
        "aead::AeadInPlace::decrypt_in_place_detached",
        "<chacha20poly1305::ChaChaPoly1305<chacha20::ChaCha20> as aead::AeadInPlace>::encrypt_in_place",
        "cipher::StreamCipher::apply_keystream",
        "<chacha20::ChaCha20 as cipher::StreamCipher>::apply_keystream_b2b",
    ] {
        assert!(rules.is_sink(symbol), "{symbol}");
    }
}
