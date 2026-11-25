use cpg_core::{AblationMode, Cpg, IrLayer, NodeKind, SafetyCtx, SourceLoc};
use qr_rules::RuleSet;

const SHAKE128S: &str = "slh_dsa::hashes::shake::Shake<typenum::uint::UInt<typenum::uint::\
    UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, \
    typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, \
    typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::\
    uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B1>, typenum::bit::B1>, \
    typenum::bit::B1>, typenum::bit::B0>>";
const SLH_ARGS: &[&str] = &[
    "slh_dsa::Shake",
    "cipher::typenum::UInt",
    "cipher::typenum::UTerm",
    "cipher::typenum::B1",
    "cipher::typenum::B0",
    "slh_dsa::Signature",
];
const RSA_SHA256_KEY: &str = "rsa::pkcs1v15::signing_key::SigningKey<digest::core_api::wrapper::\
    CoreWrapper<digest::core_api::ct_variable::CtVariableCoreWrapper<sha2::core_api::Sha256VarCore, \
    typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::\
    UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, \
    typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, sha2::OidSha256>>>";

fn trait_call(layer: IrLayer, symbol: &str, canonical: &str, type_args: &[&str]) -> Cpg {
    let mut cpg = Cpg::new(AblationMode::Dual);
    let node = cpg.add_node_full(
        layer,
        NodeKind::TraitMethod,
        symbol,
        Some(canonical.to_string()),
        Some(SourceLoc::new("src/lib.rs", 7)),
        SafetyCtx::Safe,
    );
    cpg.set_type_args(node, type_args.iter().map(|s| s.to_string()).collect());
    cpg
}

fn rule_ids(cpg: &Cpg) -> Vec<String> {
    let mut ids: Vec<String> = RuleSet::builtin()
        .match_cpg(cpg)
        .into_iter()
        .flat_map(|f| std::iter::once(f.rule_id).chain(f.with.into_iter().map(|p| p.rule_id)))
        .collect();
    ids.sort();
    ids
}

fn mir(symbol: &str, canonical: &str, type_args: &[&str]) -> Vec<String> {
    rule_ids(&trait_call(IrLayer::Mir, symbol, canonical, type_args))
}

#[test]
fn a_pkcs8_key_import_is_attributed_to_the_key_it_imports() {
    assert_eq!(
        mir(
            "rsa::pkcs8::DecodePrivateKey::from_pkcs8_der",
            "<ecdsa::signing::SigningKey<p256::NistP256> as \
             pkcs8::traits::DecodePrivateKey>::from_pkcs8_der",
            &["ecdsa::signing::SigningKey", "p256::NistP256"],
        ),
        ["R-ECDSA-004"]
    );
    assert_eq!(
        mir(
            "rsa::pkcs8::DecodePrivateKey::from_pkcs8_der",
            "<ed25519_dalek::signing::SigningKey as \
             pkcs8::traits::DecodePrivateKey>::from_pkcs8_der",
            &["ed25519_dalek::SigningKey"],
        ),
        ["R-ED25519-004"]
    );
}

#[test]
fn a_dsa_signature_printed_through_rsa_is_dsa() {
    assert_eq!(
        mir(
            "rsa::signature::hazmat::PrehashSigner::sign_prehash",
            "<dsa::signing_key::SigningKey as \
             signature::hazmat::PrehashSigner<dsa::Signature>>::sign_prehash",
            &["dsa::SigningKey", "dsa::Signature"],
        ),
        ["R-DSA-001"]
    );
}

#[test]
fn an_slh_dsa_signature_is_not_ed25519() {
    let sign = format!(
        "<slh_dsa::signing_key::SigningKey<{SHAKE128S}> as \
         signature::signer::Signer<slh_dsa::signature_encoding::Signature<{SHAKE128S}>>>::sign"
    );
    let verify = format!(
        "<slh_dsa::verifying_key::VerifyingKey<{SHAKE128S}> as \
         signature::verifier::Verifier<slh_dsa::signature_encoding::Signature<{SHAKE128S}>>>::verify"
    );
    let with = |first: &'static str| [&[first][..], SLH_ARGS].concat();
    assert_eq!(
        mir(
            "ed25519_dalek::Signer::sign",
            &sign,
            &with("slh_dsa::SigningKey")
        ),
        ["R-SLHDSA-001"]
    );
    assert_eq!(
        mir(
            "ed25519_dalek::Verifier::verify",
            &verify,
            &with("slh_dsa::VerifyingKey")
        ),
        ["R-SLHDSA-001"]
    );
}

#[test]
fn an_rsa_import_through_pkcs1_is_still_rsa() {
    assert_eq!(
        mir(
            "rsa::pkcs1::DecodeRsaPrivateKey::from_pkcs1_der",
            "<rsa::key::RsaPrivateKey as pkcs1::traits::DecodeRsaPrivateKey>::from_pkcs1_der",
            &["rsa::RsaPrivateKey"],
        ),
        ["R-RSA-001"]
    );
}

#[test]
fn an_algorithm_specific_trait_keeps_its_match() {
    assert_eq!(
        mir(
            "ecdsa::hazmat::SignPrimitive::try_sign_prehashed",
            "<p256::arithmetic::scalar::Scalar as \
             ecdsa::hazmat::SignPrimitive<p256::NistP256>>::try_sign_prehashed::\
             <p256::arithmetic::scalar::Scalar>",
            &["p256::Scalar", "p256::NistP256"],
        ),
        ["R-ECDSA-002"]
    );
}

#[test]
fn an_anchor_on_an_involved_crate_keeps_the_type_argument_reading() {
    assert_eq!(
        mir(
            "cipher::KeyInit::new_from_slice",
            "<ocb3::Ocb3<aes::autodetect::Aes128, typenum::uint::UInt<typenum::uint::UInt<\
             typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, \
             typenum::bit::B1>, typenum::bit::B1>, typenum::bit::B1>> as \
             crypto_common::KeyInit>::new_from_slice",
            &[
                "ocb3::Ocb3",
                "aes::Aes128",
                "cipher::typenum::UInt",
                "cipher::typenum::UTerm",
                "cipher::typenum::B1",
                "cipher::typenum::B0",
            ],
        ),
        ["R-AES-002"]
    );
    assert_eq!(
        mir(
            "hmac::digest::FixedOutput::finalize_fixed",
            "<digest::core_api::wrapper::CoreWrapper<sha3::Sha3_256Core> as \
             digest::FixedOutput>::finalize_fixed",
            &["hmac::digest::core_api::CoreWrapper", "sha3::Sha3_256Core"],
        ),
        ["R-SHA3-001"]
    );
}

#[test]
fn an_anchor_is_kept_by_a_crate_in_a_generic_argument() {
    assert_eq!(
        mir(
            "cipher::KeyInit::new",
            "<wrapper::W<aes::autodetect::Aes128> as crypto_common::KeyInit>::new",
            &["wrapper::W", "aes::Aes128"],
        ),
        ["R-AES-002"]
    );
}

#[test]
fn a_call_printed_through_the_traits_own_crate_is_unchanged() {
    assert_eq!(
        mir(
            "signature::Signer::sign",
            &format!(
                "<{RSA_SHA256_KEY} as \
                 signature::signer::Signer<rsa::pkcs1v15::signature::Signature>>::sign"
            ),
            &[
                "rsa::pkcs1v15::SigningKey",
                "signature::digest::core_api::CoreWrapper",
                "signature::digest::core_api::CtVariableCoreWrapper",
                "rsa::sha2::Sha256VarCore",
                "signature::digest::typenum::UInt",
                "signature::digest::typenum::UTerm",
                "signature::digest::typenum::B1",
                "signature::digest::typenum::B0",
                "rsa::sha2::OidSha256",
                "rsa::pkcs1v15::Signature",
            ],
        ),
        ["R-RSA-007", "R-SHA2-001"]
    );
    assert_eq!(
        mir(
            "signature::Signer::sign",
            "<ed25519_dalek::signing::SigningKey as \
             signature::signer::Signer<ed25519::Signature>>::sign",
            &["ed25519_dalek::SigningKey", "ed25519_dalek::Signature"],
        ),
        ["R-ED25519-004"]
    );
}

#[test]
fn trait_object_dispatch_is_untouched() {
    assert_eq!(
        mir(
            "<dyn signature::Signer>::try_sign",
            "<dyn jsonwebtoken::crypto::JwtSigner as \
             signature::signer::Signer<alloc::vec::Vec<u8>>>::try_sign",
            &["std::vec::Vec", "std::alloc::Global"],
        ),
        ["R-SIG-999"]
    );
}

#[test]
fn the_llvm_layer_is_untouched() {
    let cpg = trait_call(
        IrLayer::Llvm,
        "rsa::pkcs8::DecodePrivateKey::from_pkcs8_der",
        "<ecdsa::signing::SigningKey<p256::NistP256> as \
         pkcs8::traits::DecodePrivateKey>::from_pkcs8_der",
        &["ecdsa::signing::SigningKey", "p256::NistP256"],
    );
    assert_eq!(rule_ids(&cpg), ["R-ECDSA-004", "R-RSA-001"]);
}
