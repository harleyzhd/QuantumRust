use cpg_core::{AblationMode, Cpg, IrLayer, NodeKind, SafetyCtx, SourceLoc};
use qr_rules::RuleSet;

fn mir_trait_call(symbol: &str, canonical: &str, type_args: &[&str]) -> Cpg {
    let mut cpg = Cpg::new(AblationMode::MirOnly);
    let node = cpg.add_node_full(
        IrLayer::Mir,
        NodeKind::TraitMethod,
        symbol,
        Some(canonical.to_string()),
        Some(SourceLoc::new("src/lib.rs", 7)),
        SafetyCtx::Safe,
    );
    cpg.set_type_args(node, type_args.iter().map(|s| s.to_string()).collect());
    cpg
}

fn found(cpg: &Cpg) -> Vec<(String, Option<String>)> {
    RuleSet::builtin()
        .match_cpg(cpg)
        .into_iter()
        .map(|f| (f.rule_id, f.parameter_set))
        .collect()
}

fn one(rule: &str, set: Option<&str>) -> Vec<(String, Option<String>)> {
    vec![(rule.to_string(), set.map(str::to_string))]
}

#[test]
fn a_hasher_built_by_default_is_named_by_its_type() {
    let cpg = mir_trait_call(
        "core::default::Default::default",
        "<digest::core_api::wrapper::CoreWrapper<digest::core_api::ct_variable::\
         CtVariableCoreWrapper<sha2::core_api::Sha256VarCore, typenum::uint::UInt<typenum::\
         uint::UTerm, typenum::bit::B1>, sha2::OidSha256>> as core::default::Default>::default",
        &[
            "digest::core_api::wrapper::CoreWrapper",
            "digest::core_api::ct_variable::CtVariableCoreWrapper",
            "sha2::core_api::Sha256VarCore",
            "sha2::OidSha256",
        ],
    );
    assert_eq!(found(&cpg), one("R-SHA2-001", None));
}

#[test]
fn a_key_derived_by_from_is_found_whatever_other_rules_exclude() {
    let cpg = mir_trait_call(
        "core::convert::From::from",
        "<x25519_dalek::x25519::PublicKey as \
         core::convert::From<&x25519_dalek::x25519::StaticSecret>>::from",
        &[
            "x25519_dalek::x25519::PublicKey",
            "x25519_dalek::x25519::StaticSecret",
        ],
    );
    assert_eq!(found(&cpg), one("R-X25519-999", Some("X25519")));
}

#[test]
fn a_key_derived_by_into_is_found() {
    let cpg = mir_trait_call(
        "core::convert::Into::into",
        "<&x25519_dalek::x25519::StaticSecret as \
         core::convert::Into<x25519_dalek::x25519::PublicKey>>::into",
        &[
            "x25519_dalek::x25519::StaticSecret",
            "x25519_dalek::x25519::PublicKey",
        ],
    );
    assert_eq!(found(&cpg), one("R-X25519-999", Some("X25519")));
}

#[test]
fn a_conversion_into_a_crypto_crates_error_is_not_crypto() {
    let cpg = mir_trait_call(
        "core::convert::From::from",
        "<rsa::errors::Error as core::convert::From<pkcs1::Error>>::from",
        &["rsa::errors::Error", "pkcs1::Error"],
    );
    assert_eq!(found(&cpg), vec![]);
}

#[test]
fn another_trait_on_a_crypto_type_is_still_not_anchored() {
    let cpg = mir_trait_call(
        "serde::Serialize::serialize",
        "<x25519_dalek::x25519::PublicKey as serde::Serialize>::serialize",
        &["x25519_dalek::x25519::PublicKey"],
    );
    assert_eq!(found(&cpg), vec![]);
}
