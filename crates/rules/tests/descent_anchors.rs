use cpg_core::{AblationMode, Cpg, IrLayer, NodeKind, SafetyCtx, SourceLoc};
use qr_rules::crypto::{crypto_crates, is_crypto_crate};
use qr_rules::RuleSet;

const ADDED: &[&str] = &[
    "eax",
    "ocb3",
    "ecb",
    "cmac",
    "idea",
    "cast5",
    "hmac",
    "hkdf",
    "pbkdf2",
    "scrypt",
    "argon2",
    "ripemd",
    "shake",
    "sha1collisiondetection",
    "primeorder",
    "rfc6979",
    "cx448",
    "curve25519-dalek",
];

fn call(symbol: &str, type_args: &[&str]) -> Cpg {
    let mut cpg = Cpg::new(AblationMode::Dual);
    let node = cpg.add_node_full(
        IrLayer::Mir,
        NodeKind::CallSite,
        symbol,
        None,
        Some(SourceLoc::new("src/lib.rs", 17)),
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

#[test]
fn the_added_crates_are_crypto_crates_to_the_planner() {
    let known = crypto_crates(&RuleSet::builtin());
    for name in ADDED {
        assert!(is_crypto_crate(name, &known), "{name}");
    }
    for name in [
        "hpke",
        "age-core",
        "rust-embed",
        "rust-embed-utils",
        "i18n-embed",
    ] {
        assert!(!is_crypto_crate(name, &known), "{name}");
    }
}

#[test]
fn a_call_into_an_anchored_mode_names_its_cipher() {
    let typenum = [
        "cipher::typenum::UInt",
        "cipher::typenum::UTerm",
        "cipher::typenum::B1",
    ];
    for (cipher, rule) in [("aes::Aes128", "R-AES-002"), ("aes::Aes192", "R-AES-003")] {
        let mut args = vec![cipher, "eax::online::Encrypt"];
        args.extend(typenum);
        let cpg = call(
            "eax::online::Eax::<Cipher, Op, M>::with_key_and_nonce",
            &args,
        );
        assert_eq!(rule_ids(&cpg), [rule], "{cipher}");
    }
}

#[test]
fn a_call_into_an_anchored_kdf_names_its_hash() {
    for (variable_core, oid, rule) in [
        ("sha2::Sha256VarCore", "sha2::OidSha256", "R-SHA2-001"),
        ("sha2::Sha512VarCore", "sha2::OidSha512", "R-SHA2-003"),
    ] {
        let cpg = call(
            "hkdf::Hkdf::<H, I>::new",
            &[
                "digest::core_api::CoreWrapper",
                "digest::core_api::CtVariableCoreWrapper",
                variable_core,
                "cipher::typenum::UInt",
                oid,
                "hkdf::hmac::HmacCore",
            ],
        );
        assert_eq!(rule_ids(&cpg), [rule], "{oid}");
    }
}

#[test]
fn a_kdf_call_naming_no_hash_is_named_as_a_kdf() {
    assert_eq!(rule_ids(&call("scrypt::scrypt", &[])), ["R-SCRYPT-001"]);
}

#[test]
fn an_excluded_method_in_an_added_crate_stays_silent() {
    let cpg = call("hmac::SimpleHmac::<D>::finalize", &["sha2::OidSha256"]);
    assert!(rule_ids(&cpg).is_empty());
}
