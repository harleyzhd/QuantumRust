use cpg_core::{AblationMode, AlgorithmClass, Cpg, IrLayer, NodeKind, SourceLoc};
use qr_rules::RuleSet;

fn findings_on(symbol: &str) -> Vec<(String, AlgorithmClass)> {
    let mut cpg = Cpg::new(AblationMode::MirOnly);
    cpg.add_node(
        IrLayer::Mir,
        NodeKind::CallSite,
        symbol,
        Some(SourceLoc::new("src/lib.rs", 1)),
    );
    RuleSet::builtin()
        .match_cpg(&cpg)
        .into_iter()
        .map(|f| (f.rule_id, f.algorithm_class))
        .collect()
}

#[test]
fn p256_ecdh_is_class_ecdh() {
    assert_eq!(
        findings_on("p256::ecdh::diffie_hellman"),
        [("R-ECDH-001".to_string(), AlgorithmClass::Ecdh)]
    );
}

#[test]
fn a_bare_p256_secret_key_is_an_ec_key_not_ecdsa() {
    assert_eq!(
        findings_on("p256::elliptic_curve::SecretKey::<C>::public_key"),
        [("R-EC-999".to_string(), AlgorithmClass::EcKey)]
    );
}

#[test]
fn dsa_signing_is_class_dsa() {
    assert_eq!(
        findings_on("dsa::SigningKey::generate"),
        [("R-DSA-001".to_string(), AlgorithmClass::Dsa)]
    );
}
