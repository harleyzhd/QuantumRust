use cpg_core::{AblationMode, AlgorithmClass, Cpg, IrLayer, NodeKind, SafetyCtx, SourceLoc};
use qr_rules::RuleSet;

#[test]
fn a_reexported_curve_key_is_named_by_its_defining_crate() {
    let mut cpg = Cpg::new(AblationMode::MirOnly);
    let node = cpg.add_node_full(
        IrLayer::Mir,
        NodeKind::CallSite,
        "ecdsa::elliptic_curve::SecretKey::<C>::random",
        Some(
            "<elliptic_curve::secret_key::SecretKey<p256::NistP256>>::random::<rand_core::os::OsRng>"
                .to_string(),
        ),
        Some(SourceLoc::new("src/lib.rs", 1086)),
        SafetyCtx::Safe,
    );
    cpg.set_type_args(
        node,
        vec!["p256::NistP256".to_string(), "rand_core::OsRng".to_string()],
    );
    let got: Vec<(String, AlgorithmClass)> = RuleSet::builtin()
        .match_cpg(&cpg)
        .into_iter()
        .map(|f| (f.rule_id, f.algorithm_class))
        .collect();
    assert_eq!(got, [("R-EC-999".to_string(), AlgorithmClass::EcKey)]);
}
