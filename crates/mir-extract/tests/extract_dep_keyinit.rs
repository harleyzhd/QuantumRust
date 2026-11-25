#![feature(rustc_private)]

extern crate rustc_driver;

use std::path::PathBuf;
use std::sync::OnceLock;

use cpg_core::descent::plan;
use cpg_core::{Cpg, MirProvider, NodeKind};
use mir_extract::RustcMirProvider;
use qr_rules::RuleSet;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/dep-keyinit")
}

fn cpg() -> &'static Cpg {
    static CPG: OnceLock<Cpg> = OnceLock::new();
    CPG.get_or_init(|| {
        let known = qr_rules::crypto::crypto_crates(&RuleSet::builtin());
        let descent = plan(&root(), 3, &|name: &str| {
            qr_rules::crypto::is_crypto_crate(name, &known)
        })
        .expect("plan");
        RustcMirProvider {
            driver: Some(PathBuf::from(env!("CARGO_BIN_EXE_mir-extract-driver"))),
            descent: Some(descent),
            ..Default::default()
        }
        .extract(&root())
        .expect("extraction over fixtures/dep-keyinit")
    })
}

fn line_of(text: &str) -> u32 {
    let src = std::fs::read_to_string(root().join("src/lib.rs")).unwrap();
    src.lines().position(|l| l.contains(text)).expect(text) as u32 + 1
}

fn rules_at(line: u32) -> Vec<String> {
    let rules = RuleSet::builtin();
    let mut ids: Vec<String> = qr_rules::rehome(cpg(), &rules, rules.match_cpg(cpg()))
        .into_iter()
        .filter(|f| f.location.line == line && f.location.file == "src/lib.rs")
        .map(|f| f.rule_id)
        .collect();
    ids.sort();
    ids
}

#[test]
fn the_calls_are_filed_under_crypto_common() {
    let keyinit: Vec<_> = cpg()
        .nodes()
        .filter(|n| n.kind == NodeKind::TraitMethod && n.symbol.ends_with("KeyInit::new"))
        .collect();
    assert_eq!(keyinit.len(), 2, "{keyinit:#?}");
    assert!(
        keyinit
            .iter()
            .all(|n| n.symbol == "crypto_common::KeyInit::new" && n.dep_depth == Some(1)),
        "{keyinit:#?}"
    );
}

#[test]
fn aes_128_through_keyinit_is_named_at_the_local_call() {
    assert_eq!(rules_at(line_of("vault::aes128();")), ["R-AES-002"]);
}

#[test]
fn chacha20_through_keyinit_is_named_at_the_local_call() {
    assert_eq!(rules_at(line_of("vault::chacha20();")), ["R-CHACHA-002"]);
}

#[test]
fn a_self_type_no_rule_names_stays_silent() {
    assert!(rules_at(line_of("vault::blank();")).is_empty());
    assert!(cpg().nodes().any(|n| n.kind == NodeKind::TraitMethod
        && n.symbol.ends_with("Default::default")
        && n.dep_depth == Some(1)));
}

#[test]
fn an_excluded_call_on_a_named_type_stays_silent() {
    assert!(rules_at(line_of("vault::block_size()")).is_empty());
    assert!(cpg().nodes().any(|n| n.kind == NodeKind::TraitMethod
        && n.symbol.ends_with("BlockSizeUser::block_size")
        && n.canonical.as_deref().is_some_and(|c| c.contains("Aes128"))
        && n.dep_depth == Some(1)));
}
