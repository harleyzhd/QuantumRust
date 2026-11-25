#![feature(rustc_private)]

extern crate rustc_driver;

use std::path::PathBuf;
use std::sync::OnceLock;

use cpg_core::descent::plan;
use cpg_core::{AlgorithmClass, Cpg, MirProvider, NodeKind};
use mir_extract::RustcMirProvider;
use qr_rules::RuleSet;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/dep-descent")
}

fn extract(depth: Option<u8>) -> Cpg {
    let descent = depth.map(|d| plan(&root(), d, &|name: &str| name == "sha2").expect("plan"));
    RustcMirProvider {
        driver: Some(PathBuf::from(env!("CARGO_BIN_EXE_mir-extract-driver"))),
        descent,
        ..Default::default()
    }
    .extract(&root())
    .expect("extraction over fixtures/dep-descent")
}

fn at(depth: Option<u8>) -> &'static Cpg {
    static NONE: OnceLock<Cpg> = OnceLock::new();
    static ONE: OnceLock<Cpg> = OnceLock::new();
    static THREE: OnceLock<Cpg> = OnceLock::new();
    match depth {
        None => NONE.get_or_init(|| extract(None)),
        Some(1) => ONE.get_or_init(|| extract(Some(1))),
        Some(3) => THREE.get_or_init(|| extract(Some(3))),
        _ => unreachable!(),
    }
}

fn line_of(text: &str) -> u32 {
    let src = std::fs::read_to_string(root().join("src/lib.rs")).unwrap();
    src.lines().position(|l| l.contains(text)).expect(text) as u32 + 1
}

fn hashes_at(cpg: &Cpg, line: u32) -> usize {
    let rules = RuleSet::builtin();
    let findings = qr_rules::rehome(cpg, &rules, rules.match_cpg(cpg));
    findings
        .iter()
        .filter(|f| f.location.line == line && f.location.file == "src/lib.rs")
        .filter(|f| f.algorithm_class == AlgorithmClass::Hash)
        .count()
}

#[test]
fn without_descent_the_crate_has_no_crypto() {
    let cpg = at(None);
    assert!(cpg.nodes().all(|n| n.dep_depth.is_none()));
    for text in [
        "vault::seal(msg);",
        "vault::digest_with::<H>(msg);",
        "relay::forward(msg);",
    ] {
        assert_eq!(hashes_at(cpg, line_of(text)), 0, "{text}");
    }
}

#[test]
fn a_dependency_wrapper_is_found_at_the_local_call() {
    assert_eq!(hashes_at(at(Some(3)), line_of("vault::seal(msg);")), 1);
}

#[test]
fn a_generic_dependency_wrapper_resolves_to_the_concrete_digest() {
    let cpg = at(Some(3));
    assert_eq!(hashes_at(cpg, line_of("vault::digest_with::<H>(msg);")), 1);
    let instance = cpg
        .nodes()
        .find(|n| n.kind == NodeKind::Function && n.symbol.contains("digest_with"))
        .expect("the instance was walked");
    assert_eq!(instance.dep_depth, Some(1));
    assert!(
        instance.symbol.contains("Sha512") || instance.symbol.contains("512"),
        "{}",
        instance.symbol
    );
}

#[test]
fn two_hops_need_depth_two() {
    let line = line_of("relay::forward(msg);");
    assert_eq!(hashes_at(at(Some(3)), line), 1);
    assert_eq!(
        hashes_at(at(Some(1)), line),
        0,
        "seal_twice is a depth-2 body"
    );
}

#[test]
fn uncalled_crypto_is_never_walked_and_crypto_crates_are_never_entered() {
    let cpg = at(Some(3));
    assert!(!cpg.nodes().any(|n| n.symbol.contains("orphan")));
    assert!(!cpg
        .nodes()
        .any(|n| n.symbol.contains("384") && n.kind != NodeKind::Function));
    assert_eq!(hashes_at(cpg, line_of("vault::label(id)")), 0);
    let in_sha2 = cpg.nodes().filter(|n| {
        n.location
            .as_ref()
            .is_some_and(|l| l.file.contains("/sha2-0.10"))
    });
    assert_eq!(in_sha2.count(), 0, "a crypto crate's internals were walked");
}

#[test]
fn recursion_in_a_dependency_is_walked_once() {
    let cpg = at(Some(3));
    let countdowns = cpg
        .nodes()
        .filter(|n| n.kind == NodeKind::Function && n.symbol.contains("countdown"))
        .count();
    assert_eq!(countdowns, 1);
}
