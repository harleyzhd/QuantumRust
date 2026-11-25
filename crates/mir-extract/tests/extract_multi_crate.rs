#![feature(rustc_private)]

extern crate rustc_driver;

use std::path::PathBuf;

use cpg_core::{Cpg, MirProvider, NodeKind, QvStatus};
use mir_extract::RustcMirProvider;
use qr_rules::RuleSet;

fn multi_crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/multi-crate")
}

fn extract() -> Cpg {
    RustcMirProvider {
        driver: Some(PathBuf::from(env!("CARGO_BIN_EXE_mir-extract-driver"))),
        ..Default::default()
    }
    .extract(&multi_crate_root())
    .expect("extraction over fixtures/multi-crate")
}

#[test]
fn taint_chains_resolve_across_a_crate_boundary() {
    let cpg = extract();

    for symbol in ["make_signing_key", "sign_detached"] {
        assert!(
            cpg.nodes()
                .any(|n| n.kind == NodeKind::Function && n.symbol.contains(symbol)),
            "{symbol} is missing — one crate did not reach the merged graph"
        );
    }

    let rules = RuleSet::builtin();
    let findings = qr_taint::annotate(&cpg, &rules, rules.match_cpg(&cpg));

    let crossing: Vec<&cpg_core::Finding> = findings
        .iter()
        .filter(|f| {
            f.qv_status == QvStatus::Vulnerable
                && f.taint_chain.iter().any(|l| l.file.contains("keyring"))
                && f.taint_chain.iter().any(|l| l.file.contains("signer"))
        })
        .collect();

    assert!(
        !crossing.is_empty(),
        "no taint chain crosses the crate boundary; chains were: {:#?}",
        findings
            .iter()
            .map(|f| (&f.contextual_signature, &f.taint_chain))
            .collect::<Vec<_>>()
    );

    let chain = &crossing[0].taint_chain;
    assert!(
        chain.first().is_some_and(|l| l.file.contains("keyring")),
        "chain should start in keyring: {chain:#?}"
    );
    assert!(
        chain.last().is_some_and(|l| l.file.contains("signer")),
        "chain should end in signer: {chain:#?}"
    );
}
