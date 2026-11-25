#![feature(rustc_private)]

extern crate rustc_driver;

use std::path::PathBuf;

use cpg_core::{Cpg, CpgNode, EdgeKind, MirProvider, NodeKind};
use mir_extract::RustcMirProvider;

fn multi_unit_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/multi-unit")
}

fn extract() -> Cpg {
    RustcMirProvider {
        driver: Some(PathBuf::from(env!("CARGO_BIN_EXE_mir-extract-driver"))),
        ..Default::default()
    }
    .extract(&multi_unit_root())
    .expect("extraction over fixtures/multi-unit")
}

fn node<'a>(cpg: &'a Cpg, kind: NodeKind, symbol: &str, file: &str) -> &'a CpgNode {
    cpg.nodes()
        .find(|n| {
            n.kind == kind
                && n.symbol == symbol
                && n.location.as_ref().is_some_and(|l| l.file.ends_with(file))
        })
        .unwrap_or_else(|| panic!("no {kind:?} {symbol} in {file}"))
}

fn has_edge(cpg: &Cpg, from: u32, to: u32, kind: EdgeKind) -> bool {
    cpg.edges()
        .iter()
        .any(|(s, t, k)| *s == from && *t == to && *k == kind)
}

#[test]
fn links_calls_to_bodies_in_another_compilation_unit() {
    let cpg = extract();

    assert!(
        cpg.nodes()
            .any(|n| n.kind == NodeKind::Function && n.symbol.contains("build_secret")),
        "the library unit is missing from the merged graph"
    );
    assert!(
        cpg.nodes()
            .any(|n| n.kind == NodeKind::Function && n.symbol.contains("main")),
        "the binary unit is missing from the merged graph"
    );

    let call = node(
        &cpg,
        NodeKind::CallSite,
        "multi_unit::build_secret",
        "main.rs",
    );
    let body = node(
        &cpg,
        NodeKind::Function,
        "multi_unit::build_secret",
        "lib.rs",
    );
    assert!(
        has_edge(&cpg, call.id, body.id, EdgeKind::Call),
        "call site in the binary is not linked to its body in the library"
    );

    let inner = cpg
        .nodes()
        .find(|n| {
            n.kind == NodeKind::CallSite
                && n.location
                    .as_ref()
                    .is_some_and(|l| l.file.ends_with("lib.rs"))
                && n.symbol.contains("to_vec")
        })
        .expect("the library body's parameter-consuming call");
    assert!(
        has_edge(&cpg, call.id, inner.id, EdgeKind::ArgFlow),
        "argument flow does not enter the callee across the unit boundary"
    );
    assert!(
        has_edge(&cpg, inner.id, call.id, EdgeKind::ReturnFlow),
        "return flow does not leave the callee across the unit boundary"
    );
}

#[test]
fn a_definition_carries_the_key_its_callers_compute() {
    let cpg = extract();
    let body = node(
        &cpg,
        NodeKind::Function,
        "multi_unit::build_secret",
        "lib.rs",
    );
    let call = node(
        &cpg,
        NodeKind::CallSite,
        "multi_unit::build_secret",
        "main.rs",
    );
    assert!(body.canonical.is_some(), "definition has no canonical key");
    assert_eq!(
        body.canonical, call.canonical,
        "definition and call site disagree on the key"
    );
}
