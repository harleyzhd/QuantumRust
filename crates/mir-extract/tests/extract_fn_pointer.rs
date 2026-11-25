#![feature(rustc_private)]

extern crate rustc_driver;

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::OnceLock;

use callgraph::{ChaCallGraphProvider, DispatchScope, FallbackCallGraphProvider, Reachability};
use cpg_core::{CallGraphProvider, Cpg, CpgNode, EdgeKind, MirProvider, NodeKind};
use mir_extract::RustcMirProvider;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/fn-pointer")
}

fn cpg() -> &'static Cpg {
    static CPG: OnceLock<Cpg> = OnceLock::new();
    CPG.get_or_init(|| {
        RustcMirProvider {
            driver: Some(PathBuf::from(env!("CARGO_BIN_EXE_mir-extract-driver"))),
            ..Default::default()
        }
        .extract(&fixture_root())
        .expect("extraction over fixtures/fn-pointer")
    })
}

fn function<'a>(cpg: &'a Cpg, name: &str) -> &'a CpgNode {
    let suffix = format!("::{name}");
    cpg.nodes()
        .find(|n| n.kind == NodeKind::Function && n.symbol.ends_with(&suffix))
        .unwrap_or_else(|| panic!("no function node for {name}"))
}

fn targets(cpg: &Cpg, from: &CpgNode, kind: EdgeKind) -> HashSet<u32> {
    cpg.edges()
        .into_iter()
        .filter(|(a, _, k)| *a == from.id && *k == kind)
        .map(|(_, b, _)| b)
        .collect()
}

fn inside<'a>(cpg: &'a Cpg, caller: &str, kind: NodeKind) -> Vec<&'a CpgNode> {
    let contained = targets(cpg, function(cpg, caller), EdgeKind::Contains);
    cpg.nodes()
        .filter(|n| contained.contains(&n.id) && n.kind == kind)
        .collect()
}

fn indirect<'a>(cpg: &'a Cpg, caller: &str) -> &'a CpgNode {
    let found = inside(cpg, caller, NodeKind::IndirectCall);
    assert_eq!(found.len(), 1, "{caller} makes one call through a pointer");
    found[0]
}

fn callees(cpg: &Cpg, from: &CpgNode) -> BTreeSet<String> {
    let to = targets(cpg, from, EdgeKind::Call);
    cpg.nodes()
        .filter(|n| to.contains(&n.id))
        .map(|n| n.symbol.rsplit("::").next().unwrap_or_default().to_string())
        .collect()
}

fn top_level_refs(cpg: &Cpg) -> Vec<&CpgNode> {
    let contained: HashSet<u32> = cpg
        .edges()
        .into_iter()
        .filter(|(_, _, k)| *k == EdgeKind::Contains)
        .map(|(_, b, _)| b)
        .collect();
    cpg.nodes()
        .filter(|n| n.kind == NodeKind::FnRef && !contained.contains(&n.id))
        .collect()
}

#[test]
fn every_call_through_a_pointer_is_a_node() {
    let cpg = cpg();
    for caller in [
        "local_pointer",
        "chosen",
        "through_static",
        "callback",
        "via_const",
        "hash_with",
    ] {
        indirect(cpg, caller);
    }
}

#[test]
fn an_indirect_call_carries_its_pointer_type() {
    let cpg = cpg();
    assert_eq!(
        indirect(cpg, "through_static").fn_sig.as_deref(),
        Some("fn(u64, u8) -> u64")
    );
    assert_eq!(
        indirect(cpg, "hash_with").fn_sig.as_deref(),
        Some("fn(&[u8]) -> u64")
    );
}

#[test]
fn a_pointer_the_body_assigned_once_reaches_its_function() {
    let cpg = cpg();
    let call = indirect(cpg, "local_pointer");
    assert_eq!(callees(cpg, call), BTreeSet::from(["sign".to_string()]));

    let mix_in_sign = inside(cpg, "sign", NodeKind::CallSite)
        .into_iter()
        .find(|n| n.symbol.ends_with("mix"))
        .expect("sign calls mix");
    assert!(
        targets(cpg, call, EdgeKind::ArgFlow).contains(&mix_in_sign.id),
        "the key passed through the pointer reaches sign's body"
    );
}

#[test]
fn a_pointer_chosen_between_two_functions_reaches_both() {
    let cpg = cpg();
    assert_eq!(
        callees(cpg, indirect(cpg, "chosen")),
        BTreeSet::from(["sign".to_string(), "verify".to_string()])
    );
}

#[test]
fn a_pointer_the_body_did_not_assign_stays_unresolved() {
    let cpg = cpg();
    for caller in ["through_static", "callback", "via_const", "hash_with"] {
        assert!(
            callees(cpg, indirect(cpg, caller)).is_empty(),
            "{caller}'s pointer is not the body's to resolve"
        );
    }
}

#[test]
fn the_key_flows_into_an_unresolved_call() {
    let cpg = cpg();
    let keygen = inside(cpg, "through_static", NodeKind::CallSite)
        .into_iter()
        .find(|n| n.symbol.ends_with("keygen"))
        .expect("through_static calls keygen");
    let call = indirect(cpg, "through_static");
    assert!(targets(cpg, keygen, EdgeKind::DataDep).contains(&call.id));
}

#[test]
fn every_function_used_as_a_value_is_a_reference() {
    let cpg = cpg();
    let named = |caller: &str| -> BTreeSet<String> {
        inside(cpg, caller, NodeKind::FnRef)
            .into_iter()
            .map(|n| n.symbol.rsplit("::").next().unwrap_or_default().to_string())
            .collect()
    };
    assert_eq!(named("local_pointer"), BTreeSet::from(["sign".into()]));
    assert_eq!(
        named("chosen"),
        BTreeSet::from(["sign".into(), "verify".into()])
    );
    assert_eq!(named("item_as_value"), BTreeSet::from(["sign".into()]));

    let mut top: Vec<String> = top_level_refs(cpg)
        .into_iter()
        .map(|n| n.symbol.rsplit("::").next().unwrap_or_default().to_string())
        .collect();
    top.sort();
    assert_eq!(
        top,
        [
            "digest",
            "sign",
            "sign",
            "verify",
            "{closure#0}",
            "{closure#1}"
        ]
    );
}

#[test]
fn a_reference_carries_its_functions_type_and_leads_to_its_body() {
    let cpg = cpg();
    let sign = function(cpg, "sign");
    let refs: Vec<&CpgNode> = cpg.nodes().filter(|n| n.kind == NodeKind::FnRef).collect();
    assert_eq!(refs.len(), 10, "four in bodies, six in initialisers");
    for r in refs {
        let sig = r
            .fn_sig
            .as_deref()
            .unwrap_or_else(|| panic!("{} has no type", r.symbol));
        assert!(
            sig == "fn(u64, u8) -> u64" || sig == "fn(&[u8]) -> u64",
            "{}: {sig}",
            r.symbol
        );
        assert_eq!(
            targets(cpg, r, EdgeKind::Call).len(),
            1,
            "{} leads to the body it names",
            r.symbol
        );
        if r.symbol.ends_with("::sign") {
            assert!(targets(cpg, r, EdgeKind::Call).contains(&sign.id));
        }
    }
}

#[test]
fn only_the_upper_bound_follows_a_pointer_out_of_a_static() {
    let cpg = cpg();
    let mix_in_sign = inside(cpg, "sign", NodeKind::CallSite)
        .into_iter()
        .find(|n| n.symbol.ends_with("mix"))
        .expect("sign calls mix")
        .id;
    let mix_in_digest = inside(cpg, "digest", NodeKind::CallSite)
        .into_iter()
        .find(|n| n.symbol.ends_with("mix"))
        .expect("digest calls mix")
        .id;
    let reaches = |graph: &cpg_core::CallGraph, from: &CpgNode, to: u32| {
        Reachability::over_call_graph(graph)
            .reachable(from.id)
            .contains(&to)
    };

    let low = FallbackCallGraphProvider.build(cpg).unwrap();
    let high = ChaCallGraphProvider {
        scope: DispatchScope::AllUnresolved,
    }
    .build(cpg)
    .unwrap();
    let call = indirect(cpg, "through_static");
    assert!(!reaches(&low, call, mix_in_sign));
    assert!(reaches(&high, call, mix_in_sign));
    assert!(
        !reaches(&high, call, mix_in_digest),
        "a fn(u64, u8) pointer cannot hold digest"
    );
    assert!(reaches(&high, indirect(cpg, "hash_with"), mix_in_digest));

    let fn_call = inside(cpg, "apply", NodeKind::TraitMethod)
        .into_iter()
        .find(|n| n.symbol.contains("call"))
        .expect("apply calls its closure parameter");
    assert!(!reaches(&low, fn_call, mix_in_sign));
    assert!(reaches(&high, fn_call, mix_in_sign));
}
