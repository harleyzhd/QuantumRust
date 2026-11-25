#![feature(rustc_private)]

extern crate rustc_driver;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::OnceLock;

use cpg_core::{ArgMap, Cpg, CpgNode, EdgeKind, MirProvider, NodeKind};
use mir_extract::RustcMirProvider;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/flow-sensitivity")
}

fn cpg() -> &'static Cpg {
    static CPG: OnceLock<Cpg> = OnceLock::new();
    CPG.get_or_init(|| {
        RustcMirProvider {
            driver: Some(PathBuf::from(env!("CARGO_BIN_EXE_mir-extract-driver"))),
            ..Default::default()
        }
        .extract(&fixture_root())
        .expect("extraction over fixtures/flow-sensitivity")
    })
}

fn calls<'a>(cpg: &'a Cpg, caller: &str, callee: &str) -> Vec<&'a CpgNode> {
    let function = cpg
        .nodes()
        .find(|n| n.kind == NodeKind::Function && n.symbol.ends_with(caller))
        .unwrap_or_else(|| panic!("no function node for {caller}"));
    let contained: HashSet<u32> = cpg
        .edges()
        .into_iter()
        .filter(|(from, _, kind)| *from == function.id && *kind == EdgeKind::Contains)
        .map(|(_, to, _)| to)
        .collect();
    let mut found: Vec<&CpgNode> = cpg
        .nodes()
        .filter(|n| contained.contains(&n.id) && n.symbol.ends_with(callee))
        .collect();
    found.sort_by_key(|n| n.location.as_ref().map_or(0, |l| l.line));
    found
}

fn data_dep(cpg: &Cpg, from: &CpgNode, to: &CpgNode) -> bool {
    cpg.edges()
        .into_iter()
        .any(|(a, b, kind)| a == from.id && b == to.id && kind == EdgeKind::DataDep)
}

#[test]
fn a_reassigned_local_reaches_only_the_uses_after_each_write() {
    let cpg = cpg();
    let small = &calls(cpg, "reassigned", "keygen_2048")[..];
    let large = &calls(cpg, "reassigned", "keygen_4096")[..];
    let signs = calls(cpg, "reassigned", "sign");
    assert_eq!(
        (small.len(), large.len(), signs.len()),
        (1, 1, 2),
        "fixture shape"
    );

    assert!(
        data_dep(cpg, small[0], signs[0]),
        "2048-bit key reaches the first signing"
    );
    assert!(
        data_dep(cpg, large[0], signs[1]),
        "4096-bit key reaches the second signing"
    );
    assert!(
        !data_dep(cpg, small[0], signs[1]),
        "the 2048-bit key was overwritten before the second signing"
    );
    assert!(
        !data_dep(cpg, large[0], signs[0]),
        "the 4096-bit key does not exist yet at the first signing"
    );
}

#[test]
fn both_branches_of_a_join_reach_the_use() {
    let cpg = cpg();
    let small = calls(cpg, "branched", "keygen_2048");
    let large = calls(cpg, "branched", "keygen_4096");
    let signs = calls(cpg, "branched", "sign");
    assert_eq!(signs.len(), 1, "fixture shape");
    assert!(data_dep(cpg, small[0], signs[0]));
    assert!(data_dep(cpg, large[0], signs[0]));
}

#[test]
fn a_value_written_late_in_a_loop_reaches_a_use_earlier_in_it() {
    let cpg = cpg();
    let small = calls(cpg, "looped", "keygen_2048");
    let large = calls(cpg, "looped", "keygen_4096");
    let signs = calls(cpg, "looped", "sign");
    assert_eq!(signs.len(), 1, "fixture shape");
    assert!(data_dep(cpg, small[0], signs[0]), "first iteration");
    assert!(data_dep(cpg, large[0], signs[0]), "every later iteration");
}

#[test]
fn a_value_returned_beside_a_question_mark_still_leaves_the_function() {
    let cpg = cpg();
    let key = &calls(cpg, "early_return", "keygen_2048")[0];
    let function = cpg
        .nodes()
        .find(|n| n.kind == NodeKind::Function && n.symbol.ends_with("early_return"))
        .expect("early_return's function node");
    let returns = cpg
        .edges()
        .into_iter()
        .any(|(a, b, kind)| a == key.id && b == function.id && kind == EdgeKind::ReturnFlow);
    assert!(
        returns,
        "the key reaches the return place on the normal path"
    );
}

fn positions(cpg: &Cpg, from: &CpgNode, to: &CpgNode, kind: EdgeKind) -> ArgMap {
    let found: Vec<ArgMap> = cpg
        .edges_full()
        .into_iter()
        .filter(|(a, b, edge)| *a == from.id && *b == to.id && edge.kind == kind)
        .map(|(_, _, edge)| edge.args)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "expected one {kind:?} edge, found {found:?}"
    );
    found.into_iter().next().unwrap()
}

#[test]
fn argument_positions_are_recorded_on_both_edge_kinds() {
    let cpg = cpg();
    let keygen = &calls(cpg, "two_params", "keygen_2048")[0];
    let label = &calls(cpg, "two_params", "label")[0];
    let site = &calls(cpg, "two_params", "use_both")[0];
    let sign = &calls(cpg, "use_both", "sign")[0];
    let record = &calls(cpg, "use_both", "record")[0];

    assert_eq!(
        positions(cpg, keygen, site, EdgeKind::DataDep),
        ArgMap::from_result(ArgMap::bit(0)),
        "the key is use_both's first argument"
    );
    assert_eq!(
        positions(cpg, label, site, EdgeKind::DataDep),
        ArgMap::from_result(ArgMap::bit(1)),
        "the label is its second"
    );
    assert_eq!(
        positions(cpg, site, sign, EdgeKind::ArgFlow),
        ArgMap(vec![(0, ArgMap::bit(0))]),
        "only the first parameter reaches sign"
    );
    assert_eq!(
        positions(cpg, site, record, EdgeKind::ArgFlow),
        ArgMap(vec![(1, ArgMap::bit(0))]),
        "only the second parameter reaches record"
    );
}

#[test]
fn a_write_through_a_mutable_borrow_reaches_the_next_reader() {
    let cpg = cpg();
    let keygen = &calls(cpg, "absorbed", "keygen_2048")[0];
    let absorb = &calls(cpg, "absorbed", "absorb")[0];
    let finish = &calls(cpg, "absorbed", "finish")[0];
    assert!(
        data_dep(cpg, keygen, absorb),
        "the key is absorb's argument"
    );
    assert!(
        data_dep(cpg, absorb, finish),
        "absorb writes h through &mut self; finish reads h"
    );
}
