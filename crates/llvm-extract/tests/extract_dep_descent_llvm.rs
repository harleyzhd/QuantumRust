use std::path::PathBuf;

use cpg_core::{LlvmProvider, NodeKind};
use llvm_extract::LlvmIrProvider;

#[test]
fn reachable_dependency_code_in_the_module_is_lifted_at_its_depth() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/dep-descent");
    let plan = cpg_core::descent::plan(&root, 3, &|n: &str| n == "sha2").unwrap();
    let cpg = LlvmIrProvider {
        driver: Some(PathBuf::from(env!("CARGO_BIN_EXE_llvm-extract-driver"))),
        descent: Some(plan),
        ..Default::default()
    }
    .extract(&root)
    .unwrap();
    let depth = |name: &str| {
        cpg.nodes()
            .find(|n| n.kind == NodeKind::Function && n.symbol.contains(name))
            .map(|n| n.dep_depth)
    };
    assert_eq!(
        depth("vault::digest_with"),
        Some(Some(1)),
        "the generic wrapper's monomorphisation"
    );
    for (name, want) in [
        ("vault::seal_twice", 2),
        ("relay::forward", 1),
        ("vault::countdown", 2),
    ] {
        if let Some(found) = depth(name) {
            assert_eq!(found, Some(want), "{name}");
        }
    }
    assert_eq!(depth("vault::orphan"), None, "never called");
    assert!(
        !cpg.nodes().any(|n| n.kind == NodeKind::Function
            && n.dep_depth.is_some()
            && n.symbol.starts_with("sha2::")),
        "a crypto crate's functions are never lifted"
    );
}
