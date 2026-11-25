use std::path::PathBuf;

use cpg_core::{IrLayer, LlvmProvider, NodeKind, SafetyCtx};
use llvm_extract::LlvmIrProvider;

fn demo_crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/demo-crate")
}

#[test]
fn extracts_llvm_layer_from_demo_crate() {
    let provider = LlvmIrProvider {
        driver: Some(PathBuf::from(env!("CARGO_BIN_EXE_llvm-extract-driver"))),
        ..Default::default()
    };
    let cpg = provider
        .extract(&demo_crate_root())
        .expect("LLVM extraction over fixtures/demo-crate");

    assert!(cpg.node_count() > 0);
    assert!(cpg.nodes().all(|n| n.layer == IrLayer::Llvm));

    let has_fn = |name: &str| {
        cpg.nodes()
            .any(|n| n.kind == NodeKind::Function && n.symbol.contains(name))
    };
    assert!(has_fn("sign_with_rsa"), "missing fn sign_with_rsa");
    assert!(has_fn("use_signer"), "missing fn use_signer");

    let ffi = cpg
        .nodes()
        .find(|n| n.symbol == "RSA_sign")
        .expect("missing RSA_sign FFI call");
    assert_eq!(ffi.kind, NodeKind::FfiBoundary);
    assert_eq!(ffi.safety_ctx, SafetyCtx::Ffi);

    assert!(
        cpg.nodes().any(|n| n.kind == NodeKind::Vtable),
        "missing indirect-call Vtable node"
    );
}
