#![feature(rustc_private)]

extern crate rustc_driver;

use std::path::PathBuf;

use cpg_core::{EdgeKind, IrLayer, MirProvider, NodeKind, SafetyCtx};
use mir_extract::RustcMirProvider;

fn demo_crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/demo-crate")
}

fn extract() -> cpg_core::Cpg {
    RustcMirProvider {
        driver: Some(PathBuf::from(env!("CARGO_BIN_EXE_mir-extract-driver"))),
        ..Default::default()
    }
    .extract(&demo_crate_root())
    .expect("extraction over fixtures/demo-crate")
}

#[test]
fn extracts_golden_cases_from_demo_crate() {
    let provider = RustcMirProvider {
        driver: Some(PathBuf::from(env!("CARGO_BIN_EXE_mir-extract-driver"))),
        ..Default::default()
    };
    let cpg = provider
        .extract(&demo_crate_root())
        .expect("extraction over fixtures/demo-crate");

    assert!(cpg.node_count() > 0);
    assert!(cpg.nodes().all(|n| n.layer == IrLayer::Mir));

    let has_fn = |name: &str| {
        cpg.nodes()
            .any(|n| n.kind == NodeKind::Function && n.symbol.contains(name))
    };
    assert!(has_fn("sign_with_rsa"), "missing fn sign_with_rsa");
    assert!(has_fn("use_signer"), "missing fn use_signer");
    assert!(has_fn("sign_via_ffi"), "missing fn sign_via_ffi");

    let dyn_sign = cpg
        .nodes()
        .find(|n| {
            n.kind == NodeKind::TraitMethod && n.symbol.contains("dyn") && n.symbol.contains("sign")
        })
        .expect("missing <dyn ...Signer...>::sign trait-method node");
    assert!(
        dyn_sign.symbol.contains("Signer"),
        "got: {}",
        dyn_sign.symbol
    );

    let ffi = cpg
        .nodes()
        .find(|n| n.symbol.contains("RSA_sign"))
        .expect("missing openssl_sys::RSA_sign call site");
    assert_eq!(ffi.safety_ctx, SafetyCtx::Ffi, "got: {:?}", ffi);

    assert!(
        cpg.nodes().any(|n| n.symbol.contains("RsaPrivateKey")),
        "missing RsaPrivateKey call site"
    );

    assert!(
        cpg.nodes().any(|n| n.kind == NodeKind::Predicate),
        "missing Predicate node"
    );
    let kinds: Vec<EdgeKind> = cpg.edges().iter().map(|(_, _, k)| *k).collect();
    assert!(
        kinds.contains(&EdgeKind::ControlDep),
        "missing ControlDep edge"
    );
    assert!(kinds.contains(&EdgeKind::Contains), "missing Contains edge");
    assert!(kinds.contains(&EdgeKind::Call), "missing Call edge");

    let symbol_of = |id: u32| {
        cpg.nodes()
            .find(|n| n.id == id)
            .map(|n| n.symbol.clone())
            .unwrap_or_default()
    };
    let data_deps: Vec<(u32, u32)> = cpg
        .edges()
        .iter()
        .filter(|(_, _, k)| {
            matches!(
                k,
                EdgeKind::DataDep | EdgeKind::ArgFlow | EdgeKind::ReturnFlow
            )
        })
        .map(|(s, t, _)| (*s, *t))
        .collect();
    assert!(!data_deps.is_empty(), "no DataDep edges extracted");
    assert!(
        kinds.contains(&EdgeKind::ArgFlow) && kinds.contains(&EdgeKind::ReturnFlow),
        "interprocedural flow edges missing; local callees were not linked"
    );

    let key_construction = cpg
        .nodes()
        .find(|n| n.symbol.contains("RsaPrivateKey"))
        .expect("missing RsaPrivateKey call site")
        .id;
    let mut reached = vec![key_construction];
    let mut frontier = vec![key_construction];
    while let Some(current) = frontier.pop() {
        for (_, next) in data_deps.iter().filter(|(s, _)| *s == current) {
            if !reached.contains(next) {
                reached.push(*next);
                frontier.push(*next);
            }
        }
    }
    let chain: Vec<String> = reached.iter().map(|id| symbol_of(*id)).collect();
    assert!(
        chain.iter().any(|s| s.contains("sign_with_rng")),
        "no DataDep path from RSA key construction to the signing call; reached: {chain:#?}"
    );

    let enclosing: std::collections::HashMap<u32, String> = cpg
        .edges()
        .iter()
        .filter(|(_, _, k)| *k == EdgeKind::Contains)
        .map(|(owner, member, _)| (*member, symbol_of(*owner)))
        .collect();
    let crosses_a_boundary = cpg
        .nodes()
        .filter(|n| n.symbol.contains("RsaPrivateKey"))
        .any(|source| {
            let home = enclosing.get(&source.id);
            let mut seen = vec![source.id];
            let mut frontier = vec![source.id];
            while let Some(current) = frontier.pop() {
                for (_, next) in data_deps.iter().filter(|(s, _)| *s == current) {
                    if !seen.contains(next) {
                        seen.push(*next);
                        frontier.push(*next);
                    }
                }
            }
            seen.iter()
                .any(|id| symbol_of(*id).contains("sign_with_rng") && enclosing.get(id) != home)
        });
    assert!(
        crosses_a_boundary,
        "no interprocedural DataDep path: every key construction reaches a signing \
         call only inside its own function"
    );
}

#[test]
fn a_resolvable_trait_call_carries_an_edge_to_its_impl() {
    let cpg = extract();
    let node = |id: u32| cpg.nodes().find(|n| n.id == id).expect("node");
    let resolutions: Vec<(String, String)> = cpg
        .edges()
        .into_iter()
        .filter(|(_, _, k)| *k == EdgeKind::TraitResolve)
        .map(|(s, t, _)| (node(s).symbol.clone(), node(t).symbol.clone()))
        .collect();

    assert!(
        resolutions
            .iter()
            .any(|(from, to)| from == "signature::Signer::sign"
                && to.contains("rsa::pkcs1v15::signing_key::SigningKey")),
        "the bare trait call should resolve to the RSA signing key, got {resolutions:#?}"
    );
}

#[test]
fn a_dyn_dispatch_is_left_unresolved_for_the_llvm_layer() {
    let cpg = extract();
    let node = |id: u32| cpg.nodes().find(|n| n.id == id).expect("node");
    let dyn_resolved = cpg
        .edges()
        .into_iter()
        .filter(|(_, _, k)| *k == EdgeKind::TraitResolve)
        .any(|(s, _, _)| node(s).symbol.starts_with("<dyn "));

    assert!(
        !dyn_resolved,
        "a `dyn` call cannot be resolved statically; claiming otherwise would \
         invent a target the compiler itself does not know"
    );
}

#[test]
fn an_unextracted_impl_still_gets_a_node_to_point_at() {
    let cpg = extract();
    let node = |id: u32| cpg.nodes().find(|n| n.id == id).expect("node");
    let stubs: Vec<&str> = cpg
        .edges()
        .into_iter()
        .filter(|(_, _, k)| *k == EdgeKind::TraitResolve)
        .map(|(_, t, _)| node(t))
        .filter(|n| n.location.is_none())
        .map(|n| n.symbol.as_str())
        .collect();
    assert!(
        !stubs.is_empty(),
        "every crypto impl is in a dependency, so at least one target is a stub"
    );
}
