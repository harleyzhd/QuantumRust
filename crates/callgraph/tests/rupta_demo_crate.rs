use std::path::{Path, PathBuf};

use callgraph::cha::dispatch_edges;
use callgraph::{
    forward_reachable, DispatchScope, FallbackCallGraphProvider, RuptaCallGraphProvider,
};
use cpg_core::{AblationMode, CallGraphProvider, Cpg, EdgeKind, IrLayer, NodeKind};

fn demo_crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/demo-crate")
}

const LINK_NAME: &str = "qr-cargo-pta.testlink";

fn link_in_cwd(target: &Path) -> std::io::Result<PathBuf> {
    let target = target.canonicalize()?;
    let link = std::env::current_dir()?.join(LINK_NAME);
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&target, &link)?;
    Ok(link)
}

struct LinkGuard(PathBuf);

impl Drop for LinkGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn fixture_cpg() -> Cpg {
    let mut c = Cpg::new(AblationMode::MirOnly);
    let main = c.add_node(IrLayer::Mir, NodeKind::Function, "demo_crate::main", None);
    let swr = c.add_node(
        IrLayer::Mir,
        NodeKind::Function,
        "demo_crate::sign_with_rsa",
        None,
    );
    let ffi_fn = c.add_node(
        IrLayer::Mir,
        NodeKind::Function,
        "demo_crate::sign_via_ffi",
        None,
    );
    let ffi = c.add_node(
        IrLayer::Mir,
        NodeKind::FfiBoundary,
        "openssl_sys::RSA_sign",
        None,
    );
    c.add_edge(main, swr, EdgeKind::Call);
    c.add_edge(ffi_fn, ffi, EdgeKind::Contains);
    c
}

#[test]
fn rupta_adapter_maps_demo_crate_call_graph() {
    let Some(configured) = std::env::var_os(callgraph::rupta::CARGO_PTA_ENV) else {
        eprintln!(
            "skipping: {} not set (build Rupta and export the cargo-pta path to run this)",
            callgraph::rupta::CARGO_PTA_ENV
        );
        return;
    };

    let configured = PathBuf::from(configured);
    let link = link_in_cwd(&configured).unwrap_or_else(|e| {
        panic!(
            "{} is set to {} but linking it failed: {e}",
            callgraph::rupta::CARGO_PTA_ENV,
            configured.display()
        )
    });
    let _guard = LinkGuard(link);
    let cargo_pta = PathBuf::from(LINK_NAME);
    assert!(
        cargo_pta.is_relative(),
        "the point of this test is the relative case; got {}",
        cargo_pta.display()
    );

    let cpg = fixture_cpg();
    let provider = RuptaCallGraphProvider {
        crate_root: demo_crate_root(),
        cargo_pta: Some(cargo_pta),
    };
    let cg = provider.build(&cpg).expect("cargo-pta run + DOT mapping");

    assert!(!cg.edges.is_empty(), "no edges mapped onto the CPG");
    let fallback = FallbackCallGraphProvider.build(&cpg).expect("fallback");
    for edge in &fallback.edges {
        assert!(cg.edges.contains(edge), "dropped fallback edge {edge:?}");
    }
    assert!(cg.edges.contains(&(0, 1)), "missing main -> sign_with_rsa");
    let cha = dispatch_edges(&cpg, DispatchScope::AllUnresolved);
    for edge in cg.edges.iter().filter(|e| !fallback.edges.contains(e)) {
        assert!(
            cha.contains(edge),
            "{edge:?} lies outside the class-hierarchy bound"
        );
    }
    assert!(forward_reachable(&cg, 0) >= 1);
}

fn dyn_dispatch_cpg() -> (Cpg, u32, u32, u32) {
    use cpg_core::SourceLoc;
    let at = |line| Some(SourceLoc::new("src/main.rs", line));
    let mut c = Cpg::new(AblationMode::MirOnly);
    let rsa = c.add_node(
        IrLayer::Mir,
        NodeKind::Function,
        "dyn_dispatch::<Rsa as Signer>::sign",
        at(13),
    );
    let ecdsa = c.add_node(
        IrLayer::Mir,
        NodeKind::Function,
        "dyn_dispatch::<Ecdsa as Signer>::sign",
        at(19),
    );
    let sign_with = c.add_node(
        IrLayer::Mir,
        NodeKind::Function,
        "dyn_dispatch::sign_with",
        at(32),
    );
    let call = c.add_node(
        IrLayer::Mir,
        NodeKind::TraitMethod,
        "<dyn Signer>::sign",
        at(33),
    );
    c.add_edge(sign_with, call, EdgeKind::Contains);
    c.add_edge(sign_with, call, EdgeKind::Call);
    let id = |n| c.node(n).id;
    let ids = (id(call), id(rsa), id(ecdsa));
    (c, ids.0, ids.1, ids.2)
}

#[test]
fn rupta_resolves_dyn_dispatch_to_the_constructed_impl() {
    let Some(configured) = std::env::var_os(callgraph::rupta::CARGO_PTA_ENV) else {
        eprintln!("skipping: {} not set", callgraph::rupta::CARGO_PTA_ENV);
        return;
    };
    let (cpg, call, rsa, ecdsa) = dyn_dispatch_cpg();
    let provider = RuptaCallGraphProvider {
        crate_root: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/dyn-dispatch"),
        cargo_pta: Some(
            PathBuf::from(configured)
                .canonicalize()
                .expect("cargo-pta exists"),
        ),
    };
    let cg = provider.build(&cpg).expect("cargo-pta run + DOT mapping");
    let fallback = FallbackCallGraphProvider.build(&cpg).expect("fallback");
    let added: Vec<(u32, u32)> = cg
        .edges
        .iter()
        .copied()
        .filter(|e| !fallback.edges.contains(e))
        .collect();
    assert_eq!(
        added,
        [(call, rsa)],
        "Rupta should resolve the call to Rsa only"
    );
    let cha = dispatch_edges(&cpg, DispatchScope::Dyn);
    assert!(cha.contains(&(call, rsa)) && cha.contains(&(call, ecdsa)));
}
