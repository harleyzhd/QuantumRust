use std::process::Command;

use cpg_core::{AblationMode, Cpg, EdgeKind, IrLayer, NodeKind, SafetyCtx, SourceLoc};

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_quantumrust"));
    c.env("RUST_LOG", "warn");
    c
}

fn graph(dir: &std::path::Path) -> std::path::PathBuf {
    graph_with_dependency_file(dir, "/deps/vault/src/lib.rs")
}

fn graph_with_dependency_file(dir: &std::path::Path, dep_file: &str) -> std::path::PathBuf {
    let mut cpg = Cpg::new(AblationMode::MirOnly);
    let loc = |f: &str, l| Some(SourceLoc::new(f, l));
    let target = cpg.add_node_full(
        IrLayer::Mir,
        NodeKind::Function,
        "app::target",
        None,
        loc("src/lib.rs", 5),
        SafetyCtx::Safe,
    );
    let call = cpg.add_node_full(
        IrLayer::Mir,
        NodeKind::CallSite,
        "vault::seal",
        None,
        loc("src/lib.rs", 6),
        SafetyCtx::Safe,
    );
    let seal = cpg.add_node_full(
        IrLayer::Mir,
        NodeKind::Function,
        "vault::seal",
        None,
        loc(dep_file, 2),
        SafetyCtx::Safe,
    );
    let rsa = cpg.add_node_full(
        IrLayer::Mir,
        NodeKind::CallSite,
        "rsa::RsaPrivateKey::new",
        None,
        loc(dep_file, 3),
        SafetyCtx::Safe,
    );
    cpg.set_dep_depth(seal, 1);
    cpg.set_dep_depth(rsa, 1);
    cpg.add_edge(target, call, EdgeKind::Contains);
    cpg.add_edge(target, call, EdgeKind::Call);
    cpg.add_edge(call, seal, EdgeKind::Call);
    cpg.add_edge(seal, rsa, EdgeKind::Contains);
    cpg.add_edge(seal, rsa, EdgeKind::Call);
    let path = dir.join("graph.json");
    cpg.save_json(&path).unwrap();
    path
}

#[test]
fn a_dependency_finding_is_reported_at_the_local_line_with_its_path() {
    let dir = std::env::temp_dir().join(format!("qr-descend-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("findings.json");
    let status = bin()
        .args(["analyze", "--cpg"])
        .arg(graph(&dir))
        .arg("--findings-json")
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success());
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let rsa: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| r["rule"].as_str().unwrap().starts_with("R-RSA"))
        .collect();
    assert_eq!(rsa.len(), 1, "{rows:?}");
    assert_eq!(rsa[0]["file"], "src/lib.rs");
    assert_eq!(rsa[0]["line"], 6);
    assert_eq!(rsa[0]["via"][0]["symbol"], "vault::seal");
    assert_eq!(rsa[0]["via"][1]["symbol"], "rsa::RsaPrivateKey::new");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn via_frames_carry_no_absolute_path() {
    let dir = std::env::temp_dir().join(format!("qr-descend-paths-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let registry_file = "/Users/someone/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/vault-0.1.0/src/lib.rs";
    let findings = dir.join("findings.json");
    let status = bin()
        .args(["analyze", "--cpg"])
        .arg(graph_with_dependency_file(&dir, registry_file))
        .arg("--findings-json")
        .arg(&findings)
        .arg("--out")
        .arg(dir.join("out"))
        .status()
        .unwrap();
    assert!(status.success());
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&findings).unwrap()).unwrap();
    let files: Vec<&str> = rows
        .iter()
        .flat_map(|r| r["via"].as_array().into_iter().flatten())
        .filter_map(|v| v["file"].as_str())
        .collect();
    assert!(!files.is_empty(), "no via frame carried a file: {rows:?}");
    assert!(files.iter().all(|f| !f.starts_with('/')), "{files:?}");
    assert!(files.contains(&"vault-0.1.0/src/lib.rs"), "{files:?}");
    let cbom = std::fs::read_to_string(dir.join("out").join("cbom.json")).unwrap();
    assert!(!cbom.contains("/.cargo/"), "the CBOM names the cargo home");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn descend_with_a_serialized_graph_is_ignored_with_a_warning() {
    let dir = std::env::temp_dir().join(format!("qr-descend-cpg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = bin()
        .args(["analyze", "--descend", "--cpg"])
        .arg(graph(&dir))
        .output()
        .unwrap();
    assert!(out.status.success());
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        said.contains("--descend has no effect with --cpg"),
        "{said}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_depth_of_zero_is_rejected() {
    let out = bin().args(["analyze", "--descend=0"]).output().unwrap();
    assert!(!out.status.success());
}
