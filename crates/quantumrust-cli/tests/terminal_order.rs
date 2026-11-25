use std::process::Command;

use cpg_core::{AblationMode, Cpg, EdgeKind, IrLayer, NodeKind, SafetyCtx, SourceLoc};

fn graph(dir: &std::path::Path) -> std::path::PathBuf {
    let mut cpg = Cpg::new(AblationMode::MirOnly);
    let loc = |l| Some(SourceLoc::new("src/lib.rs", l));
    let f = cpg.add_node_full(
        IrLayer::Mir,
        NodeKind::Function,
        "app::f",
        None,
        loc(1),
        SafetyCtx::Safe,
    );
    for (line, symbol) in [
        (2, "aes::Aes256::new"),
        (3, "md5::Md5::digest"),
        (4, "rsa::RsaPrivateKey::new"),
    ] {
        let call = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::CallSite,
            symbol,
            None,
            loc(line),
            SafetyCtx::Safe,
        );
        cpg.add_edge(f, call, EdgeKind::Contains);
    }
    let path = dir.join("graph.json");
    cpg.save_json(&path).unwrap();
    path
}

fn printed_tiers(stdout: &str) -> Vec<u32> {
    let list = &stdout[stdout.find("Findings (").expect("a findings list")..];
    list.lines()
        .filter(|l| l.trim_start().starts_with("[R-"))
        .map(|l| {
            let at = l.find(" tier=").expect("a tier on every finding line") + " tier=".len();
            l[at..at + 1].parse().unwrap()
        })
        .collect()
}

#[test]
fn the_terminal_lists_findings_tier_first() {
    let dir = std::env::temp_dir().join(format!("qr-terminal-order-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_quantumrust"))
        .env("RUST_LOG", "warn")
        .args(["analyze", "--cpg"])
        .arg(graph(&dir))
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(printed_tiers(&stdout), vec![1, 2, 3], "{stdout}");
}
