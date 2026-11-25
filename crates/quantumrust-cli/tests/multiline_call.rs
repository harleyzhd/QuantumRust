mod common;

use std::path::PathBuf;
use std::sync::OnceLock;

fn fixture() -> PathBuf {
    common::workspace_root().join("fixtures/multiline-call")
}

fn line_of(marker: &str) -> u32 {
    let src = std::fs::read_to_string(fixture().join("src/lib.rs")).unwrap();
    let i = src.lines().position(|l| l.contains(marker)).unwrap();
    u32::try_from(i + 1).unwrap()
}

fn findings() -> &'static [(u32, String)] {
    static ROWS: OnceLock<Vec<(u32, String)>> = OnceLock::new();
    ROWS.get_or_init(|| {
        common::drivers();
        let dir = common::scratch("multiline-call");
        std::fs::create_dir_all(&dir).unwrap();
        let json = dir.join("findings.json");
        let out = common::bin()
            .arg("analyze")
            .arg(fixture())
            .arg("--out")
            .arg(dir.join("qr-out"))
            .arg("--findings-json")
            .arg(&json)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", common::explain(&out));
        let rows: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
        rows.iter()
            .filter(|r| r["file"] == "src/lib.rs")
            .map(|r| {
                let line = u32::try_from(r["line"].as_u64().unwrap()).unwrap();
                (line, r["rule"].as_str().unwrap().to_string())
            })
            .collect()
    })
}

fn on(line: u32) -> Vec<&'static (u32, String)> {
    findings().iter().filter(|(l, _)| *l == line).collect()
}

#[test]
fn a_multiline_method_call_is_one_finding() {
    let (start, encrypt) = (line_of("// chain: starts"), line_of("// chain: encrypt"));
    let chain: Vec<_> = findings()
        .iter()
        .filter(|(l, _)| (start..=encrypt).contains(l))
        .collect();
    assert_eq!(
        chain.len(),
        1,
        "one finding for the chain: {:?}",
        findings()
    );
    assert_eq!(
        chain[0].0,
        encrypt,
        "on the `.encrypt(` line: {:?}",
        findings()
    );
    let new = line_of("// one line: new");
    assert_eq!(on(new).len(), 1, "one finding for `new`: {:?}", findings());
}

#[test]
fn a_one_line_call_keeps_its_line() {
    let decrypt = line_of("// one line: decrypt");
    assert_eq!(on(decrypt).len(), 1, "{:?}", findings());
}

#[test]
fn a_call_a_macro_writes_is_one_finding() {
    for marker in ["// macro: method", "// macro arg: decrypt"] {
        let line = line_of(marker);
        assert_eq!(on(line).len(), 1, "{marker}: {:?}", findings());
    }
    let fn_start = line_of("pub fn seal_by_macro");
    let macro_lines = findings().iter().filter(|(l, _)| *l >= fn_start).count();
    assert_eq!(
        macro_lines,
        1,
        "only the decrypt finding after `seal_by_macro`: {:?}",
        findings()
    );
}
