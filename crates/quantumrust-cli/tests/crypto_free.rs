mod common;

use std::process::Command;

#[test]
fn a_crate_without_cryptography_gets_a_valid_empty_cbom() {
    common::drivers();
    let dir = common::scratch("crypto-free");
    let _ = std::fs::remove_dir_all(dir.join("out"));
    std::fs::create_dir_all(&dir).unwrap();
    let out = common::bin()
        .arg("analyze")
        .arg(common::workspace_root().join("fixtures/multi-unit"))
        .args(["--format", "both", "--out"])
        .arg(dir.join("out"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", common::explain(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Findings (0):"),
        "{}",
        common::explain(&out)
    );

    let json = dir.join("out/cbom.json");
    let xml = dir.join("out/cbom.xml");
    let cbom: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    assert_eq!(cbom["components"], serde_json::json!([]), "{cbom}");

    let probe = Command::new("python3")
        .args(["-c", "import jsonschema, lxml"])
        .status();
    assert!(
        probe.is_ok_and(|s| s.success()),
        "schemas/validate_cbom.py needs python3 with jsonschema and lxml: \
         python3 -m pip install jsonschema lxml"
    );
    let check = Command::new("python3")
        .arg(common::workspace_root().join("schemas/validate_cbom.py"))
        .arg(&json)
        .arg(&xml)
        .output()
        .unwrap();
    assert!(check.status.success(), "{}", common::explain(&check));
}
