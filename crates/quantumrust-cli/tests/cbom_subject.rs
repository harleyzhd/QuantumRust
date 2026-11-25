mod common;

#[test]
fn the_cbom_names_the_analysed_package() {
    common::drivers();
    let crate_root = common::workspace_root().join("fixtures/multiline-call");
    let dir = common::scratch("cbom-subject");
    let _ = std::fs::remove_dir_all(&dir);
    let out = common::bin()
        .arg("analyze")
        .arg(&crate_root)
        .args(["--format", "both", "--out"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", common::explain(&out));

    let bom: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("cbom.json")).unwrap()).unwrap();
    let component = &bom["metadata"]["component"];
    assert_eq!(component["name"], "multiline-call");
    assert_eq!(component["purl"], "pkg:cargo/multiline-call@0.0.0");
    let xml = std::fs::read_to_string(dir.join("cbom.xml")).unwrap();
    assert!(xml.contains("<purl>pkg:cargo/multiline-call@0.0.0</purl>"));
}
