mod common;

fn rows(args: &[&str]) -> Vec<(String, u64)> {
    let json = common::scratch("empty-descent").join(format!("{}.json", args.len()));
    std::fs::create_dir_all(json.parent().unwrap()).unwrap();
    let out = common::bin()
        .arg("analyze")
        .arg(common::workspace_root().join("fixtures/multiline-call"))
        .args(args)
        .arg("--findings-json")
        .arg(&json)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", common::explain(&out));
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    rows.iter()
        .map(|r| {
            (
                r["rule"].as_str().unwrap().to_string(),
                r["line"].as_u64().unwrap(),
            )
        })
        .collect()
}

#[test]
fn an_empty_descent_plan_is_the_plain_run() {
    common::drivers();
    let cache = common::workspace_root().join("fixtures/multiline-call/target/qr-extract-descend");
    let _ = std::fs::remove_dir_all(&cache);
    let plain = rows(&[]);
    let descended = rows(&["--descend"]);
    assert_eq!(descended, plain);
    assert!(!cache.exists(), "built a descent cache for an empty plan");
}
