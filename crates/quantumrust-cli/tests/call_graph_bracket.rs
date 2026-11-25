use std::path::Path;
use std::process::Command;

fn findings(call_graph: &str, dir: &Path) -> Vec<serde_json::Value> {
    let out = dir.join(format!("{call_graph}.json"));
    let status = Command::new(env!("CARGO_BIN_EXE_quantumrust"))
        .args(["analyze", "--call-graph", call_graph, "--findings-json"])
        .arg(&out)
        .env("RUST_LOG", "warn")
        .status()
        .expect("the binary runs");
    assert!(status.success(), "analyze --call-graph {call_graph} failed");
    let text = std::fs::read_to_string(&out).expect("findings JSON written");
    serde_json::from_str(&text).expect("findings JSON parses")
}

#[test]
fn both_ends_report_the_same_findings_and_the_upper_end_reaches_further() {
    let dir = std::env::temp_dir().join(format!("qr-bracket-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let low = findings("fallback", &dir);
    let high = findings("cha", &dir);
    assert!(!low.is_empty(), "the demo CPG has findings");
    assert_eq!(low.len(), high.len());
    for (a, b) in low.iter().zip(&high) {
        for field in ["node_id", "rule", "file", "line", "tier"] {
            assert_eq!(a[field], b[field], "{field} differs between the two ends");
        }
        assert!(
            a["blast"].as_u64() <= b["blast"].as_u64(),
            "a finding lost reach under the upper bound: {a} vs {b}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
