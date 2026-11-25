mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

const FIXTURES: &[&str] = &["rustcrypto", "legacy", "ring", "openssl", "tls"];

static RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn root(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rule-coverage")
        .join(name)
}

fn expectations(name: &str) -> BTreeMap<u32, (BTreeSet<String>, String)> {
    let src = std::fs::read_to_string(root(name).join("src/lib.rs")).unwrap();
    src.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let (_, ids) = line.split_once("// expect: ")?;
            let ids = ids.split(',').map(|id| id.trim().to_string()).collect();
            Some((i as u32 + 1, (ids, line.trim().to_string())))
        })
        .collect()
}

fn rows(name: &str) -> Vec<serde_json::Value> {
    common::drivers();
    let out = std::env::temp_dir().join(format!(
        "qr-rule-coverage-{name}-{}-{}.json",
        std::process::id(),
        RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let status = Command::new(env!("CARGO_BIN_EXE_quantumrust"))
        .env("RUST_LOG", "warn")
        .arg("analyze")
        .arg(root(name))
        .arg("--findings-json")
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success(), "analyze failed on {name}");
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let _ = std::fs::remove_file(&out);
    rows.into_iter()
        .filter(|r| r["file"] == "src/lib.rs")
        .collect()
}

fn findings(name: &str) -> BTreeMap<u32, BTreeSet<String>> {
    let mut by_line: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    for row in rows(name) {
        let rules = by_line
            .entry(row["line"].as_u64().unwrap() as u32)
            .or_default();
        rules.insert(row["rule"].as_str().unwrap().to_string());
        for part in row["with"].as_array().into_iter().flatten() {
            rules.insert(part["rule"].as_str().unwrap().to_string());
        }
    }
    by_line
}

#[test]
fn every_expected_rule_fires_on_its_line() {
    let mut failures = Vec::new();
    for name in FIXTURES {
        let got = findings(name);
        for (line, (want, text)) in expectations(name) {
            let have = got.get(&line).cloned().unwrap_or_default();
            let missing: Vec<&String> = want.difference(&have).collect();
            if !missing.is_empty() {
                failures.push(format!(
                    "{name}:{line} missing {missing:?}, got {have:?} | {text}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn every_rule_is_expected_somewhere() {
    let expected: BTreeSet<String> = FIXTURES
        .iter()
        .flat_map(|name| expectations(name).into_values().flat_map(|(ids, _)| ids))
        .collect();
    let embedded: BTreeSet<String> = qr_rules::embedded_rule_ids().into_iter().collect();
    assert_eq!(expected, embedded);
}

#[test]
fn no_unresolved_fallback_reports_beside_a_named_finding_of_its_class() {
    let mut doubled = Vec::new();
    for name in FIXTURES {
        let rows = rows(name);
        for fallback in rows
            .iter()
            .filter(|r| r["rule"].as_str().unwrap().ends_with("-999") && r["status"] == "Unknown")
        {
            for named in rows.iter().filter(|r| {
                r["line"] == fallback["line"]
                    && r["class"] == fallback["class"]
                    && r["status"] != "Unknown"
            }) {
                doubled.push(format!(
                    "{name}:{} {} beside {} ({})",
                    fallback["line"], fallback["rule"], named["rule"], named["class"]
                ));
            }
        }
    }
    assert!(doubled.is_empty(), "\n{}", doubled.join("\n"));
}

#[test]
fn no_call_reports_two_rows() {
    let mut doubled = Vec::new();
    for name in FIXTURES {
        let mut seen: BTreeMap<u64, String> = BTreeMap::new();
        for row in rows(name) {
            if row["via"].as_array().is_some_and(|v| !v.is_empty()) {
                continue;
            }
            let node = row["node_id"].as_u64().unwrap();
            let rule = row["rule"].as_str().unwrap().to_string();
            if let Some(first) = seen.insert(node, rule.clone()) {
                doubled.push(format!("{name}:{} {first} and {rule}", row["line"]));
            }
        }
    }
    assert!(doubled.is_empty(), "\n{}", doubled.join("\n"));
}
