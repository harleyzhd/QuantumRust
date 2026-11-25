use std::process::Command;

#[test]
fn every_output_carries_the_same_verdicts() {
    let dir = std::env::temp_dir().join(format!("qr-profile-outputs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let output = Command::new(env!("CARGO_BIN_EXE_quantumrust"))
        .args([
            "analyze",
            "--profile",
            "cnsa-2.0",
            "--format",
            "both",
            "--out",
        ])
        .arg(&dir)
        .env("RUST_LOG", "warn")
        .output()
        .expect("the binary runs");
    assert!(output.status.success());
    let terminal = String::from_utf8(output.stdout).unwrap();

    let tally = terminal
        .lines()
        .find(|l| l.contains(" need review"))
        .and_then(|l| l.trim().split(" (").next())
        .expect("a tally line")
        .to_string();
    let count = |word: &str| -> usize {
        tally
            .split(", ")
            .find(|part| part.ends_with(word))
            .and_then(|part| part.split(' ').next())
            .and_then(|n| n.parse().ok())
            .unwrap()
    };
    let (pass, fail, review) = (count("pass"), count("fail"), count("need review"));
    assert!(fail > 0 && review > 0, "the demo exercises both: {tally}");

    let bom: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("cbom.json")).unwrap()).unwrap();
    let verdicts: Vec<&str> = bom["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| {
            c["properties"]
                .as_array()?
                .iter()
                .find(|p| p["name"] == "quantumrust:profile-verdict")?["value"]
                .as_str()
        })
        .collect();
    let n = |v: &str| verdicts.iter().filter(|x| **x == v).count();
    assert_eq!((n("pass"), n("fail"), n("review")), (pass, fail, review));
    assert!(bom["metadata"]["properties"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!({"name": "quantumrust:profile-tally", "value": tally})));

    let xml = std::fs::read_to_string(dir.join("cbom.xml")).unwrap();
    for v in ["pass", "fail", "review"] {
        let property = format!("<property name=\"quantumrust:profile-verdict\">{v}</property>");
        assert_eq!(xml.matches(&property).count(), n(v), "XML {v}");
    }

    let html = std::fs::read_to_string(dir.join("report.html")).unwrap();
    assert!(html.contains(&tally), "the page gives the tally");
    for v in ["pass", "fail", "review"] {
        let badge = format!("<span class=\"verdict {v}\">{v}</span>");
        assert_eq!(html.matches(&badge).count(), 2 * n(v), "page {v}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_verdict_for_an_algorithm_the_tool_never_names_is_warned_about() {
    let dir = std::env::temp_dir().join(format!("qr-profile-typo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let profile = dir.join("typo.toml");
    std::fs::write(
        &profile,
        "id = \"typo\"\nname = \"Typo\"\n[status]\nvulnerable = \"fail\"\n\
         deprecated = \"fail\"\nresistant = \"pass\"\nunknown = \"review\"\n\
         [verdicts]\n\"AES-12\" = \"pass\"\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_quantumrust"))
        .args(["analyze", "--profile"])
        .arg(&profile)
        .arg("--out")
        .arg(dir.join("out"))
        .env("RUST_LOG", "warn")
        .output()
        .expect("the binary runs");
    assert!(output.status.success());
    let terminal = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let warning = terminal
        .lines()
        .find(|l| l.contains("WARN") && l.contains("AES-12"));
    assert!(warning.is_some(), "{terminal}");
    let _ = std::fs::remove_dir_all(&dir);
}
