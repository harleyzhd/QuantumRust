use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const EXTRACTORS: [&str; 3] = ["mir-extract", "llvm-extract", "cpg-fusion"];

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn sources() -> Vec<(String, String)> {
    let root = workspace().join("crates");
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                if let (Some(krate), Ok(text)) =
                    (crate_of(&root, &path), std::fs::read_to_string(&path))
                {
                    out.push((krate, strip_tests(&text)));
                }
            }
        }
    }
    out.sort();
    out
}

fn crate_of(root: &Path, file: &Path) -> Option<String> {
    file.strip_prefix(root)
        .ok()?
        .components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
}

fn strip_tests(text: &str) -> String {
    let Some(at) = text.find("#[cfg(test)]") else {
        return text.to_string();
    };
    text[..at].to_string()
}

fn kinds(enum_name: &str) -> Vec<String> {
    let model = std::fs::read_to_string(workspace().join("crates/cpg-core/src/model.rs"))
        .or_else(|_| std::fs::read_to_string(workspace().join("crates/cpg-core/src/lib.rs")))
        .expect("cpg-core model");
    let at = model
        .find(&format!("pub enum {enum_name}"))
        .unwrap_or_else(|| panic!("{enum_name} not found"));
    let body = &model[at..];
    let end = body.find('}').expect("enum body");
    body[..end]
        .lines()
        .filter_map(|line| {
            let t = line.trim().trim_end_matches(',');
            (!t.is_empty()
                && !t.starts_with("//")
                && !t.starts_with('#')
                && !t.starts_with("pub enum")
                && t.chars().next().is_some_and(char::is_uppercase)
                && t.chars().all(|c| c.is_alphanumeric()))
            .then(|| t.to_string())
        })
        .collect()
}

fn usage(enum_name: &str) -> BTreeMap<String, (Vec<String>, Vec<String>)> {
    let files = sources();
    let mut out = BTreeMap::new();
    for kind in kinds(enum_name) {
        let needle = format!("{enum_name}::{kind}");
        let mut producers: Vec<String> = Vec::new();
        let mut consumers: Vec<String> = Vec::new();
        for (krate, text) in &files {
            if !text.contains(&needle) {
                continue;
            }
            if krate == "cpg-core" {
                continue;
            }
            let bucket = if EXTRACTORS.contains(&krate.as_str()) {
                &mut producers
            } else {
                &mut consumers
            };
            if !bucket.contains(krate) {
                bucket.push(krate.clone());
            }
        }
        producers.sort();
        consumers.sort();
        out.insert(kind, (producers, consumers));
    }
    out
}

fn render(enum_name: &str) -> String {
    let mut s = format!("{enum_name}\n");
    for (kind, (producers, consumers)) in usage(enum_name) {
        let p = if producers.is_empty() {
            "NOTHING".to_string()
        } else {
            producers.join(", ")
        };
        let c = if consumers.is_empty() {
            "NOTHING".to_string()
        } else {
            consumers.join(", ")
        };
        s.push_str(&format!(
            "  {kind:<14} built in: {p:<40} used outside extraction: {c}\n"
        ));
    }
    s
}

#[test]
fn the_model_is_produced_and_consumed_as_expected() {
    let report = format!("{}\n{}", render("EdgeKind"), render("NodeKind"));
    insta::assert_snapshot!(report);
}
