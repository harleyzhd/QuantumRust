use std::collections::BTreeSet;
use std::path::Path;

use qr_rules::crypto::{crypto_crates, is_crypto_crate};
use qr_rules::RuleSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeclaredDependency {
    pub name: String,
    pub version: Option<String>,
}

pub fn declared_crypto(crate_root: &Path, rules: &RuleSet) -> Vec<DeclaredDependency> {
    let Ok(text) = std::fs::read_to_string(crate_root.join("Cargo.toml")) else {
        return Vec::new();
    };
    let known = crypto_crates(rules);
    let mut found: Vec<DeclaredDependency> = Vec::new();

    let mut in_deps = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(section) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_deps = section.ends_with("dependencies");
            continue;
        }
        if !in_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((name, rest)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim().trim_matches('"');
        if !is_crypto_crate(name, &known) {
            continue;
        }
        let version = rest
            .trim()
            .strip_prefix('"')
            .and_then(|v| v.split('"').next())
            .map(str::to_string);
        let entry = DeclaredDependency {
            name: name.to_string(),
            version,
        };
        if !found.contains(&entry) {
            found.push(entry);
        }
    }
    found.sort();
    found
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub name: String,
    pub version: Option<String>,
    pub library: bool,
}

impl Subject {
    pub fn purl(&self) -> String {
        match &self.version {
            Some(v) => format!("pkg:cargo/{}@{v}", self.name),
            None => format!("pkg:cargo/{}", self.name),
        }
    }
}

pub fn subject_of(crate_root: &Path) -> Option<Subject> {
    let text = std::fs::read_to_string(crate_root.join("Cargo.toml")).ok()?;
    let manifest: toml::Table = toml::from_str(&text).ok()?;
    let package = manifest.get("package")?.as_table()?;
    let name = package.get("name")?.as_str()?.to_string();
    let version = package
        .get("version")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let library = manifest.contains_key("lib")
        || crate_root.join("src/lib.rs").exists()
        || !crate_root.join("src/main.rs").exists();
    Some(Subject {
        name,
        version,
        library,
    })
}

pub fn unreached<'a>(
    declared: &[DeclaredDependency],
    seen_symbols: impl IntoIterator<Item = &'a str>,
) -> Vec<DeclaredDependency> {
    let seen: BTreeSet<String> = seen_symbols
        .into_iter()
        .flat_map(|s| {
            s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
                .filter(|t| !t.is_empty())
                .filter_map(|t| t.split("::").next())
                .map(|root| root.replace('_', "-"))
                .collect::<Vec<_>>()
        })
        .collect();
    declared
        .iter()
        .filter(|d| !seen.contains(&d.name))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, body: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("Cargo.toml"), body).unwrap();
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("qr-manifest-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn the_subject_is_the_package_the_manifest_names() {
        let lib = tmp("subject-lib");
        write(
            &lib,
            "[package]\nname = \"snow\"\nversion = \"0.10.0\"\nedition = \"2021\"\n",
        );
        std::fs::create_dir_all(lib.join("src")).unwrap();
        std::fs::write(lib.join("src/lib.rs"), "").unwrap();
        let subject = subject_of(&lib).expect("a package");
        assert_eq!(
            subject,
            Subject {
                name: "snow".into(),
                version: Some("0.10.0".into()),
                library: true
            }
        );
        assert_eq!(subject.purl(), "pkg:cargo/snow@0.10.0");

        let bin = tmp("subject-bin");
        write(
            &bin,
            "[package]\nname = \"tool\"\nversion.workspace = true\n",
        );
        std::fs::create_dir_all(bin.join("src")).unwrap();
        std::fs::write(bin.join("src/main.rs"), "fn main() {}").unwrap();
        let subject = subject_of(&bin).expect("a package");
        assert_eq!((subject.version, subject.library), (None, false));

        let virtual_manifest = tmp("subject-virtual");
        write(&virtual_manifest, "[workspace]\nmembers = []\n");
        assert_eq!(subject_of(&virtual_manifest), None);
    }

    #[test]
    fn reads_crypto_dependencies_and_ignores_the_rest() {
        let dir = tmp("basic");
        write(
            &dir,
            r#"
[package]
name = "demo"

[dependencies]
serde = "1"
rsa = "0.9"
sha2 = { version = "0.10", features = ["oid"] }
tokio = { version = "1", features = ["full"] }
"#,
        );
        let found = declared_crypto(&dir, &RuleSet::builtin());
        let names: Vec<&str> = found.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["rsa", "sha2"]);
        assert_eq!(found[0].version.as_deref(), Some("0.9"));
        assert_eq!(found[1].version, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn crate_names_normalise_across_hyphen_and_underscore() {
        let dir = tmp("hyphen");
        write(
            &dir,
            "[dependencies]\nx25519-dalek = \"2\"\ned25519-dalek = \"2\"\n",
        );
        let found = declared_crypto(&dir, &RuleSet::builtin());
        let names: Vec<&str> = found.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"x25519-dalek"), "got {names:?}");
        assert!(names.contains(&"ed25519-dalek"), "got {names:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn dep(name: &str) -> DeclaredDependency {
        DeclaredDependency {
            name: name.into(),
            version: None,
        }
    }

    #[test]
    fn a_crate_the_graph_reaches_is_not_a_declared_unknown() {
        let declared = vec![dep("rsa"), dep("sha2")];
        let gap = unreached(&declared, ["rsa::RsaPrivateKey::new", "std::vec::Vec::len"]);
        assert_eq!(gap.len(), 1);
        assert_eq!(gap[0].name, "sha2");
    }

    #[test]
    fn a_crate_reached_only_through_a_trait_path_still_counts_as_reached() {
        let declared = vec![dep("signature")];
        assert!(unreached(&declared, ["signature::Signer::sign"]).is_empty());
        assert!(unreached(&declared, ["<dyn signature::Signer>::sign"]).is_empty());
        assert!(
            unreached(&declared, ["<rsa::X as signature::Signer>::sign"]).is_empty(),
            "a qualified path names the trait's crate after `as`"
        );
    }

    #[test]
    fn a_crate_nowhere_in_the_graph_is_reported() {
        let declared = vec![dep("ed25519-dalek")];
        let gap = unreached(&declared, ["rsa::RsaPrivateKey::new"]);
        assert_eq!(gap.len(), 1);
        assert_eq!(gap[0].name, "ed25519-dalek");
    }

    #[test]
    fn a_crate_with_no_manifest_yields_nothing_rather_than_failing() {
        let dir = tmp("missing");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(declared_crypto(&dir, &RuleSet::builtin()).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
