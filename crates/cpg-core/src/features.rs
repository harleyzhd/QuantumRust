use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pass {
    pub cargo_args: Vec<String>,
    pub label: String,
}

impl Pass {
    fn default_features() -> Self {
        Self {
            cargo_args: Vec::new(),
            label: "default".into(),
        }
    }

    fn all_features() -> Self {
        Self {
            cargo_args: vec!["--all-features".into()],
            label: "all-features".into(),
        }
    }

    fn one(feature: &str) -> Self {
        Self {
            cargo_args: vec!["--features".into(), feature.to_string()],
            label: sanitise(feature),
        }
    }

    #[must_use]
    pub fn is_default(&self) -> bool {
        self.cargo_args.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub default_pass: Pass,
    pub all_pass: Option<Pass>,
    pub individual: Vec<Pass>,
}

impl Plan {
    #[must_use]
    pub fn default_only() -> Self {
        Self {
            default_pass: Pass::default_features(),
            all_pass: None,
            individual: Vec::new(),
        }
    }

    #[must_use]
    pub fn is_multi_pass(&self) -> bool {
        self.all_pass.is_some()
    }
}

#[must_use]
pub fn plan(crate_root: &Path) -> Plan {
    let manifest = std::fs::read_to_string(crate_root.join("Cargo.toml")).unwrap_or_default();
    plan_from_manifest(&manifest)
}

#[must_use]
pub fn plan_from_manifest(manifest: &str) -> Plan {
    let uncovered = uncovered_features(manifest);
    Plan {
        default_pass: Pass::default_features(),
        all_pass: (!uncovered.is_empty()).then(Pass::all_features),
        individual: uncovered.iter().map(|f| Pass::one(f)).collect(),
    }
}

fn uncovered_features(manifest: &str) -> Vec<String> {
    let Ok(doc) = manifest.parse::<toml::Table>() else {
        return Vec::new();
    };
    let Some(table) = doc.get("features").and_then(toml::Value::as_table) else {
        return Vec::new();
    };

    let mut active: BTreeSet<&str> = BTreeSet::new();
    let mut queue: Vec<&str> = table
        .get("default")
        .and_then(toml::Value::as_array)
        .map(|entries| entries.iter().filter_map(toml::Value::as_str).collect())
        .unwrap_or_default();
    while let Some(name) = queue.pop() {
        let name = name.split('/').next().unwrap_or(name);
        if name.starts_with("dep:") || !active.insert(name) {
            continue;
        }
        if let Some(entries) = table.get(name).and_then(toml::Value::as_array) {
            queue.extend(entries.iter().filter_map(toml::Value::as_str));
        }
    }

    table
        .keys()
        .filter(|name| name.as_str() != "default")
        .filter(|name| !active.contains(name.as_str()))
        .cloned()
        .collect()
}

fn sanitise(feature: &str) -> String {
    feature
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_crate_with_no_features_gets_one_pass() {
        let plan = plan_from_manifest("[package]\nname = \"x\"\n");
        assert!(!plan.is_multi_pass());
        assert!(plan.individual.is_empty());
        assert_eq!(plan.default_pass.cargo_args, Vec::<String>::new());
    }

    #[test]
    fn an_off_by_default_feature_earns_a_second_pass() {
        let plan = plan_from_manifest("[features]\ncrypto = []\n");
        assert!(plan.is_multi_pass());
        assert_eq!(plan.all_pass.unwrap().cargo_args, ["--all-features"]);
        assert_eq!(plan.individual.len(), 1);
        assert_eq!(
            plan.individual[0].cargo_args,
            ["--features".to_string(), "crypto".to_string()]
        );
    }

    #[test]
    fn a_feature_already_on_by_default_needs_no_pass() {
        let plan = plan_from_manifest("[features]\ndefault = [\"std\"]\nstd = []\n");
        assert!(!plan.is_multi_pass(), "std is already active");
    }

    #[test]
    fn default_features_are_closed_transitively() {
        let plan =
            plan_from_manifest("[features]\ndefault = [\"std\"]\nstd = [\"alloc\"]\nalloc = []\n");
        assert!(!plan.is_multi_pass(), "alloc is reached through std");
    }

    #[test]
    fn dependency_entries_are_not_features_to_cover() {
        let plan = plan_from_manifest(
            "[features]\ndefault = [\"zeroize\"]\nzeroize = [\"dep:zeroize\"]\n",
        );
        assert!(!plan.is_multi_pass());
    }

    #[test]
    fn alternative_backends_each_get_their_own_pass() {
        let plan =
            plan_from_manifest("[features]\ndefault = []\ncrypto-nettle = []\ncrypto-rust = []\n");
        let labels: Vec<&str> = plan.individual.iter().map(|p| p.label.as_str()).collect();
        assert_eq!(labels, ["crypto-nettle", "crypto-rust"]);
    }

    #[test]
    fn a_label_is_safe_as_a_directory_name() {
        assert_eq!(sanitise("crypto/rust"), "crypto-rust");
        assert_eq!(sanitise("allow-experimental"), "allow-experimental");
        assert_eq!(
            sanitise("__implicit-crypto-backend-for-tests"),
            "__implicit-crypto-backend-for-tests"
        );
    }

    #[test]
    fn an_unparseable_manifest_falls_back_to_one_pass() {
        let plan = plan_from_manifest("this is not toml {{{");
        assert!(!plan.is_multi_pass());
    }
}
