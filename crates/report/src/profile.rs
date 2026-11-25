use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use cpg_core::{CpgError, Finding, QvStatus};
use serde::Deserialize;

const SHIPPED: &[&str] = &[
    include_str!("../../../profiles/cnsa-2.0.toml"),
    include_str!("../../../profiles/nist-ir-8547.toml"),
    include_str!("../../../profiles/fips-pqc.toml"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Review,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
            Verdict::Review => "review",
        }
    }
}

pub const NOT_A_CERTIFICATE: &str = "reported against the profile, not a compliance assertion";

#[derive(Debug, Clone)]
pub struct Judged {
    pub profile_id: String,
    pub profile_name: String,
    pub verdicts: Vec<Verdict>,
}

impl Judged {
    pub fn new(profile: &Profile, findings: &[Finding], rules: &qr_rules::RuleSet) -> Self {
        let verdicts = findings
            .iter()
            .map(|f| {
                let level = crate::quantum_security_level(f, rules);
                let name = crate::algorithm_name(f, rules);
                profile.judge_named(f, level, &name)
            })
            .collect();
        Self {
            profile_id: profile.id.clone(),
            profile_name: profile.name.clone(),
            verdicts,
        }
    }

    pub fn count(&self, verdict: Verdict) -> usize {
        self.verdicts.iter().filter(|v| **v == verdict).count()
    }

    pub fn tally(&self) -> String {
        format!(
            "{} pass, {} fail, {} need review",
            self.count(Verdict::Pass),
            self.count(Verdict::Fail),
            self.count(Verdict::Review)
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub reference: Option<String>,
    pub status: StatusPolicy,
    #[serde(default)]
    pub min_quantum_security_level: Option<u8>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub closed: bool,
    #[serde(default)]
    pub verdicts: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatusPolicy {
    pub vulnerable: String,
    pub deprecated: String,
    pub resistant: String,
    pub unknown: String,
}

impl Profile {
    pub fn judge(&self, finding: &Finding, quantum_security_level: Option<u8>) -> Verdict {
        let from_status = match finding.qv_status {
            QvStatus::Vulnerable => parse_verdict(&self.status.vulnerable),
            QvStatus::Deprecated => parse_verdict(&self.status.deprecated),
            QvStatus::Resistant => parse_verdict(&self.status.resistant),
            QvStatus::Unknown => parse_verdict(&self.status.unknown),
        };
        if from_status == Verdict::Fail {
            return Verdict::Fail;
        }

        let Some(floor) = self.min_quantum_security_level else {
            return from_status;
        };
        match quantum_security_level {
            Some(level) if level < floor => Verdict::Fail,
            Some(_) => from_status,
            None => Verdict::Review,
        }
    }
}

impl Profile {
    pub fn unknown_verdict_names(&self, rules: &qr_rules::RuleSet) -> Vec<String> {
        let mut known: BTreeSet<String> = crate::migration::known_names();
        for rule in &rules.rules {
            known.extend(crate::headline::rule_name(&rule.id, None, rules));
            known.extend(rule.parameter_sets.iter().map(|set| set.name.clone()));
        }
        self.verdicts
            .keys()
            .filter(|name| !known.contains(*name))
            .cloned()
            .collect()
    }

    pub fn allows(&self, name: &str) -> bool {
        self.allow.iter().any(|a| a == name)
    }

    pub fn accepts(&self, name: &str, level: u8) -> bool {
        if let Some(verdict) = self.verdicts.get(name) {
            return parse_verdict(verdict) == Verdict::Pass;
        }
        self.allows(name)
            || (!self.closed
                && self
                    .min_quantum_security_level
                    .is_none_or(|floor| level >= floor))
    }

    pub fn judge_named(
        &self,
        finding: &Finding,
        quantum_security_level: Option<u8>,
        name: &str,
    ) -> Verdict {
        if let Some(verdict) = self.verdicts.get(name) {
            return parse_verdict(verdict);
        }
        let mut verdict = self.judge(finding, quantum_security_level);
        if verdict != Verdict::Pass && self.allows(name) {
            verdict = match finding.qv_status {
                QvStatus::Vulnerable => parse_verdict(&self.status.vulnerable),
                QvStatus::Deprecated => parse_verdict(&self.status.deprecated),
                QvStatus::Resistant => parse_verdict(&self.status.resistant),
                QvStatus::Unknown => parse_verdict(&self.status.unknown),
            };
        }
        if self.closed && verdict == Verdict::Pass && !self.allows(name) {
            return Verdict::Fail;
        }
        verdict
    }
}

fn parse_verdict(text: &str) -> Verdict {
    match text.trim().to_ascii_lowercase().as_str() {
        "pass" => Verdict::Pass,
        "fail" => Verdict::Fail,
        _ => Verdict::Review,
    }
}

pub fn parse_profile(text: &str) -> Result<Profile, CpgError> {
    let profile: Profile = toml::from_str(text)
        .map_err(|e| CpgError::Extraction(format!("malformed profile: {e}")))?;
    let status = &profile.status;
    let given = [
        ("vulnerable", &status.vulnerable),
        ("deprecated", &status.deprecated),
        ("resistant", &status.resistant),
        ("unknown", &status.unknown),
    ]
    .into_iter()
    .map(|(field, value)| (format!("[status] {field}"), value))
    .chain(
        profile
            .verdicts
            .iter()
            .map(|(name, value)| (format!("[verdicts] {name:?}"), value)),
    );
    for (field, value) in given {
        if !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "pass" | "fail" | "review"
        ) {
            return Err(CpgError::Extraction(format!(
                "malformed profile {:?}: {field} is {value:?}; a verdict is pass, fail or review",
                profile.id
            )));
        }
    }
    Ok(profile)
}

pub fn builtin_profiles() -> Vec<Profile> {
    SHIPPED
        .iter()
        .map(|text| parse_profile(text).expect("shipped profile is well-formed"))
        .collect()
}

pub fn load_profile(selector: &str) -> Result<Profile, CpgError> {
    if let Some(profile) = builtin_profiles().into_iter().find(|p| p.id == selector) {
        return Ok(profile);
    }
    let path = Path::new(selector);
    if path.is_file() {
        return parse_profile(&std::fs::read_to_string(path)?);
    }
    let known: Vec<String> = builtin_profiles().into_iter().map(|p| p.id).collect();
    Err(CpgError::Extraction(format!(
        "unknown profile {selector:?}; shipped profiles are {} — or pass a path to a profile file",
        known.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpg_core::{AlgorithmClass, SourceLoc};

    fn finding(status: QvStatus) -> Finding {
        Finding {
            rule_id: "R-TEST".into(),
            node_id: 1,
            algorithm_class: AlgorithmClass::Rsa,
            qv_status: status,
            location: SourceLoc::new("src/main.rs", 1),
            contextual_signature: "test".into(),
            taint_chain: Vec::new(),
            taint_nodes: Vec::new(),
            via: Vec::new(),
            key_size: None,
            parameter_set: None,
            with: Vec::new(),
        }
    }

    #[test]
    fn shipped_profiles_all_parse() {
        let profiles = builtin_profiles();
        assert_eq!(profiles.len(), SHIPPED.len());
        assert!(profiles.iter().all(|p| !p.id.is_empty()));
    }

    #[test]
    fn shipped_level_floors_are_actually_parsed() {
        for (id, expected) in [
            ("cnsa-2.0", Some(5)),
            ("nist-ir-8547", Some(2)),
            ("fips-pqc", None),
        ] {
            let profile = load_profile(id).unwrap();
            assert_eq!(profile.min_quantum_security_level, expected, "{id}");
        }
    }

    #[test]
    fn cnsa_fails_classical_and_passes_post_quantum() {
        let cnsa = load_profile("cnsa-2.0").unwrap();
        assert_eq!(
            cnsa.judge(&finding(QvStatus::Vulnerable), Some(0)),
            Verdict::Fail
        );
        assert_eq!(
            cnsa.judge(&finding(QvStatus::Resistant), Some(5)),
            Verdict::Pass
        );
    }

    #[test]
    fn a_resistant_primitive_can_still_fail_a_profile() {
        let cnsa = load_profile("cnsa-2.0").unwrap();
        assert_eq!(
            cnsa.judge(&finding(QvStatus::Resistant), Some(2)),
            Verdict::Fail
        );
    }

    #[test]
    fn cnsa_accepts_the_hash_it_names() {
        let cnsa = load_profile("cnsa-2.0").unwrap();
        let sha384 = finding(QvStatus::Resistant);
        assert_eq!(
            cnsa.judge(&sha384, Some(4)),
            Verdict::Fail,
            "the floor alone"
        );
        assert_eq!(cnsa.judge_named(&sha384, Some(4), "SHA-384"), Verdict::Pass);
        assert_eq!(
            cnsa.judge_named(&finding(QvStatus::Vulnerable), Some(0), "SHA-384"),
            Verdict::Fail
        );
        assert_eq!(cnsa.judge_named(&sha384, Some(2), "SHA-256"), Verdict::Fail);
    }

    #[test]
    fn an_unestablished_level_is_review_not_pass() {
        let cnsa = load_profile("cnsa-2.0").unwrap();
        assert_eq!(
            cnsa.judge(&finding(QvStatus::Resistant), None),
            Verdict::Review
        );
    }

    #[test]
    fn an_unknown_status_is_never_silently_passed() {
        for profile in builtin_profiles() {
            assert_ne!(
                profile.judge(&finding(QvStatus::Unknown), Some(5)),
                Verdict::Pass,
                "{} passes an unresolved finding",
                profile.id
            );
        }
    }

    #[test]
    fn a_typo_in_a_profile_never_passes() {
        let typo = parse_profile(
            r#"
id = "typo"
name = "Typo"
[status]
vulnerable = "flail"
deprecated = "fail"
resistant = "pass"
unknown = "review"
"#,
        );
        assert!(typo.is_err(), "{typo:?}");
    }

    #[test]
    fn an_unknown_selector_names_the_alternatives() {
        let err = load_profile("no-such-profile").unwrap_err();
        let message = format!("{err}");
        assert!(message.contains("cnsa-2.0"), "got: {message}");
    }

    #[test]
    fn a_profile_can_be_loaded_from_a_path() {
        let dir = std::env::temp_dir().join("qr-profile-path-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("house.toml");
        std::fs::write(
            &path,
            r#"
id = "house"
name = "House policy"
[status]
vulnerable = "fail"
deprecated = "pass"
resistant = "pass"
unknown = "review"
"#,
        )
        .unwrap();
        let profile = load_profile(path.to_str().unwrap()).unwrap();
        assert_eq!(profile.id, "house");
        assert_eq!(
            profile.judge(&finding(QvStatus::Deprecated), None),
            Verdict::Pass
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cnsa_fails_chacha20_poly1305() {
        let cnsa = load_profile("cnsa-2.0").unwrap();
        let f = finding(QvStatus::Resistant);
        for name in ["ChaCha20", "ChaCha20-Poly1305"] {
            assert_eq!(cnsa.judge_named(&f, Some(5), name), Verdict::Fail, "{name}");
        }
    }

    #[test]
    fn cnsa_fails_camellia_256() {
        let cnsa = load_profile("cnsa-2.0").unwrap();
        assert_eq!(
            cnsa.judge_named(&finding(QvStatus::Resistant), Some(5), "Camellia-256"),
            Verdict::Fail
        );
    }

    #[test]
    fn cnsa_passes_aes_256_sha_384_sha_512_ml_kem_1024() {
        let cnsa = load_profile("cnsa-2.0").unwrap();
        let f = finding(QvStatus::Resistant);
        for (name, level) in [
            ("AES-256", 5),
            ("SHA-384", 4),
            ("SHA-512", 5),
            ("ML-KEM-1024", 5),
        ] {
            assert_eq!(
                cnsa.judge_named(&f, Some(level), name),
                Verdict::Pass,
                "{name}"
            );
        }
    }

    #[test]
    fn cnsa_reviews_ml_dsa_without_a_parameter_set() {
        let cnsa = load_profile("cnsa-2.0").unwrap();
        assert_eq!(
            cnsa.judge_named(&finding(QvStatus::Resistant), None, "ML-DSA"),
            Verdict::Review
        );
    }

    #[test]
    fn ir8547_passes_aes_128_and_aes_192() {
        let ir = load_profile("nist-ir-8547").unwrap();
        let f = finding(QvStatus::Deprecated);
        assert_eq!(ir.judge_named(&f, Some(1), "AES-128"), Verdict::Pass);
        assert_eq!(ir.judge_named(&f, Some(3), "AES-192"), Verdict::Pass);
    }

    #[test]
    fn ir8547_still_fails_rsa_and_sha_1() {
        let ir = load_profile("nist-ir-8547").unwrap();
        assert_eq!(
            ir.judge_named(&finding(QvStatus::Vulnerable), Some(0), "RSA"),
            Verdict::Fail
        );
        assert_eq!(
            ir.judge_named(&finding(QvStatus::Deprecated), None, "SHA-1"),
            Verdict::Fail
        );
    }

    #[test]
    fn verdicts_override_status() {
        let house = parse_profile(
            r#"
id = "house"
name = "House policy"
[status]
vulnerable = "fail"
deprecated = "fail"
resistant = "pass"
unknown = "review"
[verdicts]
"RSA" = "pass"
"AES-256" = "fail"
"#,
        )
        .unwrap();
        assert_eq!(
            house.judge_named(&finding(QvStatus::Vulnerable), Some(0), "RSA"),
            Verdict::Pass
        );
        assert_eq!(
            house.judge_named(&finding(QvStatus::Resistant), Some(5), "AES-256"),
            Verdict::Fail
        );
    }

    #[test]
    fn a_misspelled_verdict_is_an_error() {
        let base = "id = \"t\"\nname = \"t\"\n[status]\nvulnerable = \"fail\"\n\
                    deprecated = \"fail\"\nresistant = \"pass\"\nunknown = \"review\"\n";
        assert!(parse_profile(base).is_ok());
        let in_status = base.replace("vulnerable = \"fail\"", "vulnerable = \"fial\"");
        let err = parse_profile(&in_status).unwrap_err().to_string();
        assert!(err.contains("fial") && err.contains("vulnerable"), "{err}");
        let in_verdicts = format!("{base}[verdicts]\n\"AES-128\" = \"pas\"\n");
        let err = parse_profile(&in_verdicts).unwrap_err().to_string();
        assert!(err.contains("pas") && err.contains("AES-128"), "{err}");
    }

    #[test]
    fn a_verdict_for_an_algorithm_the_tool_never_names_is_listed() {
        let rules = qr_rules::RuleSet::builtin();
        let typo = parse_profile(
            "id = \"t\"\nname = \"t\"\n[status]\nvulnerable = \"fail\"\n\
             deprecated = \"fail\"\nresistant = \"pass\"\nunknown = \"review\"\n\
             [verdicts]\n\"AES-12\" = \"pass\"\n\"AES-128\" = \"pass\"\n",
        )
        .unwrap();
        assert_eq!(typo.unknown_verdict_names(&rules), ["AES-12"]);
        for profile in builtin_profiles() {
            assert!(
                profile.unknown_verdict_names(&rules).is_empty(),
                "{}",
                profile.id
            );
        }
    }
}
