pub mod tables;

use std::cmp::Ordering;
use std::path::Path;

use cpg_core::{AlgorithmClass, CpgError, QvStatus};
use serde::{Deserialize, Serialize};

pub use tables::ScoreTables;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NistTier {
    Tier1,
    Tier2,
    Tier3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierAssignment {
    pub tier: NistTier,
    pub conservatively_mapped: bool,
}

impl From<NistTier> for TierAssignment {
    fn from(tier: NistTier) -> Self {
        Self {
            tier,
            conservatively_mapped: false,
        }
    }
}

pub fn tier_for(qv_status: QvStatus, class: AlgorithmClass) -> TierAssignment {
    match qv_status {
        QvStatus::Vulnerable => NistTier::Tier1.into(),
        QvStatus::Deprecated => NistTier::Tier2.into(),
        QvStatus::Resistant => NistTier::Tier3.into(),
        QvStatus::Unknown => TierAssignment {
            tier: class_ceiling(class),
            conservatively_mapped: true,
        },
    }
}

fn class_ceiling(class: AlgorithmClass) -> NistTier {
    match class {
        AlgorithmClass::Rsa
        | AlgorithmClass::FiniteFieldDh
        | AlgorithmClass::Ecdsa
        | AlgorithmClass::EdDsa
        | AlgorithmClass::EcdhX25519
        | AlgorithmClass::Ecdh
        | AlgorithmClass::Dsa
        | AlgorithmClass::EcKey => NistTier::Tier1,

        AlgorithmClass::Kem => NistTier::Tier1,

        AlgorithmClass::Hash
        | AlgorithmClass::Aead
        | AlgorithmClass::Symmetric
        | AlgorithmClass::Kdf => NistTier::Tier2,

        AlgorithmClass::Unknown => NistTier::Tier1,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Criticality {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CriticalityMap {
    #[serde(default, rename = "module")]
    rules: Vec<CriticalityRule>,
}

#[derive(Debug, Clone, Deserialize)]
struct CriticalityRule {
    pattern: String,
    criticality: Criticality,
}

impl CriticalityMap {
    pub fn parse(text: &str) -> Result<Self, CpgError> {
        toml::from_str(text)
            .map_err(|e| CpgError::Extraction(format!("malformed criticality map: {e}")))
    }

    pub fn load(path: &Path) -> Result<Self, CpgError> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    pub fn for_path(&self, file: &str) -> Criticality {
        self.rules
            .iter()
            .find(|rule| file.contains(&rule.pattern))
            .map(|rule| rule.criticality)
            .unwrap_or(Criticality::Medium)
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

pub fn blast_dampening(blast_radius: u64) -> f64 {
    1.0 + ((blast_radius + 1) as f64).log2()
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RiskScore {
    pub tier: NistTier,
    pub value: f64,
    pub severity: f64,
    pub blast_factor: f64,
    pub criticality: f64,
    pub conservatively_mapped: bool,
}

impl RiskScore {
    pub fn priority_cmp(&self, other: &Self) -> Ordering {
        other
            .severity
            .total_cmp(&self.severity)
            .then_with(|| other.value.total_cmp(&self.value))
    }
}

pub fn score(tier: NistTier, blast_radius: u64, criticality: Criticality) -> RiskScore {
    score_with(
        &ScoreTables::builtin(),
        tier.into(),
        blast_radius,
        criticality,
    )
}

pub fn score_with(
    tables: &ScoreTables,
    tier: TierAssignment,
    blast_radius: u64,
    criticality: Criticality,
) -> RiskScore {
    let severity = tables.severity.weight(tier.tier);
    let blast_factor = blast_dampening(blast_radius);
    let crit = tables.criticality.weight(criticality);
    let value = if severity > 0.0 {
        blast_factor * crit
    } else {
        0.0
    };
    RiskScore {
        tier: tier.tier,
        value,
        severity,
        blast_factor,
        criticality: crit,
        conservatively_mapped: tier.conservatively_mapped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_map_is_neutral() {
        let map = CriticalityMap::default();
        assert!(map.is_empty());
        assert_eq!(map.for_path("src/anything.rs"), Criticality::Medium);
        assert_eq!(
            ScoreTables::builtin()
                .criticality
                .weight(Criticality::Medium),
            1.0
        );
    }

    #[test]
    fn first_matching_rule_wins_in_file_order() {
        let map = CriticalityMap::parse(
            r#"
[[module]]
pattern = "src/auth/"
criticality = "High"

[[module]]
pattern = "src/"
criticality = "Low"
"#,
        )
        .unwrap();
        assert_eq!(map.for_path("src/auth/token.rs"), Criticality::High);
        assert_eq!(map.for_path("src/util.rs"), Criticality::Low);
        assert_eq!(map.for_path("tests/fixture.rs"), Criticality::Medium);
    }

    #[test]
    fn criticality_reorders_two_otherwise_identical_findings() {
        let high = score(NistTier::Tier1, 5, Criticality::High).value;
        let low = score(NistTier::Tier1, 5, Criticality::Low).value;
        assert!(high > low, "{high} !> {low}");
    }

    #[test]
    fn a_malformed_map_is_an_error_not_a_panic() {
        assert!(CriticalityMap::parse("[[module]]\npattern = 3").is_err());
    }

    #[test]
    fn f_of_zero_is_one() {
        assert!((blast_dampening(0) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn monotonic_in_blast_radius() {
        let mut prev = f64::NEG_INFINITY;
        for b in 0..1000u64 {
            let v = score(NistTier::Tier1, b, Criticality::Medium).value;
            assert!(v >= prev, "score decreased at b={b}");
            prev = v;
        }
    }

    #[test]
    fn monotonic_in_severity_tier() {
        let lo = score(NistTier::Tier3, 5, Criticality::Medium);
        let mid = score(NistTier::Tier2, 5, Criticality::Medium);
        let hi = score(NistTier::Tier1, 5, Criticality::Medium);
        assert_eq!(hi.priority_cmp(&mid), Ordering::Less);
        assert_eq!(mid.priority_cmp(&lo), Ordering::Less);
    }

    #[test]
    fn no_reach_lifts_a_finding_over_a_more_severe_tier() {
        let isolated_tier1 = score(NistTier::Tier1, 0, Criticality::Low);
        let everywhere_tier2 = score(NistTier::Tier2, 26_145, Criticality::High);
        assert!(everywhere_tier2.value > isolated_tier1.value);
        assert_eq!(
            isolated_tier1.priority_cmp(&everywhere_tier2),
            Ordering::Less,
            "the Tier1 finding ranks first however far the Tier2 one reaches"
        );
    }

    #[test]
    fn within_a_tier_reach_decides() {
        let near = score(NistTier::Tier1, 2, Criticality::Medium);
        let far = score(NistTier::Tier1, 200, Criticality::Medium);
        assert_eq!(far.priority_cmp(&near), Ordering::Less);
    }

    #[test]
    fn monotonic_in_criticality() {
        let lo = score(NistTier::Tier1, 5, Criticality::Low).value;
        let hi = score(NistTier::Tier1, 5, Criticality::High).value;
        assert!(lo <= hi);
    }

    #[test]
    fn tier3_resistant_scores_zero() {
        assert_eq!(score(NistTier::Tier3, 100, Criticality::High).value, 0.0);
    }

    #[test]
    fn every_rule_declares_the_tier_its_status_implies() {
        let expected = |tier: NistTier| match tier {
            NistTier::Tier1 => "Tier1",
            NistTier::Tier2 => "Tier2",
            NistTier::Tier3 => "Tier3",
        };
        let mut wrong: Vec<String> = Vec::new();
        let mut checked = 0usize;
        for rule in &qr_rules::RuleSet::builtin().rules {
            let Some(declared) = rule.nist_tier.as_deref() else {
                if rule.qv_status != QvStatus::Unknown {
                    wrong.push(format!(
                        "{} declares no nist_tier but its status is {:?}, which fixes one",
                        rule.id, rule.qv_status
                    ));
                }
                continue;
            };
            checked += 1;
            let derived = tier_for(rule.qv_status, rule.algorithm_class);
            if declared != expected(derived.tier) {
                wrong.push(format!(
                    "{} declares {declared} but status {:?} derives {:?}",
                    rule.id, rule.qv_status, derived.tier
                ));
            }
        }
        assert!(
            wrong.is_empty(),
            "declared and derived tiers disagree:\n  {}",
            wrong.join("\n  ")
        );
        assert!(
            checked >= 60,
            "only {checked} rules declared a tier; the check is not exercising the rule set"
        );
    }

    #[test]
    fn an_unresolved_call_does_not_score_zero() {
        for class in [
            AlgorithmClass::Unknown,
            AlgorithmClass::Hash,
            AlgorithmClass::Aead,
            AlgorithmClass::Rsa,
            AlgorithmClass::Kem,
        ] {
            let t = tier_for(QvStatus::Unknown, class);
            let s = score_with(&ScoreTables::builtin(), t, 5, Criticality::Medium);
            assert!(
                s.value > 0.0,
                "{class:?} with an unresolved status scored {}",
                s.value
            );
        }
    }

    #[test]
    fn a_resolved_resistant_call_still_scores_zero() {
        let t = tier_for(QvStatus::Resistant, AlgorithmClass::Kem);
        assert_eq!(t.tier, NistTier::Tier3);
        assert!(!t.conservatively_mapped);
        assert_eq!(
            score_with(&ScoreTables::builtin(), t, 100, Criticality::High).value,
            0.0
        );
    }

    #[test]
    fn an_unresolved_hash_is_not_ranked_alongside_an_unresolved_signature() {
        let hash = tier_for(QvStatus::Unknown, AlgorithmClass::Hash);
        let anything = tier_for(QvStatus::Unknown, AlgorithmClass::Unknown);
        assert_eq!(hash.tier, NistTier::Tier2);
        assert_eq!(anything.tier, NistTier::Tier1);

        let tables = ScoreTables::builtin();
        let at = |t| score_with(&tables, t, 10, Criticality::Medium);
        assert_eq!(at(anything).priority_cmp(&at(hash)), Ordering::Less);
        assert!(at(hash).value > 0.0);
    }

    #[test]
    fn an_unresolved_cipher_or_kdf_is_ceilinged_at_tier_2() {
        for class in [AlgorithmClass::Symmetric, AlgorithmClass::Kdf] {
            let t = tier_for(QvStatus::Unknown, class);
            assert_eq!(t.tier, NistTier::Tier2, "{class:?}");
            assert!(t.conservatively_mapped);
        }
    }

    #[test]
    fn an_unresolved_kem_is_treated_as_possibly_classical() {
        assert_eq!(
            tier_for(QvStatus::Unknown, AlgorithmClass::Kem).tier,
            NistTier::Tier1
        );
    }

    #[test]
    fn only_an_assumed_tier_is_flagged_as_conservative() {
        for (status, expected) in [
            (QvStatus::Vulnerable, false),
            (QvStatus::Deprecated, false),
            (QvStatus::Resistant, false),
            (QvStatus::Unknown, true),
        ] {
            let t = tier_for(status, AlgorithmClass::Rsa);
            assert_eq!(t.conservatively_mapped, expected, "for {status:?}");
            let s = score_with(&ScoreTables::builtin(), t, 1, Criticality::Medium);
            assert_eq!(s.conservatively_mapped, expected, "score for {status:?}");
        }
    }

    const BANDS: &str = include_str!("../../../data/cvss_v31_environmental.toml");

    fn tiers_toml(t1: f64, t2: f64, t3: f64) -> String {
        format!(
            "[[tier]]\nname = \"Tier1\"\nseverity_rank = {t1}\n\
             [[tier]]\nname = \"Tier2\"\nseverity_rank = {t2}\n\
             [[tier]]\nname = \"Tier3\"\nseverity_rank = {t3}\n"
        )
    }

    fn grid() -> Vec<(NistTier, u64, Criticality)> {
        let mut out = Vec::new();
        for tier in [NistTier::Tier1, NistTier::Tier2, NistTier::Tier3] {
            for b in [0u64, 1, 3, 10, 50, 200, 1000] {
                for c in [Criticality::Low, Criticality::Medium, Criticality::High] {
                    out.push((tier, b, c));
                }
            }
        }
        out
    }

    fn same_ranking(a: &ScoreTables, b: &ScoreTables, what: &str) {
        let g = grid();
        for (i, &(ta, ba, ca)) in g.iter().enumerate() {
            for &(tb, bb, cb) in &g[i + 1..] {
                let ordering = |t: &ScoreTables| {
                    score_with(t, ta.into(), ba, ca).priority_cmp(&score_with(t, tb.into(), bb, cb))
                };
                assert_eq!(
                    ordering(a),
                    ordering(b),
                    "{what} reordered ({ta:?},{ba},{ca:?}) vs ({tb:?},{bb},{cb:?})"
                );
            }
        }
    }

    #[test]
    fn rescaling_the_severity_table_preserves_every_ranking() {
        let base = ScoreTables::builtin();
        for k in [0.5, 2.0, 8.0] {
            let scaled = ScoreTables::parse(&tiers_toml(2.0 * k, k, 0.0), BANDS).expect("valid");
            same_ranking(&base, &scaled, &format!("rescaling by {k}"));
        }
    }

    #[test]
    fn changing_the_tier_ratio_reorders_nothing() {
        let shipped = ScoreTables::builtin();
        for (t1, t2) in [(7.0, 4.0), (8.0, 5.5), (1.1, 1.0), (100.0, 1.0)] {
            let other = ScoreTables::parse(&tiers_toml(t1, t2, 0.0), BANDS).expect("valid");
            same_ranking(&shipped, &other, &format!("the ratio {t1}:{t2}"));
        }
        let tier1 = score(NistTier::Tier1, 10, Criticality::Medium);
        let tier2 = score(NistTier::Tier2, 150, Criticality::Medium);
        assert_eq!(tier1.priority_cmp(&tier2), Ordering::Less);
    }

    #[test]
    fn the_table_still_decides_the_tier_order() {
        let swapped = ScoreTables::parse(&tiers_toml(1.0, 2.0, 0.0), BANDS).expect("valid");
        let tier1 = score_with(&swapped, NistTier::Tier1.into(), 50, Criticality::Medium);
        let tier2 = score_with(&swapped, NistTier::Tier2.into(), 0, Criticality::Medium);
        assert_eq!(tier2.priority_cmp(&tier1), Ordering::Less);
    }
}
