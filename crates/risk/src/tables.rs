use cpg_core::CpgError;
use serde::Deserialize;

use crate::{Criticality, NistTier};

const TIERS_TOML: &str = include_str!("../../../data/nist_ir_8547_tiers.toml");
const BANDS_TOML: &str = include_str!("../../../data/cvss_v31_environmental.toml");

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SeverityRanks {
    tier1: f64,
    tier2: f64,
    tier3: f64,
}

impl SeverityRanks {
    pub fn weight(self, tier: NistTier) -> f64 {
        match tier {
            NistTier::Tier1 => self.tier1,
            NistTier::Tier2 => self.tier2,
            NistTier::Tier3 => self.tier3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CriticalityBands {
    high: f64,
    medium: f64,
    low: f64,
}

impl CriticalityBands {
    pub fn weight(self, criticality: Criticality) -> f64 {
        match criticality {
            Criticality::High => self.high,
            Criticality::Medium => self.medium,
            Criticality::Low => self.low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoreTables {
    pub severity: SeverityRanks,
    pub criticality: CriticalityBands,
}

#[derive(Deserialize)]
struct TierFile {
    #[serde(default, rename = "tier")]
    tiers: Vec<TierRow>,
}

#[derive(Deserialize)]
struct TierRow {
    name: String,
    severity_rank: f64,
}

#[derive(Deserialize)]
struct BandFile {
    criticality: CriticalityRows,
}

#[derive(Deserialize)]
struct CriticalityRows {
    #[serde(rename = "High")]
    high: f64,
    #[serde(rename = "Medium")]
    medium: f64,
    #[serde(rename = "Low")]
    low: f64,
}

impl ScoreTables {
    pub fn builtin() -> Self {
        Self::parse(TIERS_TOML, BANDS_TOML).expect("shipped score tables are well-formed")
    }

    pub fn load_dir(dir: &std::path::Path) -> Result<Self, CpgError> {
        let tiers = std::fs::read_to_string(dir.join("nist_ir_8547_tiers.toml"))?;
        let bands = std::fs::read_to_string(dir.join("cvss_v31_environmental.toml"))?;
        Self::parse(&tiers, &bands)
    }

    pub fn parse(tiers: &str, bands: &str) -> Result<Self, CpgError> {
        let malformed = |what: &str, e: toml::de::Error| {
            CpgError::Extraction(format!("malformed {what} table: {e}"))
        };
        let tier_file: TierFile =
            toml::from_str(tiers).map_err(|e| malformed("NIST IR 8547 tier", e))?;
        let band_file: BandFile =
            toml::from_str(bands).map_err(|e| malformed("CVSS v3.1 Environmental", e))?;

        let find = |name: &str| -> Result<f64, CpgError> {
            tier_file
                .tiers
                .iter()
                .find(|t| t.name == name)
                .map(|t| t.severity_rank)
                .ok_or_else(|| {
                    CpgError::Extraction(format!(
                        "NIST IR 8547 tier table names no `{name}`; every tier must have a \
                         weight, because defaulting a missing one to zero would read as \
                         \"not a risk\""
                    ))
                })
        };

        Ok(Self {
            severity: SeverityRanks {
                tier1: find("Tier1")?,
                tier2: find("Tier2")?,
                tier3: find("Tier3")?,
            },
            criticality: CriticalityBands {
                high: band_file.criticality.high,
                medium: band_file.criticality.medium,
                low: band_file.criticality.low,
            },
        })
    }
}

impl Default for ScoreTables {
    fn default() -> Self {
        Self::builtin()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_ranks_are_the_declared_ordinal_encoding() {
        let t = ScoreTables::builtin();
        assert_eq!(t.severity.weight(NistTier::Tier1), 2.0);
        assert_eq!(t.severity.weight(NistTier::Tier2), 1.0);
        assert_eq!(t.severity.weight(NistTier::Tier3), 0.0);
        assert_eq!(t.criticality.weight(Criticality::High), 1.5);
        assert_eq!(t.criticality.weight(Criticality::Medium), 1.0);
        assert_eq!(t.criticality.weight(Criticality::Low), 0.5);
    }

    #[test]
    fn the_ranks_are_strictly_ordered_with_tier3_at_zero() {
        let s = ScoreTables::builtin().severity;
        assert!(s.weight(NistTier::Tier1) > s.weight(NistTier::Tier2));
        assert!(s.weight(NistTier::Tier2) > s.weight(NistTier::Tier3));
        assert_eq!(
            s.weight(NistTier::Tier3),
            0.0,
            "Tier3 is a true zero, not a small weight"
        );
    }

    #[test]
    fn the_embedded_tables_match_the_data_directory() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data");
        assert_eq!(
            ScoreTables::load_dir(&dir).expect("/data loads"),
            ScoreTables::builtin()
        );
    }

    #[test]
    fn a_missing_tier_is_an_error_not_a_silent_zero() {
        let tiers = r#"
[[tier]]
name = "Tier1"
severity_rank = 2.0
"#;
        let err = ScoreTables::parse(tiers, BANDS_TOML).unwrap_err();
        assert!(format!("{err}").contains("Tier2"), "got: {err}");
    }

    #[test]
    fn a_malformed_table_is_an_error_not_a_panic() {
        assert!(ScoreTables::parse("[[tier]] name =", BANDS_TOML).is_err());
        assert!(ScoreTables::parse(TIERS_TOML, "criticality = 3").is_err());
    }

    #[test]
    fn a_supplied_table_overrides_the_shipped_one() {
        let tiers = r#"
[[tier]]
name = "Tier1"
severity_rank = 9.0
[[tier]]
name = "Tier2"
severity_rank = 5.0
[[tier]]
name = "Tier3"
severity_rank = 0.0
"#;
        let t = ScoreTables::parse(tiers, BANDS_TOML).expect("valid");
        assert_eq!(t.severity.weight(NistTier::Tier1), 9.0);
    }
}
