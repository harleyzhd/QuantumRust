use std::collections::{BTreeMap, BTreeSet};

use cpg_core::{AlgorithmClass, Finding, QvStatus};
use qr_rules::RuleSet;

use crate::ScoredFinding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmCount {
    pub name: String,
    pub tier: u8,
    pub sites: usize,
    pub unresolved: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headline {
    pub most_severe: Option<(u8, Vec<AlgorithmCount>)>,
    pub most_common: Option<AlgorithmCount>,
    pub unresolved_above: usize,
    pub algorithms: Vec<AlgorithmCount>,
}

pub fn algorithm_name(finding: &Finding, rules: &RuleSet) -> String {
    let spec = crate::crypto_spec(finding, rules);
    let named =
        rule_name(&finding.rule_id, finding.parameter_set.as_deref(), rules).or_else(|| {
            finding
                .with
                .iter()
                .find_map(|part| rule_name(&part.rule_id, part.parameter_set.as_deref(), rules))
        });
    let name = named.unwrap_or_else(|| {
        match finding.algorithm_class {
            AlgorithmClass::Rsa => "RSA",
            AlgorithmClass::Ecdsa => "ECDSA",
            AlgorithmClass::EdDsa => "EdDSA",
            AlgorithmClass::EcdhX25519 | AlgorithmClass::Ecdh => "ECDH",
            AlgorithmClass::Dsa => "DSA",
            AlgorithmClass::EcKey => "EC key",
            AlgorithmClass::FiniteFieldDh => "finite-field DH/DSA",
            AlgorithmClass::Kem => "KEM",
            AlgorithmClass::Hash => "hash",
            AlgorithmClass::Aead => "AEAD",
            AlgorithmClass::Symmetric => "symmetric cipher",
            AlgorithmClass::Kdf => "KDF",
            AlgorithmClass::Unknown => match spec.primitive.as_str() {
                "signature" => "signature",
                "key-agree" => "key agreement",
                "block-cipher" => "block cipher",
                "hash" => "hash",
                _ => "unnamed algorithm",
            },
        }
        .to_string()
    });
    if finding.qv_status == QvStatus::Unknown {
        format!("{name} (unresolved)")
    } else {
        name
    }
}

pub(crate) fn rule_name(
    rule_id: &str,
    parameter_set: Option<&str>,
    rules: &RuleSet,
) -> Option<String> {
    let rule = rules.rules.iter().find(|rule| rule.id == rule_id)?;
    parameter_set
        .and_then(|id| rule.parameter_set(id))
        .map(|set| set.name.clone())
        .or(rule
            .crypto
            .parameter_set_identifier
            .clone()
            .filter(|p| !p.chars().all(|c| c.is_ascii_digit())))
        .or(rule.crypto.algorithm_family.clone().map(|family| {
            if family.starts_with("RSA") {
                "RSA".to_string()
            } else {
                family
            }
        }))
}

pub fn tier_label(tier: u8) -> &'static str {
    match tier {
        1 => "quantum-vulnerable — NIST IR 8547: deprecated after 2030, disallowed after 2035",
        2 => "transition advisory — deprecated, or below the 256-bit bar",
        _ => "quantum-resistant — no quantum migration needed",
    }
}

type Entry = (String, u8, bool);

pub fn headline(scored: &[ScoredFinding<'_>]) -> Headline {
    let mut sites: BTreeMap<Entry, BTreeSet<(&str, u32)>> = BTreeMap::new();
    for r in scored {
        let loc = (r.finding.location.file.as_str(), r.finding.location.line);
        sites
            .entry((r.algorithm.clone(), r.tier, r.conservative))
            .or_default()
            .insert(loc);
    }
    let mut algorithms: Vec<AlgorithmCount> = sites
        .into_iter()
        .map(|((name, tier, unresolved), at)| AlgorithmCount {
            name,
            tier,
            sites: at.len(),
            unresolved,
        })
        .collect();
    algorithms.sort_by(|a, b| {
        a.tier
            .cmp(&b.tier)
            .then(b.sites.cmp(&a.sites))
            .then_with(|| a.name.cmp(&b.name))
    });

    let resolved = || algorithms.iter().filter(|a| !a.unresolved);
    let top_tier = resolved().map(|a| a.tier).min();
    let most_severe = top_tier.map(|tier| {
        (
            tier,
            resolved().filter(|a| a.tier == tier).cloned().collect(),
        )
    });
    let most_common = resolved()
        .max_by(|a, b| {
            a.sites
                .cmp(&b.sites)
                .then(b.tier.cmp(&a.tier))
                .then_with(|| b.name.cmp(&a.name))
        })
        .cloned();
    let unresolved_above = algorithms
        .iter()
        .filter(|a| a.unresolved && top_tier.is_none_or(|top| a.tier < top))
        .map(|a| a.sites)
        .sum();

    Headline {
        most_severe,
        most_common,
        unresolved_above,
        algorithms,
    }
}

fn count(a: &AlgorithmCount) -> String {
    format!(
        "{}, {} site{}",
        a.name,
        a.sites,
        if a.sites == 1 { "" } else { "s" }
    )
}

pub fn render_text(h: &Headline) -> String {
    let mut out = String::new();
    match &h.most_severe {
        Some((tier, algorithms)) => {
            let list: Vec<String> = algorithms.iter().map(count).collect();
            out.push_str(&format!(
                "Most severe: Tier {tier} ({}) — {}\n",
                tier_label(*tier),
                list.join("; ")
            ));
        }
        None => out.push_str("Most severe: no algorithm was resolved\n"),
    }
    if let Some(a) = &h.most_common {
        out.push_str(&format!("Most common: {} (Tier {})\n", count(a), a.tier));
    }
    if h.unresolved_above > 0 {
        out.push_str(&format!(
            "  plus {} unresolved call site{} that could be more severe (scored as upper bounds)\n",
            h.unresolved_above,
            if h.unresolved_above == 1 { "" } else { "s" }
        ));
    }
    out
}

pub fn render_html(h: &Headline) -> String {
    let esc = crate::xml::escape;
    if h.algorithms.is_empty() {
        return "<div class=headline><div class=card><div class=k>Cryptography found</div>\
                <div class=v>none</div></div></div>"
            .to_string();
    }
    let same = matches!(
        (&h.most_severe, &h.most_common),
        (Some((_, severe)), Some(common)) if severe.first() == Some(common)
    );
    let severe = match &h.most_severe {
        Some((tier, algorithms)) => {
            let (first, rest) = algorithms.split_first().expect("a tier has an algorithm");
            let others: Vec<String> = rest
                .iter()
                .map(|a| format!("{} &times;{}", esc(&a.name), a.sites))
                .collect();
            format!(
                "<div class=\"card t{tier}\"><div class=k>{title}</div>\
                 <div class=v>{name} <small>&times;{sites}</small></div>\
                 <div class=d>Tier {tier} &middot; {label}</div>{others}</div>",
                title = if same {
                    "Most severe and most common"
                } else {
                    "Most severe"
                },
                name = esc(&first.name),
                sites = first.sites,
                label = esc(tier_label(*tier)),
                others = if others.is_empty() {
                    String::new()
                } else {
                    format!("<div class=m>also {}</div>", others.join(" &middot; "))
                },
            )
        }
        None => "<div class=card><div class=k>Most severe</div>\
                 <div class=v>unresolved</div>\
                 <div class=d>no finding established its tier</div></div>"
            .to_string(),
    };
    let common = h
        .most_common
        .as_ref()
        .filter(|_| !same)
        .map(|a| {
            format!(
                "<div class=\"card t{tier}\"><div class=k>Most common</div>\
                 <div class=v>{name} <small>&times;{sites}</small></div>\
                 <div class=d>Tier {tier} &middot; {label}</div></div>",
                tier = a.tier,
                name = esc(&a.name),
                sites = a.sites,
                label = esc(tier_label(a.tier)),
            )
        })
        .unwrap_or_default();
    let caveat = if h.unresolved_above > 0 {
        format!(
            "<p class=hcaveat>plus {n} unresolved call site{s} that could be more severe \
             &mdash; rows marked <span class=flag>upper bound</span></p>",
            n = h.unresolved_above,
            s = if h.unresolved_above == 1 { "" } else { "s" },
        )
    } else {
        String::new()
    };
    let chips: String = h
        .algorithms
        .iter()
        .map(|a| {
            format!(
                "<span class=\"chip t{tier}\" title=\"Tier {tier}\">{name} &times;{sites}</span>",
                tier = a.tier,
                name = esc(&a.name),
                sites = a.sites,
            )
        })
        .collect();
    format!(
        "<div class=headline>{severe}{common}</div>{caveat}\
         <div class=chips><span class=ck>All algorithms, by tier, call sites:</span>{chips}</div>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpg_core::SourceLoc;

    fn finding(rule: &str, status: QvStatus, file: &str, line: u32) -> Finding {
        Finding {
            rule_id: rule.into(),
            node_id: line,
            algorithm_class: AlgorithmClass::Unknown,
            qv_status: status,
            location: SourceLoc::new(file, line),
            contextual_signature: format!("{rule}::call"),
            taint_chain: Vec::new(),
            taint_nodes: Vec::new(),
            key_size: None,
            via: Vec::new(),
            parameter_set: None,
            with: Vec::new(),
        }
    }

    fn row<'a>(f: &'a Finding, algorithm: &str, tier: u8) -> ScoredFinding<'a> {
        ScoredFinding {
            algorithm: algorithm.into(),
            tier,
            conservative: f.qv_status == QvStatus::Unknown,
            ..ScoredFinding::for_test(f)
        }
    }

    #[test]
    fn severe_and_common_are_separate_answers() {
        let rsa = finding("R-RSA-001", QvStatus::Vulnerable, "src/a.rs", 1);
        let hashes: Vec<Finding> = (1..=3)
            .map(|i| finding("R-SHA2-001", QvStatus::Resistant, "src/h.rs", i))
            .collect();
        let mut rows = vec![row(&rsa, "RSA", 1)];
        rows.extend(hashes.iter().map(|f| row(f, "SHA-256", 3)));
        let h = headline(&rows);
        let (tier, severe) = h.most_severe.clone().expect("RSA is resolved");
        assert_eq!(tier, 1);
        assert_eq!(severe[0].name, "RSA");
        let common = h.most_common.expect("a common algorithm");
        assert_eq!((common.name.as_str(), common.sites), ("SHA-256", 3));
    }

    #[test]
    fn sites_are_counted_once_per_line() {
        let keygen = finding("R-RSA-001", QvStatus::Vulnerable, "src/a.rs", 7);
        let sign = finding("R-RSA-005", QvStatus::Vulnerable, "src/a.rs", 7);
        let h = headline(&[row(&keygen, "RSA", 1), row(&sign, "RSA", 1)]);
        assert_eq!(h.algorithms[0].sites, 1);
    }

    #[test]
    fn an_unresolved_call_is_counted_but_never_the_headline() {
        let sha1 = finding("R-SHA1-001", QvStatus::Deprecated, "src/a.rs", 1);
        let unknown = finding("R-SIG-999", QvStatus::Unknown, "src/b.rs", 2);
        let h = headline(&[
            row(&sha1, "SHA-1", 2),
            row(&unknown, "signature (unresolved)", 1),
        ]);
        assert_eq!(h.most_severe.as_ref().map(|(t, _)| *t), Some(2));
        assert_eq!(
            h.most_common.as_ref().map(|a| a.name.as_str()),
            Some("SHA-1")
        );
        assert_eq!(h.unresolved_above, 1);
        assert!(render_text(&h).contains("1 unresolved call site"));
    }

    #[test]
    fn names_prefer_the_parameter_set_and_collapse_rsa_schemes() {
        let rules = RuleSet::builtin();
        let named = |rule: &str, status| {
            let mut f = finding(rule, status, "f", 1);
            f.algorithm_class = rules
                .rules
                .iter()
                .find(|r| r.id == rule)
                .expect("a shipped rule")
                .algorithm_class;
            algorithm_name(&f, &rules)
        };
        assert_eq!(named("R-AES-002", QvStatus::Deprecated), "AES-128");
        assert_eq!(named("R-SHA2-001", QvStatus::Resistant), "SHA-256");
        assert_eq!(named("R-RSA-006", QvStatus::Vulnerable), "RSA");
        assert_eq!(named("R-ECDSA-001", QvStatus::Vulnerable), "ECDSA");
        assert_eq!(named("R-HASH-999", QvStatus::Unknown), "hash (unresolved)");
        assert_eq!(
            named("R-SIG-999", QvStatus::Unknown),
            "signature (unresolved)"
        );
    }

    #[test]
    fn one_algorithm_that_is_both_gets_one_card() {
        let ecdh: Vec<Finding> = (1..=2)
            .map(|i| finding("R-ECDH-001", QvStatus::Vulnerable, "src/a.rs", i))
            .collect();
        let rows: Vec<ScoredFinding<'_>> = ecdh.iter().map(|f| row(f, "ECDH", 1)).collect();
        let html = render_html(&headline(&rows));
        assert!(html.contains("Most severe and most common"));
        assert_eq!(html.matches("class=\"card").count(), 1);
    }

    #[test]
    fn the_html_panel_escapes_names() {
        let f = finding("R-X-001", QvStatus::Vulnerable, "src/a.rs", 1);
        let h = headline(&[row(&f, "<b>evil</b>", 1)]);
        let html = render_html(&h);
        assert!(html.contains("&lt;b&gt;evil&lt;/b&gt;") && !html.contains("<b>evil"));
    }
}
