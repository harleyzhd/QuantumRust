use std::collections::BTreeSet;

use crate::RuleSet;

pub fn crypto_crates(rules: &RuleSet) -> BTreeSet<String> {
    rules
        .rules
        .iter()
        .flat_map(|rule| {
            rule.match_spec
                .crate_name
                .iter()
                .chain(rule.match_spec.crates.iter())
        })
        .map(|c| c.replace('_', "-"))
        .collect()
}

pub fn is_crypto_crate(name: &str, known: &BTreeSet<String>) -> bool {
    let name = name.replace('_', "-");
    known.iter().any(|anchor| {
        name.strip_prefix(anchor.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('-'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleSet;

    #[test]
    fn the_anchors_name_the_crypto_crates_and_match_across_a_separator() {
        let known = crypto_crates(&RuleSet::builtin());
        assert!(is_crypto_crate("rsa", &known));
        assert!(is_crypto_crate("ed25519-dalek", &known));
        assert!(is_crypto_crate("ed25519_dalek", &known));
        assert!(is_crypto_crate("md5", &known));
        assert!(!is_crypto_crate("md-5", &known));
        assert!(!is_crypto_crate("serde", &known));
        assert!(
            !is_crypto_crate("rsautil", &known),
            "a prefix is not a separator"
        );
    }
}
