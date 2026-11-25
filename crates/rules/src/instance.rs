use std::collections::BTreeSet;

use cpg_core::CpgNode;

use crate::rule::Prepared;
use crate::RuleSet;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Instance {
    pub params: BTreeSet<String>,
    pub hits: BTreeSet<String>,
}

impl Instance {
    pub fn compatible(&self, other: &Instance) -> bool {
        (self.params == other.params || self.params.is_empty() || other.params.is_empty())
            && (self.hits.is_subset(&other.hits) || other.hits.is_subset(&self.hits))
    }

    pub fn specificity(&self) -> (usize, usize) {
        (self.params.len(), self.hits.len())
    }
}

impl RuleSet {
    pub fn instance_of(&self, node: &CpgNode) -> Instance {
        let args: Vec<Prepared> = node
            .type_args
            .iter()
            .chain(node.static_args.iter())
            .map(|a| Prepared::new(a))
            .collect();
        let mut out = Instance::default();
        if args.is_empty() {
            return out;
        }
        for rule in &self.rules {
            if args.iter().any(|a| rule.matches_type_prepared(a)) {
                out.hits.insert(rule.id.clone());
            }
            out.params.extend(
                rule.parameter_sets_named(&args)
                    .map(|set| set.identifier.clone()),
            );
        }
        out
    }

    pub fn same_instance(&self, a: &CpgNode, b: &CpgNode) -> bool {
        self.instance_of(a).compatible(&self.instance_of(b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(params: &[&str], hits: &[&str]) -> Instance {
        Instance {
            params: params.iter().map(|s| s.to_string()).collect(),
            hits: hits.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn compatibility_reads_parameter_sets_and_contained_matches() {
        let p256 = instance(&["P-256"], &["R-ECDSA-004"]);
        let p384 = instance(&["P-384"], &["R-ECDSA-004"]);
        let generic = instance(&[], &[]);
        assert!(!p256.compatible(&p384));
        assert!(p256.compatible(&generic) && generic.compatible(&p384));
        let sha256 = instance(&[], &["R-SHA2-001"]);
        let sha384 = instance(&[], &["R-SHA2-002"]);
        let wrapped = instance(&[], &["R-SHA2-001", "R-RSA-007"]);
        assert!(!sha256.compatible(&sha384));
        assert!(sha256.compatible(&wrapped));
    }
}
