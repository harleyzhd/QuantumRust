pub mod crypto;
pub mod instance;
pub mod rehome;
pub mod rule;

pub use instance::Instance;
pub use rehome::rehome;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use cpg_core::{
    AlgorithmClass, Cpg, CpgError, CpgNode, EdgeKind, Finding, IrLayer, NodeKind, Part, QvStatus,
    SourceLoc,
};

pub use rule::{parse_rule, CryptoSpec, MatchSpec, ParameterSet, ParameterSpec, Rule, TaintSpec};

const SHIPPED: &[&str] = &[
    include_str!("../../../rules/R-RSA-001.toml"),
    include_str!("../../../rules/R-RSA-002.toml"),
    include_str!("../../../rules/R-RSA-003.toml"),
    include_str!("../../../rules/R-RSA-004.toml"),
    include_str!("../../../rules/R-RSA-005.toml"),
    include_str!("../../../rules/R-RSA-006.toml"),
    include_str!("../../../rules/R-RSA-999.toml"),
    include_str!("../../../rules/R-RSA-007.toml"),
    include_str!("../../../rules/R-RSA-008.toml"),
    include_str!("../../../rules/R-ECDSA-001.toml"),
    include_str!("../../../rules/R-ECDSA-002.toml"),
    include_str!("../../../rules/R-ECDSA-003.toml"),
    include_str!("../../../rules/R-ECDSA-999.toml"),
    include_str!("../../../rules/R-EC-999.toml"),
    include_str!("../../../rules/R-ECDSA-004.toml"),
    include_str!("../../../rules/R-ED25519-001.toml"),
    include_str!("../../../rules/R-ED25519-002.toml"),
    include_str!("../../../rules/R-ED25519-003.toml"),
    include_str!("../../../rules/R-ED25519-999.toml"),
    include_str!("../../../rules/R-ED25519-004.toml"),
    include_str!("../../../rules/R-DSA-001.toml"),
    include_str!("../../../rules/R-DSA-999.toml"),
    include_str!("../../../rules/R-DSA-002.toml"),
    include_str!("../../../rules/R-X25519-001.toml"),
    include_str!("../../../rules/R-X25519-002.toml"),
    include_str!("../../../rules/R-ECDH-001.toml"),
    include_str!("../../../rules/R-X25519-999.toml"),
    include_str!("../../../rules/R-X448-001.toml"),
    include_str!("../../../rules/R-ED448-001.toml"),
    include_str!("../../../rules/R-MLKEM-001.toml"),
    include_str!("../../../rules/R-MLDSA-001.toml"),
    include_str!("../../../rules/R-SLHDSA-001.toml"),
    include_str!("../../../rules/R-PQC-999.toml"),
    include_str!("../../../rules/R-SHA2-001.toml"),
    include_str!("../../../rules/R-SHA2-002.toml"),
    include_str!("../../../rules/R-SHA2-003.toml"),
    include_str!("../../../rules/R-SHA2-004.toml"),
    include_str!("../../../rules/R-SHA3-001.toml"),
    include_str!("../../../rules/R-SHA3-002.toml"),
    include_str!("../../../rules/R-BLAKE-001.toml"),
    include_str!("../../../rules/R-BLAKE-002.toml"),
    include_str!("../../../rules/R-MD5-001.toml"),
    include_str!("../../../rules/R-SHA1-001.toml"),
    include_str!("../../../rules/R-HASH-999.toml"),
    include_str!("../../../rules/R-ARGON2-001.toml"),
    include_str!("../../../rules/R-SCRYPT-001.toml"),
    include_str!("../../../rules/R-PBKDF2-001.toml"),
    include_str!("../../../rules/R-AES-001.toml"),
    include_str!("../../../rules/R-AES-002.toml"),
    include_str!("../../../rules/R-AES-003.toml"),
    include_str!("../../../rules/R-CHACHA-002.toml"),
    include_str!("../../../rules/R-CAMELLIA-001.toml"),
    include_str!("../../../rules/R-CAMELLIA-002.toml"),
    include_str!("../../../rules/R-CAMELLIA-003.toml"),
    include_str!("../../../rules/R-TWOFISH-001.toml"),
    include_str!("../../../rules/R-3DES-001.toml"),
    include_str!("../../../rules/R-BLOWFISH-001.toml"),
    include_str!("../../../rules/R-CAST5-001.toml"),
    include_str!("../../../rules/R-IDEA-001.toml"),
    include_str!("../../../rules/R-SYM-999.toml"),
    include_str!("../../../rules/R-RING-001.toml"),
    include_str!("../../../rules/R-RING-002.toml"),
    include_str!("../../../rules/R-RING-003.toml"),
    include_str!("../../../rules/R-RING-004.toml"),
    include_str!("../../../rules/R-RING-005.toml"),
    include_str!("../../../rules/R-RING-006.toml"),
    include_str!("../../../rules/R-RING-007.toml"),
    include_str!("../../../rules/R-RING-008.toml"),
    include_str!("../../../rules/R-RING-ALG-001.toml"),
    include_str!("../../../rules/R-RING-ALG-002.toml"),
    include_str!("../../../rules/R-RING-ALG-003.toml"),
    include_str!("../../../rules/R-TLS-001.toml"),
    include_str!("../../../rules/R-OPENSSL-001.toml"),
    include_str!("../../../rules/R-OPENSSL-002.toml"),
    include_str!("../../../rules/R-OPENSSL-003.toml"),
    include_str!("../../../rules/R-OPENSSL-004.toml"),
    include_str!("../../../rules/R-OPENSSL-005.toml"),
    include_str!("../../../rules/R-OPENSSL-006.toml"),
    include_str!("../../../rules/R-SIG-999.toml"),
];

#[derive(Debug, Clone)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

pub fn embedded_rule_ids() -> Vec<String> {
    let mut ids: Vec<String> = SHIPPED
        .iter()
        .map(|text| parse_rule(text).expect("shipped rule is well-formed").id)
        .collect();
    ids.sort();
    ids
}

impl RuleSet {
    pub fn builtin() -> Self {
        let rules = SHIPPED
            .iter()
            .map(|text| parse_rule(text).expect("shipped rule is well-formed"))
            .collect();
        Self::ordered(rules)
    }

    pub fn load_dir(dir: &Path) -> Result<Self, CpgError> {
        let mut paths: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        paths.sort();

        let mut rules = Vec::with_capacity(paths.len());
        for path in paths {
            let text = std::fs::read_to_string(&path)?;
            let rule = parse_rule(&text)
                .map_err(|e| CpgError::Extraction(format!("{}: {e}", path.display())))?;
            rules.push(rule);
        }
        Ok(Self::ordered(rules))
    }

    fn ordered(mut rules: Vec<Rule>) -> Self {
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        RuleSet { rules }
    }

    pub fn is_sink(&self, symbol: &str) -> bool {
        let subject = rule::Prepared::new(symbol);
        self.rules
            .iter()
            .any(|rule| rule.is_sink_prepared(&subject))
    }

    pub fn match_cpg(&self, cpg: &Cpg) -> Vec<Finding> {
        let call_shaped = [
            NodeKind::CallSite,
            NodeKind::FfiBoundary,
            NodeKind::TraitMethod,
            NodeKind::FnRef,
        ];
        let mut candidates: Candidates = BTreeMap::new();
        let mut order = 0usize;
        let into_own_body = calls_into_own_body(cpg);

        for node in cpg.nodes().filter(|n| call_shaped.contains(&n.kind)) {
            let subject = rule::Prepared::new(&node.symbol);
            let link = rule::link_of(node.canonical.as_deref());
            let mut signature = node.symbol.as_str();
            let mut matched: Vec<&Rule> = self
                .rules
                .iter()
                .filter(|rule| rule.matches_prepared(&subject, link.as_deref()))
                .collect();
            let resolved = resolved_trait_call(node);
            if let Some((call, _)) = &resolved {
                matched.retain(|rule| rule.agrees_with(call));
            }
            if resolved.is_none() && node.layer == IrLayer::Mir && node.kind == NodeKind::CallSite {
                if let Some(owner) = node.canonical.as_deref().and_then(inherent_owner_crate) {
                    let before = matched.len();
                    matched.retain(|rule| rule.matches_by_signature() || rule.anchors_crate(owner));
                    if matched.len() < before
                        && matched.iter().all(|rule| rule.matches_by_signature())
                    {
                        matched.extend(self.rules.iter().filter(|rule| {
                            !rule.matches_by_signature()
                                && rule.anchors_crate(owner)
                                && !rule.excludes(&subject)
                        }));
                    }
                }
            }
            if matched.is_empty() {
                if let Some((call, canonical)) = &resolved {
                    if call.is_core_construction() {
                        matched = self
                            .rules
                            .iter()
                            .filter(|rule| rule.matches_resolved(&call.instance, &call.self_ty))
                            .collect();
                        if matched.is_empty() {
                            if let Some(root) = call.self_root() {
                                matched = self
                                    .rules
                                    .iter()
                                    .filter(|rule| {
                                        rule.anchors_crate(root)
                                            && !rule.excludes(&call.instance)
                                            && !rule.excludes(&subject)
                                    })
                                    .collect();
                            }
                        }
                        signature = canonical;
                    } else {
                        let excluded = self
                            .rules
                            .iter()
                            .any(|rule| rule.excludes(&subject) || rule.excludes(&call.instance));
                        if !excluded {
                            matched = self
                                .rules
                                .iter()
                                .filter(|rule| rule.matches_resolved(&call.instance, &call.self_ty))
                                .collect();
                            signature = canonical;
                        }
                    }
                }
            }
            let gated = !matched.is_empty() && into_own_body.contains(&node.id);
            if gated {
                matched.clear();
            }
            let mut hits: Vec<(&Rule, &str)> =
                match matched.iter().map(|rule| precedence(rule, signature)).max() {
                    Some(best) => matched
                        .into_iter()
                        .filter(|rule| precedence(rule, signature) == best)
                        .map(|rule| (rule, signature))
                        .collect(),
                    None if gated => Vec::new(),
                    None => continue,
                };

            let type_hits = self.type_argument_hits(node);

            hits.retain(|(fallback, _)| {
                fallback.is_specific()
                    || !type_hits
                        .iter()
                        .any(|(resolver, _)| supersedes(resolver, fallback))
            });
            let named_classes: HashSet<AlgorithmClass> = hits
                .iter()
                .filter(|(rule, _)| rule.is_specific())
                .map(|(rule, _)| suppression_class(rule.algorithm_class))
                .collect();
            hits.extend(type_hits.into_iter().filter(|(resolver, _)| {
                !named_classes.contains(&suppression_class(resolver.algorithm_class))
            }));

            let arguments: Vec<String> = node
                .type_args
                .iter()
                .chain(node.static_args.iter())
                .cloned()
                .collect();
            let instance = (!hits.is_empty()).then(|| self.instance_of(node));
            for (rule, signature) in hits {
                let location = node
                    .location
                    .as_ref()
                    .map(cpg_core::paths::display_loc)
                    .unwrap_or_else(|| SourceLoc::new("<unknown>", 0));
                let key = (
                    rule.id.clone(),
                    signature.to_string(),
                    location.file.clone(),
                    location.line,
                );
                order += 1;
                candidates.entry(key).or_default().push((
                    order,
                    Finding {
                        rule_id: rule.id.clone(),
                        node_id: node.id,
                        algorithm_class: rule.algorithm_class,
                        qv_status: rule.qv_status,
                        location,
                        contextual_signature: signature.to_string(),
                        taint_chain: Vec::new(),
                        taint_nodes: Vec::new(),
                        via: Vec::new(),
                        key_size: rule.key_size(&node.const_args),
                        parameter_set: rule
                            .parameter_set_for(&arguments, &rule::Prepared::new(signature))
                            .map(|set| set.identifier.clone()),
                        with: Vec::new(),
                    },
                    instance.clone().unwrap_or_default(),
                ));
            }
        }
        let findings = one_per_instance(candidates);
        let findings = drop_cross_layer_duplicates(self, cpg, findings);
        let findings = drop_shadowed_fallbacks(self, cpg, findings);
        one_row_per_call(cpg, findings)
    }
}

type RepeatKey = (String, String, String, u32);

type Candidates = BTreeMap<RepeatKey, Vec<(usize, Finding, Instance)>>;

fn one_per_instance(candidates: Candidates) -> Vec<Finding> {
    let mut kept: Vec<(usize, Finding)> = Vec::new();
    for (_, mut members) in candidates {
        members.sort_by(|a, b| {
            b.2.specificity()
                .cmp(&a.2.specificity())
                .then(a.0.cmp(&b.0))
        });
        let mut clusters: Vec<(Instance, Vec<(usize, Finding)>)> = Vec::new();
        for (order, finding, instance) in members {
            match clusters
                .iter_mut()
                .find(|(seed, _)| seed.compatible(&instance))
            {
                Some((_, cluster)) => cluster.push((order, finding)),
                None => clusters.push((instance, vec![(order, finding)])),
            }
        }
        for (_, cluster) in clusters {
            if let Some(first) = cluster.into_iter().min_by_key(|(order, _)| *order) {
                kept.push(first);
            }
        }
    }
    kept.sort_by_key(|(order, _)| *order);
    kept.into_iter().map(|(_, finding)| finding).collect()
}

fn one_row_per_call(cpg: &Cpg, findings: Vec<Finding>) -> Vec<Finding> {
    let nodes: HashMap<u32, &CpgNode> = cpg.nodes().map(|n| (n.id, n)).collect();
    let local = |f: &Finding| nodes.get(&f.node_id).is_some_and(|n| n.dep_depth.is_none());
    let mut groups: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, f) in findings.iter().enumerate() {
        if local(f) {
            groups.entry(f.node_id).or_default().push(i);
        }
    }
    let severity = |s: QvStatus| match s {
        QvStatus::Vulnerable => 3,
        QvStatus::Deprecated => 2,
        QvStatus::Unknown => 1,
        QvStatus::Resistant => 0,
    };
    let mut out = Vec::with_capacity(findings.len());
    let mut done: HashSet<u32> = HashSet::new();
    for f in &findings {
        if !local(f) {
            out.push(f.clone());
            continue;
        }
        if !done.insert(f.node_id) {
            continue;
        }
        let group: Vec<&Finding> = groups[&f.node_id].iter().map(|&i| &findings[i]).collect();
        if group.len() == 1 {
            out.push(f.clone());
            continue;
        }
        let node = nodes[&f.node_id];
        let own = |g: &Finding| {
            g.contextual_signature == node.symbol
                || node.canonical.as_deref() == Some(g.contextual_signature.as_str())
        };
        let lead = group
            .iter()
            .filter(|g| own(g))
            .min_by(|a, b| a.rule_id.cmp(&b.rule_id))
            .or_else(|| group.iter().min_by(|a, b| a.rule_id.cmp(&b.rule_id)))
            .copied()
            .expect("a group has members");
        let mut parts: Vec<&Finding> = group
            .iter()
            .copied()
            .filter(|g| !std::ptr::eq(*g, lead))
            .collect();
        parts.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
        let mut row = lead.clone();
        row.qv_status = std::iter::once(lead)
            .chain(parts.iter().copied())
            .map(|g| g.qv_status)
            .max_by_key(|s| severity(*s))
            .unwrap_or(lead.qv_status);
        row.with = parts
            .iter()
            .map(|p| Part {
                rule_id: p.rule_id.clone(),
                signature: p.contextual_signature.clone(),
                qv_status: p.qv_status,
                parameter_set: p.parameter_set.clone(),
            })
            .collect();
        out.push(row);
    }
    out
}

fn calls_into_own_body(cpg: &Cpg) -> HashSet<u32> {
    let own: HashSet<u32> = cpg
        .nodes()
        .filter(|n| n.kind == NodeKind::Function && n.dep_depth.is_none())
        .map(|n| n.id)
        .collect();
    cpg.edges()
        .into_iter()
        .filter(|(_, to, kind)| *kind == EdgeKind::Call && own.contains(to))
        .map(|(from, _, _)| from)
        .collect()
}

impl RuleSet {
    fn type_argument_hits<'a>(&'a self, node: &'a CpgNode) -> Vec<(&'a Rule, &'a str)> {
        let mut best_per_rule: BTreeMap<&'a str, (&'a Rule, &'a str)> = BTreeMap::new();
        for type_arg in node.type_args.iter().chain(node.static_args.iter()) {
            let prepared = rule::Prepared::new(type_arg);
            for rule in &self.rules {
                if rule.matches_type_prepared(&prepared) {
                    best_per_rule
                        .entry(rule.id.as_str())
                        .or_insert((rule, type_arg.as_str()));
                }
            }
        }
        if best_per_rule.is_empty() {
            return Vec::new();
        }
        let best_per_class: HashMap<AlgorithmClass, (bool, bool, usize)> = best_per_rule
            .values()
            .map(|(rule, arg)| {
                (
                    suppression_class(rule.algorithm_class),
                    precedence(rule, arg),
                )
            })
            .fold(HashMap::new(), |mut acc, (class, rank)| {
                let slot = acc.entry(class).or_insert(rank);
                *slot = (*slot).max(rank);
                acc
            });
        best_per_rule
            .into_values()
            .filter(|(rule, arg)| {
                best_per_class.get(&suppression_class(rule.algorithm_class))
                    == Some(&precedence(rule, arg))
            })
            .collect()
    }
}

fn drop_shadowed_fallbacks(rules: &RuleSet, cpg: &Cpg, findings: Vec<Finding>) -> Vec<Finding> {
    let by_id: HashMap<&str, &Rule> = rules.rules.iter().map(|r| (r.id.as_str(), r)).collect();
    let rule_of = |f: &Finding| by_id.get(f.rule_id.as_str()).copied();
    let instances = instances_of(rules, cpg, &findings);

    let mut resolved_at: HashMap<(&str, u32), Vec<(&Rule, &Instance)>> = HashMap::new();
    for finding in &findings {
        let Some(rule) = rule_of(finding) else {
            continue;
        };
        if resolves_the_algorithm(rule) {
            resolved_at
                .entry((finding.location.file.as_str(), finding.location.line))
                .or_default()
                .push((rule, &instances[&finding.node_id]));
        }
    }

    let shadowed: HashSet<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| f.location.file != "<unknown>")
        .filter(|(_, f)| {
            rule_of(f).is_some_and(|fallback| {
                !fallback.is_specific()
                    && !resolves_the_algorithm(fallback)
                    && resolved_at
                        .get(&(f.location.file.as_str(), f.location.line))
                        .into_iter()
                        .flatten()
                        .any(|(resolver, instance)| {
                            supersedes(resolver, fallback)
                                && instance.compatible(&instances[&f.node_id])
                        })
            })
        })
        .map(|(i, _)| i)
        .collect();

    findings
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !shadowed.contains(i))
        .map(|(_, f)| f)
        .collect()
}

fn supersedes(resolver: &Rule, fallback: &Rule) -> bool {
    resolves_the_algorithm(resolver) && same_asset(resolver, fallback)
}

fn same_asset(resolver: &Rule, fallback: &Rule) -> bool {
    let (resolver_class, fallback_class) = (
        suppression_class(resolver.algorithm_class),
        suppression_class(fallback.algorithm_class),
    );
    if resolver_class == fallback_class {
        return true;
    }
    fallback_class == AlgorithmClass::Unknown && resolver_class != AlgorithmClass::Hash
}

fn inherent_owner_crate(canonical: &str) -> Option<&str> {
    let inner = canonical.trim().strip_prefix('<')?;
    let mut depth = 0usize;
    let mut end = None;
    for (i, c) in inner.char_indices() {
        match c {
            '<' => depth += 1,
            '>' if depth == 0 => {
                end = Some(i);
                break;
            }
            '>' => depth -= 1,
            ' ' if depth == 0 && inner[i..].starts_with(" as ") => return None,
            _ => {}
        }
    }
    let ty = inner[..end?].trim();
    if ty.starts_with(['&', '*', '[', '(']) || ty.starts_with("dyn ") {
        return None;
    }
    let (root, _) = ty.split_once("::")?;
    let valid = root.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && root.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    valid.then_some(root)
}

fn suppression_class(class: AlgorithmClass) -> AlgorithmClass {
    match class {
        AlgorithmClass::Symmetric => AlgorithmClass::Unknown,
        AlgorithmClass::Kdf => AlgorithmClass::Hash,
        AlgorithmClass::Ecdh => AlgorithmClass::EcdhX25519,
        AlgorithmClass::Dsa => AlgorithmClass::FiniteFieldDh,
        AlgorithmClass::EcKey => AlgorithmClass::Ecdsa,
        other => other,
    }
}

fn resolves_the_algorithm(rule: &Rule) -> bool {
    rule.crypto.algorithm_family.is_some()
}

fn resolved_trait_call(node: &CpgNode) -> Option<(rule::ResolvedCall, &str)> {
    if node.layer != IrLayer::Mir || node.kind != NodeKind::TraitMethod {
        return None;
    }
    let canonical = node.canonical.as_deref()?;
    Some((rule::ResolvedCall::of(canonical)?, canonical))
}

fn precedence(rule: &Rule, signature: &str) -> (bool, bool, usize) {
    (
        rule.is_specific(),
        suppression_class(rule.algorithm_class) != AlgorithmClass::Unknown,
        rule.match_depth(signature),
    )
}

fn instances_of(rules: &RuleSet, cpg: &Cpg, findings: &[Finding]) -> HashMap<u32, Instance> {
    let wanted: HashSet<u32> = findings.iter().map(|f| f.node_id).collect();
    cpg.nodes()
        .filter(|n| wanted.contains(&n.id))
        .map(|n| (n.id, rules.instance_of(n)))
        .collect()
}

fn drop_cross_layer_duplicates(rules: &RuleSet, cpg: &Cpg, findings: Vec<Finding>) -> Vec<Finding> {
    let layer_of: HashMap<u32, IrLayer> = cpg.nodes().map(|n| (n.id, n.layer)).collect();
    let by_id: HashMap<&str, &Rule> = rules.rules.iter().map(|r| (r.id.as_str(), r)).collect();

    let mut partners: HashMap<u32, Vec<u32>> = HashMap::new();
    for (src, dst, kind) in cpg.edges() {
        if kind == EdgeKind::CrossLayerRef {
            partners.entry(src).or_default().push(dst);
            partners.entry(dst).or_default().push(src);
        }
    }

    let is_mir = |f: &Finding| layer_of.get(&f.node_id) == Some(&IrLayer::Mir);
    let mir_findings: HashSet<(&str, u32)> = findings
        .iter()
        .filter(|f| is_mir(f))
        .map(|f| (f.rule_id.as_str(), f.node_id))
        .collect();
    let mir_classes: HashSet<(AlgorithmClass, u32)> = findings
        .iter()
        .filter(|f| is_mir(f))
        .map(|f| (suppression_class(f.algorithm_class), f.node_id))
        .collect();
    let mir_resolved: HashSet<u32> = findings
        .iter()
        .filter(|f| is_mir(f))
        .filter(|f| {
            by_id
                .get(f.rule_id.as_str())
                .is_some_and(|r| resolves_the_algorithm(r))
        })
        .map(|f| f.node_id)
        .collect();

    let superseded: HashSet<(&str, u32)> = findings
        .iter()
        .filter(|f| layer_of.get(&f.node_id) == Some(&IrLayer::Llvm))
        .filter(|f| {
            let is_fallback = !by_id
                .get(f.rule_id.as_str())
                .is_some_and(|r| r.is_specific());
            partners
                .get(&f.node_id)
                .into_iter()
                .flatten()
                .any(|partner| {
                    mir_findings.contains(&(f.rule_id.as_str(), *partner))
                        || mir_classes.contains(&(suppression_class(f.algorithm_class), *partner))
                        || (is_fallback && mir_resolved.contains(partner))
                })
        })
        .map(|f| (f.rule_id.as_str(), f.node_id))
        .collect();

    let instances = instances_of(rules, cpg, &findings);
    let mut mir_rule_lines: HashMap<(&str, &str, u32), Vec<&Instance>> = HashMap::new();
    for f in findings
        .iter()
        .filter(|f| is_mir(f) && f.location.file != "<unknown>")
    {
        mir_rule_lines
            .entry((
                f.rule_id.as_str(),
                f.location.file.as_str(),
                f.location.line,
            ))
            .or_default()
            .push(&instances[&f.node_id]);
    }
    let twins = findings
        .iter()
        .filter(|f| layer_of.get(&f.node_id) == Some(&IrLayer::Llvm))
        .filter(|f| {
            mir_rule_lines
                .get(&(
                    f.rule_id.as_str(),
                    f.location.file.as_str(),
                    f.location.line,
                ))
                .is_some_and(|mir| mir.iter().any(|i| i.compatible(&instances[&f.node_id])))
        })
        .map(|f| (f.rule_id.as_str(), f.node_id));

    let superseded: HashSet<(String, u32)> = superseded
        .into_iter()
        .chain(twins)
        .map(|(id, node)| (id.to_string(), node))
        .collect();

    type Handover<'a> = HashMap<(String, String, u32), Vec<(&'a Instance, String)>>;
    let mut handed_over: Handover = HashMap::new();
    for f in findings
        .iter()
        .filter(|f| superseded.contains(&(f.rule_id.clone(), f.node_id)))
    {
        if let Some(set) = f.parameter_set.clone() {
            handed_over
                .entry((f.rule_id.clone(), f.location.file.clone(), f.location.line))
                .or_default()
                .push((&instances[&f.node_id], set));
        }
    }
    let handed_to = |f: &Finding| -> Option<String> {
        let key = (f.rule_id.clone(), f.location.file.clone(), f.location.line);
        let mine = &instances[&f.node_id];
        let sets: BTreeSet<&String> = handed_over
            .get(&key)
            .into_iter()
            .flatten()
            .filter(|(instance, _)| instance.compatible(mine))
            .map(|(_, set)| set)
            .collect();
        (sets.len() == 1)
            .then(|| sets.into_iter().next().cloned())
            .flatten()
    };

    let specificity = |id: &str| by_id.get(id).map_or(0, |r| r.specificity());
    type Handed = (String, AlgorithmClass, QvStatus, Option<String>);
    let mut takes: HashMap<(u32, AlgorithmClass), Handed> = HashMap::new();
    for f in findings
        .iter()
        .filter(|f| layer_of.get(&f.node_id) == Some(&IrLayer::Llvm))
    {
        let class = suppression_class(f.algorithm_class);
        for partner in partners.get(&f.node_id).into_iter().flatten() {
            if !mir_classes.contains(&(class, *partner)) {
                continue;
            }
            let better = takes
                .get(&(*partner, class))
                .is_none_or(|(held, ..)| specificity(&f.rule_id) > specificity(held));
            if better {
                takes.insert(
                    (*partner, class),
                    (
                        f.rule_id.clone(),
                        f.algorithm_class,
                        f.qv_status,
                        f.parameter_set.clone(),
                    ),
                );
            }
        }
    }

    let mut seen = HashSet::new();
    findings
        .into_iter()
        .filter(|f| !superseded.contains(&(f.rule_id.clone(), f.node_id)))
        .map(|mut f| {
            if f.parameter_set.is_none() && is_mir(&f) {
                f.parameter_set = handed_to(&f);
            }
            if is_mir(&f) {
                let key = (f.node_id, suppression_class(f.algorithm_class));
                if let Some((rule, class, status, set)) = takes.get(&key) {
                    if specificity(rule) > specificity(&f.rule_id) {
                        f.rule_id = rule.to_string();
                        f.algorithm_class = *class;
                        f.qv_status = *status;
                        f.parameter_set = set.clone().or(f.parameter_set);
                    }
                }
            }
            f
        })
        .filter(|f| {
            seen.insert((
                f.rule_id.clone(),
                f.node_id,
                f.location.file.clone(),
                f.location.line,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_rule_file_is_embedded() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| {
                let path = e.unwrap().path();
                (path.extension()? == "toml").then(|| {
                    parse_rule(&std::fs::read_to_string(&path).unwrap())
                        .unwrap()
                        .id
                })
            })
            .collect();
        on_disk.sort();
        assert_eq!(on_disk, embedded_rule_ids());
    }

    use super::*;
    use cpg_core::{AlgorithmClass, QvStatus};

    #[test]
    fn a_paired_twin_keeps_the_more_specific_rule() {
        use cpg_core::{AblationMode, EdgeKind, IrLayer, NodeKind, SafetyCtx, SourceLoc};

        let mut cpg = Cpg::new(AblationMode::Dual);
        let at = || Some(SourceLoc::new("src/lib.rs", 32));
        let mir = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::TraitMethod,
            "signature::Signer::sign",
            None,
            at(),
            SafetyCtx::Safe,
        );
        cpg.set_type_args(
            mir,
            vec!["ecdsa::signing::SigningKey<p256::NistP256>".to_string()],
        );
        let llvm = cpg.add_node_full(
            IrLayer::Llvm,
            NodeKind::CallSite,
            "<ecdsa::signing::SigningKey<p256::NistP256> as signature::signer::Signer<ecdsa::Signature<p256::NistP256>>>::sign",
            None,
            at(),
            SafetyCtx::Safe,
        );
        cpg.add_edge(mir, llvm, EdgeKind::CrossLayerRef);

        let findings = RuleSet::builtin().match_cpg(&cpg);
        let got: Vec<(&str, u32)> = findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f.node_id))
            .collect();
        assert_eq!(got, [("R-ECDSA-002", cpg.node(mir).id)]);
    }

    #[test]
    fn a_paired_fallback_takes_its_twins_rule() {
        use cpg_core::{AblationMode, EdgeKind, IrLayer, NodeKind, SafetyCtx, SourceLoc};

        let mut cpg = Cpg::new(AblationMode::Dual);
        let at = || Some(SourceLoc::new("src/lib.rs", 89));
        let mir = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::TraitMethod,
            "signature::Signer::sign",
            None,
            at(),
            SafetyCtx::Safe,
        );
        cpg.set_type_args(
            mir,
            vec!["slh_dsa::signing_key::SigningKey<slh_dsa::hashes::shake::Shake128s>".to_string()],
        );
        let llvm = cpg.add_node_full(
            IrLayer::Llvm,
            NodeKind::CallSite,
            "<slh_dsa::signing_key::SigningKey<slh_dsa::hashes::shake::Shake128s> as signature::signer::Signer<slh_dsa::signature_encoding::Signature<slh_dsa::hashes::shake::Shake128s>>>::sign",
            None,
            at(),
            SafetyCtx::Safe,
        );
        cpg.add_edge(mir, llvm, EdgeKind::CrossLayerRef);

        let findings = RuleSet::builtin().match_cpg(&cpg);
        let got: Vec<(&str, u32)> = findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f.node_id))
            .collect();
        assert_eq!(got, [("R-SLHDSA-001", cpg.node(mir).id)]);
    }

    #[test]
    fn an_unpaired_twin_on_the_same_line_is_one_call() {
        use cpg_core::{AblationMode, IrLayer, NodeKind, SafetyCtx, SourceLoc};

        let mut cpg = Cpg::new(AblationMode::Dual);
        let at = || Some(SourceLoc::new("src/lib.rs", 9));
        cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::CallSite,
            "aes::Aes128::new",
            None,
            at(),
            SafetyCtx::Safe,
        );
        let llvm = cpg.add_node_full(
            IrLayer::Llvm,
            NodeKind::CallSite,
            "<aes::autodetect::Aes128 as crypto_common::KeyInit>::new",
            None,
            at(),
            SafetyCtx::Safe,
        );
        cpg.set_type_args(llvm, vec!["aes::Aes128".to_string()]);
        let other = cpg.add_node_full(
            IrLayer::Llvm,
            NodeKind::CallSite,
            "<aes::autodetect::Aes256 as crypto_common::KeyInit>::new",
            None,
            at(),
            SafetyCtx::Safe,
        );
        cpg.set_type_args(other, vec!["aes::Aes256".to_string()]);

        let findings = RuleSet::builtin().match_cpg(&cpg);
        let rules: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(
            rules.iter().filter(|r| **r == "R-AES-002").count(),
            1,
            "{rules:?}"
        );
        assert_eq!(
            rules.iter().filter(|r| **r == "R-AES-001").count(),
            1,
            "{rules:?}"
        );
    }

    #[test]
    fn a_function_used_as_a_value_is_matched_and_a_pointer_call_is_not() {
        use cpg_core::{AblationMode, IrLayer, NodeKind, SafetyCtx, SourceLoc};

        let mut cpg = Cpg::new(AblationMode::MirOnly);
        let reference = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::FnRef,
            "rsa::RsaPrivateKey::new",
            None,
            Some(SourceLoc::new("src/lib.rs", 3)),
            SafetyCtx::Safe,
        );
        cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::IndirectCall,
            "<indirect fn(&mut rsa::rand_core::OsRng, usize) -> rsa::RsaPrivateKey>",
            None,
            Some(SourceLoc::new("src/lib.rs", 4)),
            SafetyCtx::Safe,
        );
        let findings = RuleSet::builtin().match_cpg(&cpg);
        let hits: Vec<(&str, u32)> = findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f.location.line))
            .collect();
        assert_eq!(hits, [("R-RSA-001", 3)], "{hits:?}");
        assert_eq!(findings[0].node_id, cpg.node(reference).id);
    }

    #[test]
    fn shipped_rules_all_parse() {
        let set = RuleSet::builtin();
        assert_eq!(set.rules.len(), SHIPPED.len());
        assert!(set.rules.iter().all(|r| r.id.starts_with("R-")));
    }

    #[test]
    fn matches_rsa_call_site_and_ffi_in_demo() {
        let findings = RuleSet::builtin().match_cpg(&Cpg::demo());
        let by_rule =
            |id: &str| -> Vec<&Finding> { findings.iter().filter(|f| f.rule_id == id).collect() };

        assert_eq!(by_rule("R-RSA-002").len(), 2, "got: {findings:#?}");
        assert!(by_rule("R-RSA-002").iter().all(
            |f| f.algorithm_class == AlgorithmClass::Rsa && f.qv_status == QvStatus::Vulnerable
        ));

        let unresolved = by_rule("R-SIG-999");
        assert_eq!(unresolved.len(), 1, "got: {findings:#?}");
        assert_eq!(unresolved[0].algorithm_class, AlgorithmClass::Unknown);
        assert_eq!(unresolved[0].qv_status, QvStatus::Unknown);
    }

    #[test]
    fn a_trait_object_crypto_call_is_attributed_to_its_family() {
        use cpg_core::AblationMode;

        let mut cpg = Cpg::new(AblationMode::Dual);
        cpg.add_node(
            IrLayer::Mir,
            NodeKind::TraitMethod,
            "<dyn rsa::signature::Signer>::sign",
            Some(SourceLoc::new("src/main.rs", 29)),
        );
        let findings = RuleSet::builtin().match_cpg(&cpg);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].rule_id, "R-RSA-002");
    }

    #[test]
    fn a_named_api_suppresses_its_family_fallback() {
        use cpg_core::AblationMode;

        let mut cpg = Cpg::new(AblationMode::Dual);
        cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::RsaPrivateKey::new",
            Some(SourceLoc::new("src/main.rs", 21)),
        );
        cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::RsaPrivateKey::validate",
            Some(SourceLoc::new("src/main.rs", 22)),
        );

        let findings = RuleSet::builtin().match_cpg(&cpg);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(ids, ["R-RSA-001", "R-RSA-999"], "got: {findings:#?}");
    }

    #[test]
    fn the_fallback_does_not_report_signature_encoding() {
        use cpg_core::AblationMode;

        let mut cpg = Cpg::new(AblationMode::Dual);
        cpg.add_node(
            IrLayer::Mir,
            NodeKind::TraitMethod,
            "rsa::signature::SignatureEncoding::to_vec",
            Some(SourceLoc::new("src/main.rs", 23)),
        );
        assert!(RuleSet::builtin().match_cpg(&cpg).is_empty());
    }

    #[test]
    fn the_rule_set_is_silent_on_ordinary_code() {
        let rules = RuleSet::builtin();
        for symbol in [
            "serde::Deserialize::deserialize",
            "serde::Serialize::serialize",
            "serde_json::from_str",
            "std::fmt::Debug::fmt",
            "core::ptr::drop_in_place",
            "tokio::runtime::Runtime::new",
            "std::collections::HashMap::insert",
            "clap::Parser::parse",
            "std::process::Command::new",
            "regex::Regex::new",
            "std::sync::Arc::clone",
            "anyhow::Context::context",
            "std::io::Read::read",
            "ctrlc::set_handler",
            "descriptor::Descriptor::new",
            "aesthetic::Theme::new",
            "demo_crate::sign_with_rsa",
            "demo_crate::encrypt_settings",
            "app::KeyValueStore::insert_key",
        ] {
            let hits: Vec<&str> = rules
                .rules
                .iter()
                .filter(|rule| rule.matches(symbol))
                .map(|rule| rule.id.as_str())
                .collect();
            assert!(hits.is_empty(), "{symbol} wrongly matched {hits:?}");
        }
    }

    #[test]
    fn a_pqc_type_is_not_also_a_symmetric_cipher() {
        use cpg_core::AblationMode;

        let mut cpg = Cpg::new(AblationMode::Dual);
        cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "pqcrypto_mlkem::mlkem768::Ciphertext::from_bytes",
            Some(SourceLoc::new("src/kem.rs", 4)),
        );
        let findings = RuleSet::builtin().match_cpg(&cpg);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(ids, ["R-PQC-999"], "got: {findings:#?}");
    }

    #[test]
    fn aes_128_and_aes_256_are_told_apart() {
        use cpg_core::AblationMode;

        let verdict = |symbol: &str| {
            let mut cpg = Cpg::new(AblationMode::Dual);
            cpg.add_node(
                IrLayer::Mir,
                NodeKind::CallSite,
                symbol,
                Some(SourceLoc::new("src/crypto.rs", 7)),
            );
            let findings = RuleSet::builtin().match_cpg(&cpg);
            assert_eq!(findings.len(), 1, "got: {findings:#?}");
            (findings[0].rule_id.clone(), findings[0].qv_status)
        };

        let (id_256, status_256) = verdict("<aes::Aes256 as crypto_common::KeyInit>::new");
        assert_eq!(id_256, "R-AES-001");
        assert_eq!(status_256, QvStatus::Resistant);

        let (id_128, status_128) = verdict("<aes::Aes128 as crypto_common::KeyInit>::new");
        assert_eq!(id_128, "R-AES-002");
        assert_eq!(status_128, QvStatus::Deprecated);
    }

    #[test]
    fn a_generic_hasher_is_unknown_not_assumed_safe() {
        use cpg_core::AblationMode;

        let mut cpg = Cpg::new(AblationMode::Dual);
        cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "digest::Digest::digest",
            Some(SourceLoc::new("src/hash.rs", 3)),
        );
        let findings = RuleSet::builtin().match_cpg(&cpg);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].rule_id, "R-HASH-999");
        assert_eq!(findings[0].qv_status, QvStatus::Unknown);
        assert_eq!(findings[0].algorithm_class, AlgorithmClass::Hash);
    }

    #[test]
    fn a_blake2_hasher_named_by_its_core_is_one_finding() {
        for (core, set) in [
            ("blake2::Blake2bVarCore", "BLAKE2b"),
            ("blake2::Blake2sVarCore", "BLAKE2s"),
        ] {
            let cpg = call_with_type_args(
                "blake2::Digest::new",
                &[
                    "digest::core_api::wrapper::CoreWrapper",
                    "digest::core_api::ct_variable::CtVariableCoreWrapper",
                    core,
                ],
            );
            let findings = RuleSet::builtin().match_cpg(&cpg);
            let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
            assert_eq!(ids, ["R-BLAKE-001"], "{core}: {findings:#?}");
            assert_eq!(findings[0].qv_status, QvStatus::Resistant);
            assert_eq!(findings[0].parameter_set.as_deref(), Some(set));
        }
    }

    #[test]
    fn a_fallback_names_the_scheme_its_call_path_settles() {
        use cpg_core::AblationMode;

        let set = |layer: IrLayer, symbol: &str| {
            let mut cpg = Cpg::new(AblationMode::Dual);
            cpg.add_node(
                layer,
                NodeKind::CallSite,
                symbol,
                Some(SourceLoc::new("src/dh.rs", 9)),
            );
            let findings = RuleSet::builtin().match_cpg(&cpg);
            assert_eq!(findings.len(), 1, "{symbol}: {findings:#?}");
            (
                findings[0].rule_id.clone(),
                findings[0].parameter_set.clone(),
            )
        };
        let want = |id: &str, set: Option<&str>| (id.to_string(), set.map(str::to_string));

        for (layer, symbol, expected) in [
            (
                IrLayer::Mir,
                "curve25519_dalek::MontgomeryPoint::mul_clamped",
                want("R-X25519-999", Some("X25519")),
            ),
            (
                IrLayer::Llvm,
                "<curve25519_dalek::montgomery::MontgomeryPoint>::mul_base_clamped",
                want("R-X25519-999", Some("X25519")),
            ),
            (
                IrLayer::Mir,
                "x25519_dalek::SharedSecret::was_contributory",
                want("R-X25519-999", Some("X25519")),
            ),
            (
                IrLayer::Mir,
                "x448::Secret::to_public",
                want("R-X25519-999", Some("X448")),
            ),
            (
                IrLayer::Mir,
                "curve25519_dalek::EdwardsPoint::mul_base",
                want("R-X25519-999", None),
            ),
            (
                IrLayer::Mir,
                "ed25519_dalek::SigningKey::to_scalar",
                want("R-ED25519-999", Some("Ed25519")),
            ),
            (
                IrLayer::Mir,
                "ed448::SigningKey::to_scalar",
                want("R-ED25519-999", Some("Ed448")),
            ),
        ] {
            assert_eq!(set(layer, symbol), expected, "{symbol}");
        }
    }

    #[test]
    fn each_ring_operation_carries_its_own_class() {
        use cpg_core::AblationMode;

        for (symbol, rule, class) in [
            (
                "ring::aead::UnboundKey::new",
                "R-RING-005",
                AlgorithmClass::Aead,
            ),
            ("ring::digest::digest", "R-RING-006", AlgorithmClass::Hash),
            ("ring::hmac::sign", "R-RING-007", AlgorithmClass::Hash),
            ("ring::pbkdf2::derive", "R-RING-008", AlgorithmClass::Kdf),
            ("ring::hkdf::Salt::new", "R-RING-008", AlgorithmClass::Kdf),
        ] {
            let mut cpg = Cpg::new(AblationMode::Dual);
            cpg.add_node(
                IrLayer::Mir,
                NodeKind::CallSite,
                symbol,
                Some(SourceLoc::new("src/ring.rs", 3)),
            );
            let findings = RuleSet::builtin().match_cpg(&cpg);
            assert_eq!(findings.len(), 1, "{symbol}: {findings:#?}");
            assert_eq!(
                (findings[0].rule_id.as_str(), findings[0].algorithm_class),
                (rule, class),
                "{symbol}"
            );
        }
    }

    #[test]
    fn a_type_named_rule_under_a_fallback_anchor_names_its_family() {
        let rules = RuleSet::builtin();
        let mut unnamed = Vec::new();
        for rule in &rules.rules {
            if rule.qv_status == QvStatus::Unknown || resolves_the_algorithm(rule) {
                continue;
            }
            for type_name in &rule.match_spec.type_names {
                let root = type_name.split("::").next().unwrap_or_default();
                for fallback in rules
                    .rules
                    .iter()
                    .filter(|f| f.id != rule.id && !f.is_specific() && f.anchors_crate(root))
                {
                    if same_asset(rule, fallback) {
                        unnamed.push(format!("{} ({type_name}) beside {}", rule.id, fallback.id));
                    }
                }
            }
        }
        assert!(
            unnamed.is_empty(),
            "rules that would report beside a fallback:\n  {}",
            unnamed.join("\n  ")
        );
    }

    fn fired(findings: &[Finding]) -> Vec<(String, QvStatus)> {
        findings
            .iter()
            .flat_map(|f| {
                std::iter::once((f.rule_id.clone(), f.qv_status))
                    .chain(f.with.iter().map(|p| (p.rule_id.clone(), p.qv_status)))
            })
            .collect()
    }

    fn call_with_type_args(symbol: &str, type_args: &[&str]) -> Cpg {
        use cpg_core::AblationMode;

        let mut cpg = Cpg::new(AblationMode::Dual);
        let node = cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            symbol,
            Some(SourceLoc::new("src/main.rs", 22)),
        );
        cpg.set_type_args(node, type_args.iter().map(|s| s.to_string()).collect());
        cpg
    }

    #[test]
    fn a_digest_named_only_as_a_type_parameter_is_inventoried() {
        let cpg = call_with_type_args(
            "rsa::pkcs1v15::SigningKey::<D>::new",
            &["rsa::sha2::Sha256VarCore", "rsa::sha2::OidSha256"],
        );
        let findings = RuleSet::builtin().match_cpg(&cpg);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        let row = &findings[0];
        assert_eq!(row.rule_id, "R-RSA-005");
        assert_eq!(row.qv_status, QvStatus::Vulnerable);
        assert_eq!(
            row.with,
            vec![cpg_core::Part {
                rule_id: "R-SHA2-001".into(),
                signature: "rsa::sha2::OidSha256".into(),
                qv_status: QvStatus::Resistant,
                parameter_set: None,
            }]
        );
    }

    #[test]
    fn a_ring_call_is_one_row_rated_by_its_constant() {
        use cpg_core::AblationMode;

        for (constant, rule, status, set) in [
            (
                "ring::aead::AES_128_GCM",
                "R-RING-ALG-003",
                QvStatus::Deprecated,
                "AES-128",
            ),
            (
                "ring::aead::AES_256_GCM",
                "R-RING-ALG-002",
                QvStatus::Resistant,
                "AES-256",
            ),
        ] {
            let mut cpg = Cpg::new(AblationMode::Dual);
            let node = cpg.add_node(
                IrLayer::Mir,
                NodeKind::CallSite,
                "ring::aead::UnboundKey::new",
                Some(SourceLoc::new("src/aead.rs", 26)),
            );
            cpg.set_static_args(node, vec![constant.to_string()]);
            let findings = RuleSet::builtin().match_cpg(&cpg);
            assert_eq!(findings.len(), 1, "{constant}: {findings:#?}");
            let row = &findings[0];
            assert_eq!(row.rule_id, "R-RING-005");
            assert_eq!(row.qv_status, status, "{constant}");
            assert_eq!(
                row.with,
                vec![cpg_core::Part {
                    rule_id: rule.into(),
                    signature: constant.into(),
                    qv_status: status,
                    parameter_set: Some(set.into()),
                }]
            );
        }
    }

    #[test]
    fn an_ambiguous_digest_core_is_unresolved_not_assumed() {
        let cpg = call_with_type_args(
            "rsa::pkcs1v15::SigningKey::<D>::new",
            &["rsa::sha2::Sha256VarCore"],
        );
        let findings = RuleSet::builtin().match_cpg(&cpg);
        let hash: Vec<(String, QvStatus)> = fired(&findings)
            .into_iter()
            .filter(|(id, _)| id.starts_with("R-HASH") || id.starts_with("R-SHA2"))
            .collect();
        assert_eq!(
            hash,
            [("R-HASH-999".to_string(), QvStatus::Unknown)],
            "got: {findings:#?}"
        );
    }

    #[test]
    fn one_rule_reports_a_type_parameter_once() {
        let cpg = call_with_type_args(
            "rsa::pkcs1v15::SigningKey::<D>::new",
            &["rsa::sha2::OidSha256", "sha2::Sha256"],
        );
        let findings = RuleSet::builtin().match_cpg(&cpg);
        let sha = fired(&findings)
            .into_iter()
            .filter(|(id, _)| id == "R-SHA2-001")
            .count();
        assert_eq!(sha, 1, "got: {findings:#?}");
    }

    #[test]
    fn attribution_does_not_depend_on_the_callers_import_path() {
        let resolve = |symbol: &str| {
            let cpg = call_with_type_args(symbol, &["rsa::pkcs1v15::SigningKey"]);
            let mut ids: Vec<String> = RuleSet::builtin()
                .match_cpg(&cpg)
                .into_iter()
                .map(|f| f.rule_id)
                .collect();
            ids.sort();
            ids
        };

        assert_eq!(resolve("rsa::signature::Signer::sign"), ["R-RSA-002"]);
        assert_eq!(resolve("signature::Signer::sign"), ["R-RSA-007"]);
    }

    #[test]
    fn a_resolved_digest_does_not_silence_the_operation_it_parameterises() {
        let cpg = call_with_type_args(
            "signature::RandomizedSigner::sign_with_rng",
            &["rsa::pkcs1v15::SigningKey", "rsa::sha2::OidSha256"],
        );
        let mut ids: Vec<String> = fired(&RuleSet::builtin().match_cpg(&cpg))
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        ids.sort();
        assert_eq!(ids, ["R-RSA-007", "R-SHA2-001"]);
    }

    #[test]
    fn a_resolved_digest_still_silences_an_unresolved_hash() {
        let cpg = call_with_type_args("sha2::Digest::digest", &["rsa::sha2::OidSha256"]);
        let ids: Vec<String> = RuleSet::builtin()
            .match_cpg(&cpg)
            .into_iter()
            .map(|f| f.rule_id)
            .collect();
        assert_eq!(ids, ["R-SHA2-001"]);
    }

    #[test]
    fn a_fallback_is_silent_where_another_finding_already_named_the_line() {
        use cpg_core::AblationMode;

        let mut cpg = Cpg::new(AblationMode::Dual);
        let mir = cpg.add_node(
            IrLayer::Mir,
            NodeKind::TraitMethod,
            "cipher::BlockEncryptMut::encrypt_blocks_mut",
            Some(SourceLoc::new("src/aead.rs", 455)),
        );
        cpg.set_type_args(mir, vec!["aes::Aes128".to_string()]);
        cpg.add_node(
            IrLayer::Llvm,
            NodeKind::CallSite,
            "<aes_gcm::AesGcm<aes::Aes128, U12> as aead::AeadInPlace>::encrypt_in_place_detached",
            Some(SourceLoc::new("src/aead.rs", 455)),
        );

        let findings = RuleSet::builtin().match_cpg(&cpg);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(ids, ["R-AES-002"], "got: {findings:#?}");
    }

    #[test]
    fn an_unknown_location_is_not_a_shared_line() {
        use cpg_core::AblationMode;

        let mut cpg = Cpg::new(AblationMode::Dual);
        let resolved = cpg.add_node(
            IrLayer::Mir,
            NodeKind::TraitMethod,
            "cipher::BlockEncryptMut::encrypt_blocks_mut",
            None,
        );
        cpg.set_type_args(resolved, vec!["aes::Aes128".to_string()]);
        cpg.add_node(
            IrLayer::Llvm,
            NodeKind::CallSite,
            "cipher::BlockDecryptMut::decrypt_blocks_mut",
            None,
        );

        let mut ids: Vec<String> = RuleSet::builtin()
            .match_cpg(&cpg)
            .into_iter()
            .map(|f| f.rule_id)
            .collect();
        ids.sort();
        assert_eq!(ids, ["R-AES-002", "R-SYM-999"]);
    }

    #[test]
    fn a_digest_does_not_shadow_an_operation_on_the_same_line() {
        use cpg_core::AblationMode;

        let mut cpg = Cpg::new(AblationMode::Dual);
        cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "<sha2::Sha256 as digest::Digest>::digest",
            Some(SourceLoc::new("src/main.rs", 23)),
        );
        cpg.add_node(
            IrLayer::Mir,
            NodeKind::TraitMethod,
            "<dyn signature::Signer>::sign",
            Some(SourceLoc::new("src/main.rs", 23)),
        );

        let mut ids: Vec<String> = RuleSet::builtin()
            .match_cpg(&cpg)
            .into_iter()
            .map(|f| f.rule_id)
            .collect();
        ids.sort();
        assert_eq!(ids, ["R-SHA2-001", "R-SIG-999"]);
    }

    #[test]
    fn a_cipher_named_only_by_generic_argument_is_told_apart() {
        let verdict = |type_arg: &str| {
            let cpg =
                call_with_type_args("cipher::BlockEncryptMut::encrypt_blocks_mut", &[type_arg]);
            let findings = RuleSet::builtin().match_cpg(&cpg);
            assert_eq!(findings.len(), 1, "{type_arg} got: {findings:#?}");
            (findings[0].rule_id.clone(), findings[0].qv_status)
        };

        assert_eq!(
            verdict("aes::Aes256"),
            ("R-AES-001".into(), QvStatus::Resistant)
        );
        assert_eq!(
            verdict("aes::Aes128"),
            ("R-AES-002".into(), QvStatus::Deprecated)
        );
        assert_eq!(
            verdict("des::TdesEde3"),
            ("R-3DES-001".into(), QvStatus::Deprecated)
        );
        assert_eq!(
            verdict("twofish::Twofish"),
            ("R-TWOFISH-001".into(), QvStatus::Unknown)
        );
    }

    #[test]
    fn a_resolved_algorithm_silences_the_fallback_that_could_not_name_it() {
        let cpg = call_with_type_args(
            "cipher::BlockEncryptMut::encrypt_blocks_mut",
            &["aes::Aes256"],
        );
        let ids: Vec<String> = RuleSet::builtin()
            .match_cpg(&cpg)
            .into_iter()
            .map(|f| f.rule_id)
            .collect();
        assert_eq!(ids, ["R-AES-001"]);

        let bare = call_with_type_args("cipher::BlockEncryptMut::encrypt_blocks_mut", &[]);
        let ids: Vec<String> = RuleSet::builtin()
            .match_cpg(&bare)
            .into_iter()
            .map(|f| f.rule_id)
            .collect();
        assert_eq!(ids, ["R-SYM-999"]);
    }

    #[test]
    fn resolving_a_type_argument_does_not_silence_an_enumerated_rule() {
        let cpg = call_with_type_args(
            "rsa::pkcs1v15::SigningKey::<D>::new",
            &["rsa::sha2::OidSha256"],
        );
        let ids: Vec<String> = fired(&RuleSet::builtin().match_cpg(&cpg))
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(ids, ["R-RSA-005", "R-SHA2-001"]);
    }

    #[test]
    fn an_ambiguous_type_argument_does_not_silence_the_fallback() {
        let cpg = call_with_type_args("digest::Digest::digest", &["sha2::Sha256VarCore"]);
        let findings = RuleSet::builtin().match_cpg(&cpg);
        assert!(
            findings.iter().all(|f| f.rule_id == "R-HASH-999"),
            "got: {findings:#?}"
        );
        assert!(findings.iter().all(|f| f.qv_status == QvStatus::Unknown));
    }

    #[test]
    fn type_parameters_of_a_non_crypto_call_are_ignored() {
        let cpg = call_with_type_args(
            "std::result::Result::<T, E>::expect",
            &["rsa::sha2::OidSha256", "rsa::RsaPrivateKey"],
        );
        assert!(RuleSet::builtin().match_cpg(&cpg).is_empty());
    }

    #[test]
    fn a_keygen_call_carries_its_key_size_onto_the_finding() {
        use cpg_core::{AblationMode, ConstArg};

        let mut cpg = Cpg::new(AblationMode::Dual);
        let node = cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::RsaPrivateKey::new",
            Some(SourceLoc::new("src/main.rs", 21)),
        );
        cpg.set_const_args(
            node,
            vec![ConstArg {
                index: 1,
                value: 2048,
            }],
        );

        let findings = RuleSet::builtin().match_cpg(&cpg);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].rule_id, "R-RSA-001");
        assert_eq!(findings[0].key_size, Some(2048));
    }

    #[test]
    fn a_signing_call_has_no_key_size_yet() {
        use cpg_core::AblationMode;

        let mut cpg = Cpg::new(AblationMode::Dual);
        cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::pkcs1v15::SigningKey::sign",
            Some(SourceLoc::new("src/main.rs", 23)),
        );
        let findings = RuleSet::builtin().match_cpg(&cpg);
        assert_eq!(findings[0].rule_id, "R-RSA-002");
        assert_eq!(findings[0].key_size, None);
    }

    #[test]
    fn ecdh_is_key_agreement_not_a_signature() {
        use cpg_core::AblationMode;

        let mut cpg = Cpg::new(AblationMode::Dual);
        cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "p256::ecdh::EphemeralSecret::diffie_hellman",
            Some(SourceLoc::new("src/kex.rs", 8)),
        );
        let findings = RuleSet::builtin().match_cpg(&cpg);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].rule_id, "R-ECDH-001");
    }

    #[test]
    fn every_shipped_rule_fires_on_something() {
        use cpg_core::AblationMode;

        let probes: &[(&[&str], &str, &[&str])] = &[
            (&["R-RSA-001"], "rsa::RsaPrivateKey::new", &[]),
            (&["R-RSA-002"], "rsa::pkcs1v15::SigningKey::sign", &[]),
            (&["R-RSA-003"], "rsa::pkcs1v15::VerifyingKey::verify", &[]),
            (&["R-RSA-004"], "rsa::RsaPublicKey::encrypt", &[]),
            (&["R-RSA-005"], "rsa::pkcs1v15::SigningKey::<D>::new", &[]),
            (&["R-RSA-006"], "rsa::pss::BlindedSigningKey::random", &[]),
            (&["R-RSA-999"], "rsa::RsaPrivateKey::validate", &[]),
            (&["R-ECDSA-001"], "p256::ecdsa::SigningKey::random", &[]),
            (
                &["R-ECDSA-002"],
                "p256::ecdsa::SigningKey::sign_prehash",
                &[],
            ),
            (&["R-ECDSA-003"], "p256::ecdsa::VerifyingKey::verify", &[]),
            (&["R-EC-999"], "p256::AffinePoint::decompress", &[]),
            (&["R-ECDSA-999"], "ecdsa::Signature::<C>::normalize_s", &[]),
            (
                &["R-ED25519-001"],
                "ed25519_dalek::SigningKey::generate",
                &[],
            ),
            (&["R-ED25519-002"], "ed25519_dalek::SigningKey::sign", &[]),
            (
                &["R-ED25519-003"],
                "ed25519_dalek::VerifyingKey::verify_strict",
                &[],
            ),
            (
                &["R-ED25519-999"],
                "ed25519_dalek::Signature::from_components",
                &[],
            ),
            (&["R-DSA-001"], "dsa::SigningKey::generate", &[]),
            (&["R-DSA-999"], "dsa::VerifyingKey::to_public_key_der", &[]),
            (
                &["R-X25519-001"],
                "x25519_dalek::EphemeralSecret::random",
                &[],
            ),
            (
                &["R-X25519-002"],
                "x25519_dalek::EphemeralSecret::diffie_hellman",
                &[],
            ),
            (
                &["R-ECDH-001"],
                "p256::ecdh::EphemeralSecret::diffie_hellman",
                &[],
            ),
            (
                &["R-X25519-999"],
                "x25519_dalek::SharedSecret::was_contributory",
                &[],
            ),
            (
                &["R-MLKEM-001"],
                "pqcrypto_mlkem::mlkem768::encapsulate",
                &[],
            ),
            (
                &["R-MLDSA-001"],
                "pqcrypto_mldsa::mldsa65::detached_sign",
                &[],
            ),
            (&["R-SLHDSA-001"], "slh_dsa::SigningKey::try_sign", &[]),
            (&["R-PQC-999"], "oqs::kem::Kem::new", &[]),
            (&["R-SIG-999"], "<dyn signature::Signer>::sign", &[]),
            (&[], "signature::Error::from_source", &[]),
            (
                &["R-RSA-007"],
                "signature::Signer::sign",
                &["rsa::pkcs1v15::SigningKey"],
            ),
            (
                &["R-RSA-008"],
                "signature::RandomizedSigner::sign_with_rng",
                &["rsa::pss::BlindedSigningKey"],
            ),
            (
                &["R-ECDSA-004"],
                "signature::Signer::sign",
                &["ecdsa::SigningKey"],
            ),
            (
                &["R-ED25519-004"],
                "signature::Verifier::verify",
                &["ed25519::Signature"],
            ),
            (
                &["R-DSA-002"],
                "signature::Signer::sign",
                &["dsa::SigningKey"],
            ),
            (
                &["R-SHA2-001"],
                "<sha2::Sha256 as digest::Digest>::digest",
                &[],
            ),
            (
                &["R-SHA2-002"],
                "<sha2::Sha384 as digest::Digest>::new",
                &[],
            ),
            (
                &["R-SHA2-003"],
                "<sha2::Sha512 as digest::Digest>::new",
                &[],
            ),
            (
                &["R-SHA2-004"],
                "<sha2::Sha224 as digest::Digest>::new",
                &[],
            ),
            (
                &["R-SHA3-001"],
                "<sha3::Sha3_256 as digest::Digest>::new",
                &[],
            ),
            (
                &["R-SHA3-002"],
                "<sha3::Sha3_224 as digest::Digest>::new",
                &[],
            ),
            (&["R-BLAKE-001"], "blake2::Blake2s256::digest", &[]),
            (&["R-BLAKE-002"], "blake3::hash", &[]),
            (&["R-MD5-001"], "<md5::Md5 as digest::Digest>::digest", &[]),
            (&["R-SHA1-001"], "<sha1::Sha1 as digest::Digest>::new", &[]),
            (&["R-HASH-999"], "digest::Digest::digest", &[]),
            (
                &["R-AES-001"],
                "<aes::Aes256 as crypto_common::KeyInit>::new",
                &[],
            ),
            (
                &["R-AES-002"],
                "<aes::Aes128 as crypto_common::KeyInit>::new",
                &[],
            ),
            (
                &["R-AES-003"],
                "<aes::Aes192 as crypto_common::KeyInit>::new",
                &[],
            ),
            (&["R-SYM-999"], "aead::Aead::encrypt", &[]),
            (
                &["R-CHACHA-002"],
                "chacha20poly1305::KeyInit::new",
                &["chacha20poly1305::ChaChaPoly1305"],
            ),
            (
                &["R-CAMELLIA-001"],
                "cipher::BlockEncryptMut::encrypt_blocks_mut",
                &["camellia::Camellia256"],
            ),
            (
                &["R-CAMELLIA-002"],
                "cipher::BlockEncryptMut::encrypt_blocks_mut",
                &["camellia::Camellia128"],
            ),
            (
                &["R-CAMELLIA-003"],
                "cipher::BlockEncryptMut::encrypt_blocks_mut",
                &["camellia::Camellia192"],
            ),
            (
                &["R-TWOFISH-001"],
                "cipher::BlockEncryptMut::encrypt_blocks_mut",
                &["twofish::Twofish"],
            ),
            (
                &["R-3DES-001"],
                "cipher::BlockDecryptMut::decrypt_blocks_mut",
                &["des::TdesEde3"],
            ),
            (
                &["R-BLOWFISH-001"],
                "cipher::BlockDecryptMut::decrypt_blocks_mut",
                &["blowfish::Blowfish"],
            ),
            (
                &["R-CAST5-001"],
                "cipher::BlockDecryptMut::decrypt_blocks_mut",
                &["cast5::Cast5"],
            ),
            (
                &["R-IDEA-001"],
                "cipher::BlockDecryptMut::decrypt_blocks_mut",
                &["idea::Idea"],
            ),
            (&["R-RING-001"], "ring::rsa::KeyPair::from_pkcs8", &[]),
            (
                &["R-RING-002"],
                "ring::signature::UnparsedPublicKey::<B>::new",
                &[],
            ),
            (
                &["R-RING-003"],
                "ring::signature::Ed25519KeyPair::sign",
                &[],
            ),
            (
                &["R-RING-004"],
                "ring::agreement::EphemeralPrivateKey::generate",
                &[],
            ),
            (
                &["R-RING-005"],
                "ring::aead::LessSafeKey::open_in_place",
                &[],
            ),
            (&["R-RING-006"], "ring::digest::digest", &[]),
            (&["R-RING-007"], "ring::hmac::sign", &[]),
            (&["R-RING-008"], "ring::pbkdf2::derive", &[]),
            (&["R-TLS-001"], "rustls::ClientConfig::builder", &[]),
            (&["R-OPENSSL-001"], "openssl::rsa::Rsa::generate", &[]),
            (
                &["R-OPENSSL-002"],
                "openssl::symm::Cipher::aes_256_gcm",
                &[],
            ),
            (
                &["R-OPENSSL-003"],
                "openssl::symm::Cipher::aes_128_gcm",
                &[],
            ),
            (&["R-X448-001"], "cx448::x448::Secret::new", &[]),
            (&["R-ED448-001"], "cx448::SigningKey::sign_raw", &[]),
            (
                &["R-ARGON2-001"],
                "argon2::Argon2::<'key>::hash_password_into",
                &[],
            ),
            (&["R-SCRYPT-001"], "scrypt::scrypt", &[]),
            (&["R-PBKDF2-001"], "pbkdf2::pbkdf2_hmac", &[]),
            (&["R-OPENSSL-004"], "openssl::sha::sha256", &[]),
            (&["R-OPENSSL-005"], "openssl::sha::sha1", &[]),
            (
                &["R-OPENSSL-006"],
                "openssl::sign::Signer::<'_>::sign_to_vec",
                &[],
            ),
            (
                &["R-RING-004", "R-RING-ALG-001"],
                "ring::agreement::EphemeralPrivateKey::generate",
                &["ring::agreement::X25519"],
            ),
            (
                &["R-RING-005", "R-RING-ALG-002"],
                "ring::aead::UnboundKey::new",
                &["ring::aead::AES_256_GCM"],
            ),
            (
                &["R-RING-005", "R-RING-ALG-003"],
                "ring::aead::UnboundKey::new",
                &["ring::aead::AES_128_GCM"],
            ),
        ];

        let rules = RuleSet::builtin();
        for (expected, symbol, args) in probes {
            let mut cpg = Cpg::new(AblationMode::Dual);
            let node = cpg.add_node(
                IrLayer::Mir,
                NodeKind::CallSite,
                *symbol,
                Some(SourceLoc::new("src/probe.rs", 1)),
            );
            cpg.set_static_args(node, args.iter().map(|s| s.to_string()).collect());

            let mut ids: Vec<String> = rules
                .match_cpg(&cpg)
                .into_iter()
                .flat_map(|f| {
                    std::iter::once(f.rule_id).chain(f.with.into_iter().map(|p| p.rule_id))
                })
                .collect();
            ids.sort();
            let mut want: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
            want.sort();
            assert_eq!(ids, want, "{symbol} with args {args:?}");
        }

        let covered: HashSet<&str> = probes
            .iter()
            .flat_map(|(ids, _, _)| ids.iter().copied())
            .collect();
        let shipped: HashSet<&str> = rules.rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(covered, shipped);
    }

    fn dual_layer_cpg() -> Cpg {
        use cpg_core::{AblationMode, IrLayer};

        let mut cpg = Cpg::new(AblationMode::Dual);
        let mir_call = cpg.add_node(
            IrLayer::Mir,
            NodeKind::CallSite,
            "rsa::RsaPrivateKey::new",
            Some(SourceLoc::new("src/main.rs", 21)),
        );
        let llvm_call = cpg.add_node(
            IrLayer::Llvm,
            NodeKind::CallSite,
            "<rsa::key::RsaPrivateKey>::new::<R>",
            None,
        );
        cpg.add_node(
            IrLayer::Llvm,
            NodeKind::FfiBoundary,
            "rsa_only_after_monomorphisation",
            None,
        );
        cpg.add_edge(mir_call, llvm_call, EdgeKind::CrossLayerRef);
        cpg
    }

    #[test]
    fn the_same_call_at_both_layers_is_one_finding() {
        let findings = RuleSet::builtin().match_cpg(&dual_layer_cpg());
        let rsa_new: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.contextual_signature.contains("RsaPrivateKey"))
            .collect();
        assert_eq!(rsa_new.len(), 1, "got: {rsa_new:#?}");
        assert_eq!(rsa_new[0].location.file, "src/main.rs");
        assert_eq!(rsa_new[0].location.line, 21);
    }

    #[test]
    fn a_resolved_mir_call_supersedes_its_unresolved_llvm_partner() {
        use cpg_core::AblationMode;

        let mut cpg = Cpg::new(AblationMode::Dual);
        let mir = cpg.add_node(
            IrLayer::Mir,
            NodeKind::TraitMethod,
            "chacha20poly1305::KeyInit::new",
            Some(SourceLoc::new("src/aead.rs", 19)),
        );
        cpg.set_type_args(mir, vec!["chacha20poly1305::ChaChaPoly1305".to_string()]);
        let llvm = cpg.add_node(
            IrLayer::Llvm,
            NodeKind::CallSite,
            "<chacha20poly1305::ChaChaPoly1305<C> as crypto_common::KeyInit>::new",
            None,
        );
        cpg.add_edge(mir, llvm, EdgeKind::CrossLayerRef);

        let findings = RuleSet::builtin().match_cpg(&cpg);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].rule_id, "R-CHACHA-002");
        assert_eq!(findings[0].location.file, "src/aead.rs");
    }

    #[test]
    fn one_call_resolved_by_different_rules_at_each_layer_is_one_finding() {
        use cpg_core::AblationMode;

        let mut cpg = Cpg::new(AblationMode::Dual);
        let mir = cpg.add_node(
            IrLayer::Mir,
            NodeKind::TraitMethod,
            "signature::Signer::sign",
            Some(SourceLoc::new("src/main.rs", 92)),
        );
        cpg.set_type_args(mir, vec!["rsa::pkcs1v15::SigningKey".to_string()]);
        let llvm = cpg.add_node(
            IrLayer::Llvm,
            NodeKind::CallSite,
            "<rsa::pkcs1v15::signing_key::SigningKey<D> as signature::signer::Signer<S>>::sign",
            None,
        );
        cpg.add_edge(mir, llvm, EdgeKind::CrossLayerRef);

        let findings = RuleSet::builtin().match_cpg(&cpg);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].rule_id, "R-RSA-002");
        assert_eq!(findings[0].node_id, cpg.node(mir).id);
        assert_eq!(findings[0].location.line, 92);
    }

    #[test]
    fn an_llvm_only_finding_is_kept() {
        let findings = RuleSet::builtin().match_cpg(&dual_layer_cpg());
        assert!(
            findings
                .iter()
                .any(|f| f.contextual_signature == "rsa_only_after_monomorphisation"),
            "a call with no MIR counterpart must survive, or the layer ablation \
             measures nothing"
        );
    }

    #[test]
    fn load_dir_reads_the_shipped_directory() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let loaded = RuleSet::load_dir(&dir).expect("rules/ loads");
        let builtin = RuleSet::builtin();
        let loaded_ids: Vec<&str> = loaded.rules.iter().map(|r| r.id.as_str()).collect();
        let builtin_ids: Vec<&str> = builtin.rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(loaded_ids, builtin_ids);
        assert_eq!(loaded.rules.len(), SHIPPED.len());
    }

    fn call_into_body(
        layer: IrLayer,
        symbol: &str,
        type_args: &[&str],
        body: Option<Option<u8>>,
    ) -> Cpg {
        use cpg_core::{AblationMode, SafetyCtx};

        let mut cpg = Cpg::new(AblationMode::Dual);
        let call = cpg.add_node_full(
            layer,
            NodeKind::CallSite,
            symbol,
            Some(symbol.to_string()),
            Some(SourceLoc::new("src/lib.rs", 7)),
            SafetyCtx::Safe,
        );
        cpg.set_type_args(call, type_args.iter().map(|s| s.to_string()).collect());
        if let Some(depth) = body {
            let f = cpg.add_node_full(
                layer,
                NodeKind::Function,
                symbol,
                Some(symbol.to_string()),
                None,
                SafetyCtx::Safe,
            );
            if let Some(d) = depth {
                cpg.set_dep_depth(f, d);
            }
            cpg.add_edge(call, f, EdgeKind::Call);
        }
        cpg
    }

    fn rule_ids(cpg: &Cpg) -> Vec<String> {
        let mut ids: Vec<String> = RuleSet::builtin()
            .match_cpg(cpg)
            .into_iter()
            .map(|f| f.rule_id)
            .collect();
        ids.sort();
        ids
    }

    #[test]
    fn a_call_into_the_crates_own_body_matches_no_rule() {
        let jwt = "<jsonwebtoken::crypto::rust_crypto::rsa::Rsa256Signer as \
                   signature::signer::Signer<alloc::vec::Vec<u8>>>::try_sign";
        let dsa = "crypto::backend::interface::asymmetric::Asymmetric::dsa_sign";
        assert_eq!(
            rule_ids(&call_into_body(IrLayer::Llvm, jwt, &[], None)),
            ["R-RSA-002"]
        );
        assert_eq!(
            rule_ids(&call_into_body(IrLayer::Mir, dsa, &[], None)),
            ["R-DSA-001"]
        );
        assert!(rule_ids(&call_into_body(IrLayer::Llvm, jwt, &[], Some(None))).is_empty());
        assert!(rule_ids(&call_into_body(IrLayer::Mir, dsa, &[], Some(None))).is_empty());
    }

    #[test]
    fn a_call_into_a_lifted_dependency_body_still_matches() {
        let cpg = call_into_body(IrLayer::Mir, "rsa::RsaPrivateKey::new", &[], Some(Some(1)));
        assert_eq!(rule_ids(&cpg), ["R-RSA-001"]);
    }

    #[test]
    fn an_ecdh_module_path_still_matches() {
        let cpg = call_into_body(IrLayer::Mir, "p256::ecdh::diffie_hellman", &[], None);
        assert_eq!(rule_ids(&cpg), ["R-ECDH-001"]);
    }

    #[test]
    fn a_type_argument_survives_the_gate() {
        let cpg = call_into_body(IrLayer::Mir, "rsa::sign", &["sha2::OidSha256"], Some(None));
        assert_eq!(rule_ids(&cpg), ["R-SHA2-001"]);
    }

    #[test]
    fn the_recorded_x448_ed448_kdf_and_sha1cd_calls_get_their_rules() {
        use cpg_core::AblationMode;

        let cases: &[(&str, &str, AlgorithmClass, QvStatus)] = &[
            (
                "cx448::x448::Secret::new",
                "R-X448-001",
                AlgorithmClass::EcdhX25519,
                QvStatus::Vulnerable,
            ),
            (
                "<cx448::x448::PublicKey as core::convert::From<&cx448::x448::Secret>>::from",
                "R-X448-001",
                AlgorithmClass::EcdhX25519,
                QvStatus::Vulnerable,
            ),
            (
                "<cx448::x448::Secret as core::convert::From<[u8; 56]>>::from",
                "R-X448-001",
                AlgorithmClass::EcdhX25519,
                QvStatus::Vulnerable,
            ),
            (
                "cx448::x448::Secret::as_diffie_hellman",
                "R-X448-001",
                AlgorithmClass::EcdhX25519,
                QvStatus::Vulnerable,
            ),
            (
                "cx448::SigningKey::generate",
                "R-ED448-001",
                AlgorithmClass::EdDsa,
                QvStatus::Vulnerable,
            ),
            (
                "cx448::SigningKey::verifying_key",
                "R-ED448-001",
                AlgorithmClass::EdDsa,
                QvStatus::Vulnerable,
            ),
            (
                "cx448::SigningKey::sign_raw",
                "R-ED448-001",
                AlgorithmClass::EdDsa,
                QvStatus::Vulnerable,
            ),
            (
                "cx448::VerifyingKey::verify_raw",
                "R-ED448-001",
                AlgorithmClass::EdDsa,
                QvStatus::Vulnerable,
            ),
            (
                "argon2::Argon2::<'key>::new",
                "R-ARGON2-001",
                AlgorithmClass::Kdf,
                QvStatus::Resistant,
            ),
            (
                "argon2::Argon2::<'key>::hash_password_into_with_memory",
                "R-ARGON2-001",
                AlgorithmClass::Kdf,
                QvStatus::Resistant,
            ),
            (
                "scrypt::scrypt",
                "R-SCRYPT-001",
                AlgorithmClass::Kdf,
                QvStatus::Resistant,
            ),
            (
                "pbkdf2::pbkdf2_hmac",
                "R-PBKDF2-001",
                AlgorithmClass::Kdf,
                QvStatus::Resistant,
            ),
            (
                "sha1collisiondetection::Builder::build",
                "R-SHA1-001",
                AlgorithmClass::Hash,
                QvStatus::Deprecated,
            ),
            (
                "<sha1collisiondetection::Builder>::build",
                "R-SHA1-001",
                AlgorithmClass::Hash,
                QvStatus::Deprecated,
            ),
            (
                "<sha1collisiondetection::Builder as core::default::Default>::default",
                "R-HASH-999",
                AlgorithmClass::Hash,
                QvStatus::Unknown,
            ),
        ];
        let rules = RuleSet::builtin();
        for (symbol, rule, class, status) in cases {
            let mut cpg = Cpg::new(AblationMode::Dual);
            cpg.add_node(
                IrLayer::Mir,
                NodeKind::CallSite,
                *symbol,
                Some(SourceLoc::new("src/lib.rs", 1)),
            );
            let found: Vec<(String, AlgorithmClass, QvStatus)> = rules
                .match_cpg(&cpg)
                .into_iter()
                .map(|f| (f.rule_id, f.algorithm_class, f.qv_status))
                .collect();
            assert_eq!(found, [(rule.to_string(), *class, *status)], "{symbol}");
        }
    }

    #[test]
    fn the_ml_kem_parameter_set_is_read_from_type_arguments() {
        let set_of = |args: &[&str]| -> Vec<Option<String>> {
            let cpg = call_into_body(IrLayer::Mir, "ml_kem::KemCore::generate", args, None);
            RuleSet::builtin()
                .match_cpg(&cpg)
                .into_iter()
                .map(|f| f.parameter_set)
                .collect()
        };
        assert_eq!(
            set_of(&["ml_kem::kem::Kem", "ml_kem::MlKem768Params"]),
            [Some("768".into())]
        );
        assert_eq!(set_of(&["ml_kem::MlKem1024"]), [Some("1024".into())]);
        assert_eq!(
            set_of(&["ml_kem::ml_kem_768::MlKem768"]),
            [Some("768".into())]
        );
        assert_eq!(set_of(&["ml_kem::MlKem512Params"]), [Some("512".into())]);
        assert_eq!(set_of(&[]), [None]);
        assert_eq!(set_of(&["ml_kem::MlKem768", "ml_kem::MlKem1024"]), [None]);
    }

    #[test]
    fn a_dropped_twin_hands_over_its_parameter_set() {
        use cpg_core::{AblationMode, SafetyCtx};

        let mut cpg = Cpg::new(AblationMode::Dual);
        let at = || Some(SourceLoc::new("src/lib.rs", 7));
        let mir = cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::CallSite,
            "ml_kem::KemCore::generate",
            None,
            at(),
            SafetyCtx::Safe,
        );
        let llvm = cpg.add_node_full(
            IrLayer::Llvm,
            NodeKind::CallSite,
            "<ml_kem::kem::Kem<ml_kem::MlKem768Params> as ml_kem::KemCore>::generate::<rand::rngs::thread::ThreadRng>",
            None,
            at(),
            SafetyCtx::Safe,
        );
        cpg.set_type_args(
            llvm,
            vec!["ml_kem::kem::Kem".into(), "ml_kem::MlKem768Params".into()],
        );
        let findings = RuleSet::builtin().match_cpg(&cpg);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].node_id, cpg.node(mir).id);
        assert_eq!(findings[0].parameter_set.as_deref(), Some("768"));
    }

    #[test]
    fn the_cipher_rules_are_symmetric() {
        let rules = RuleSet::builtin();
        for id in [
            "R-AES-001",
            "R-AES-002",
            "R-AES-003",
            "R-CAMELLIA-001",
            "R-CAMELLIA-002",
            "R-CAMELLIA-003",
            "R-CAST5-001",
            "R-IDEA-001",
            "R-3DES-001",
            "R-BLOWFISH-001",
            "R-TWOFISH-001",
            "R-OPENSSL-003",
            "R-SYM-999",
        ] {
            let rule = rules.rules.iter().find(|r| r.id == id).expect(id);
            assert_eq!(rule.algorithm_class, AlgorithmClass::Symmetric, "{id}");
        }
    }

    #[test]
    fn load_dir_surfaces_a_malformed_rule() {
        let dir = std::env::temp_dir().join("qr-rules-malformed-test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("broken.toml"), "id = \"R-BROKEN\"").unwrap();
        let err = RuleSet::load_dir(&dir).unwrap_err();
        assert!(format!("{err}").contains("broken.toml"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn typed_call(
        cpg: &mut Cpg,
        layer: IrLayer,
        symbol: &str,
        canonical: Option<&str>,
        line: u32,
        type_args: &[&str],
    ) -> u32 {
        use cpg_core::{NodeKind, SafetyCtx, SourceLoc};
        let kind = if symbol.contains("::Try::") {
            NodeKind::TraitMethod
        } else {
            NodeKind::CallSite
        };
        let n = cpg.add_node_full(
            layer,
            kind,
            symbol,
            canonical.map(str::to_string),
            Some(SourceLoc::new("src/ecdsa.rs", line)),
            SafetyCtx::Safe,
        );
        cpg.set_type_args(n, type_args.iter().map(|s| s.to_string()).collect());
        cpg.node(n).id
    }

    fn rule_and_set_rows(findings: &[Finding]) -> Vec<(String, Option<String>)> {
        let mut rows: Vec<_> = findings
            .iter()
            .map(|f| (f.rule_id.clone(), f.parameter_set.clone()))
            .collect();
        rows.sort();
        rows
    }

    #[test]
    fn two_instances_of_one_call_on_one_line_are_two_findings() {
        use cpg_core::AblationMode;
        let mut cpg = Cpg::new(AblationMode::Dual);
        let path = "ecdsa::verifying::VerifyingKey::<C>::from_sec1_bytes";
        for curve in ["p256::NistP256", "p384::NistP384"] {
            let canonical = format!("<ecdsa::verifying::VerifyingKey<{curve}>>::from_sec1_bytes");
            typed_call(&mut cpg, IrLayer::Mir, path, Some(&canonical), 60, &[curve]);
            typed_call(
                &mut cpg,
                IrLayer::Mir,
                "std::ops::Try::branch",
                None,
                60,
                &[
                    "std::result::Result",
                    "ecdsa::verifying::VerifyingKey",
                    curve,
                    "errors::ErrorKind",
                ],
            );
        }
        let findings = RuleSet::builtin().match_cpg(&cpg);
        assert_eq!(
            rule_and_set_rows(&findings),
            [
                ("R-ECDSA-001".to_string(), Some("P-256".to_string())),
                ("R-ECDSA-001".to_string(), Some("P-384".to_string())),
            ],
            "{findings:#?}"
        );
    }

    #[test]
    fn what_differs_only_in_wrappers_is_one_instance() {
        use cpg_core::AblationMode;
        let mut cpg = Cpg::new(AblationMode::Dual);
        typed_call(
            &mut cpg,
            IrLayer::Mir,
            "eax::online::Eax::<Cipher, Op, M>::with_key_and_nonce",
            None,
            260,
            &[
                "aes::autodetect::Aes128",
                "eax::online::Encrypt",
                "typenum::uint::UInt",
                "typenum::bit::B1",
            ],
        );
        typed_call(
            &mut cpg,
            IrLayer::Llvm,
            "<eax::online::Eax<aes::autodetect::Aes128, eax::online::Encrypt>>::with_key_and_nonce",
            None,
            260,
            &[
                "eax::online::Eax",
                "aes::autodetect::Aes128",
                "eax::online::Encrypt",
            ],
        );
        for wrapper in ["cfb_mode::Encryptor", "cfb_mode::Decryptor"] {
            typed_call(
                &mut cpg,
                IrLayer::Mir,
                "aes::Aes128::new",
                None,
                525,
                &[wrapper, "aes::Aes128"],
            );
        }
        let findings = RuleSet::builtin().match_cpg(&cpg);
        let at = |line: u32| findings.iter().filter(|f| f.location.line == line).count();
        assert_eq!((at(260), at(525)), (1, 1), "{findings:#?}");
    }

    #[test]
    fn a_twin_of_another_instance_is_not_a_twin() {
        use cpg_core::AblationMode;
        let mut cpg = Cpg::new(AblationMode::Dual);
        typed_call(
            &mut cpg,
            IrLayer::Mir,
            "ecdsa::verifying::VerifyingKey::<C>::from_sec1_bytes",
            None,
            60,
            &["p256::NistP256"],
        );
        typed_call(
            &mut cpg,
            IrLayer::Llvm,
            "<ecdsa::verifying::VerifyingKey<p384::NistP384>>::from_sec1_bytes",
            None,
            60,
            &["ecdsa::verifying::VerifyingKey", "p384::NistP384"],
        );
        let findings = RuleSet::builtin().match_cpg(&cpg);
        assert_eq!(
            rule_and_set_rows(&findings),
            [
                ("R-ECDSA-001".to_string(), Some("P-256".to_string())),
                ("R-ECDSA-001".to_string(), Some("P-384".to_string())),
            ],
            "{findings:#?}"
        );
    }

    #[test]
    fn a_generic_call_twinned_by_two_instances_takes_no_set() {
        use cpg_core::AblationMode;
        let mut cpg = Cpg::new(AblationMode::Dual);
        typed_call(
            &mut cpg,
            IrLayer::Mir,
            "ecdsa::verifying::VerifyingKey::<C>::from_sec1_bytes",
            None,
            60,
            &[],
        );
        for curve in ["p256::NistP256", "p384::NistP384"] {
            typed_call(
                &mut cpg,
                IrLayer::Llvm,
                &format!("<ecdsa::verifying::VerifyingKey<{curve}>>::from_sec1_bytes"),
                None,
                60,
                &["ecdsa::verifying::VerifyingKey", curve],
            );
        }
        let findings = RuleSet::builtin().match_cpg(&cpg);
        assert_eq!(
            rule_and_set_rows(&findings),
            [("R-ECDSA-001".to_string(), None)],
            "{findings:#?}"
        );
    }

    #[test]
    fn a_fallback_is_shadowed_only_by_its_own_instance() {
        use cpg_core::AblationMode;
        let mut cpg = Cpg::new(AblationMode::Dual);
        typed_call(
            &mut cpg,
            IrLayer::Mir,
            "ecdsa::verifying::VerifyingKey::<C>::from_sec1_bytes",
            None,
            70,
            &["p256::NistP256"],
        );
        typed_call(
            &mut cpg,
            IrLayer::Llvm,
            "<ecdsa::der::Signature<p384::NistP384>>::from_bytes",
            None,
            70,
            &["p384::NistP384"],
        );
        let findings = RuleSet::builtin().match_cpg(&cpg);
        let rules: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"R-ECDSA-999"), "{findings:#?}");
    }

    #[test]
    fn the_inherent_owner_veto_drops_an_anchor_match_of_a_typed_fallback() {
        use cpg_core::{AblationMode, NodeKind, SafetyCtx, SourceLoc};
        let mut cpg = Cpg::new(AblationMode::Dual);
        cpg.add_node_full(
            IrLayer::Mir,
            NodeKind::CallSite,
            "sha2::digest::generic_array::GenericArray::<T, N>::clone_from_slice",
            Some("<generic_array::GenericArray<u8, typenum::U32>>::clone_from_slice".into()),
            Some(SourceLoc::new("src/lib.rs", 3)),
            SafetyCtx::Safe,
        );
        let findings = RuleSet::builtin().match_cpg(&cpg);
        assert!(findings.is_empty(), "{findings:#?}");
    }
}
