pub mod headline;
pub mod manifest;
pub mod migration;
pub mod profile;
pub mod xml;

use std::collections::BTreeMap;

use cpg_core::{Finding, QvStatus};
use qr_rules::{CryptoSpec, RuleSet};
use serde_json::{json, Map, Value};

pub use headline::{algorithm_name, headline, Headline};
pub use manifest::{declared_crypto, subject_of, unreached, DeclaredDependency, Subject};
pub use profile::{
    builtin_profiles, load_profile, parse_profile, Judged, Profile, Verdict, NOT_A_CERTIFICATE,
};
pub use xml::{emit_cbom_xml, emit_cbom_xml_report, emit_cbom_xml_with_manifest};

pub fn emit_cbom(findings: &[Finding], rules: &RuleSet) -> Value {
    emit_cbom_with_manifest(findings, rules, &[])
}

pub fn emit_cbom_with_manifest(
    findings: &[Finding],
    rules: &RuleSet,
    declared: &[manifest::DeclaredDependency],
) -> Value {
    emit_cbom_report(
        findings,
        rules,
        CbomExtras {
            declared,
            ..CbomExtras::default()
        },
    )
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CbomExtras<'a> {
    pub declared: &'a [manifest::DeclaredDependency],
    pub judged: Option<&'a Judged>,
    pub subject: Option<&'a Subject>,
}

pub fn emit_cbom_report(findings: &[Finding], rules: &RuleSet, extras: CbomExtras<'_>) -> Value {
    let declared = extras.declared;
    let refs = bom_refs(findings);
    let mut components: Vec<Value> = findings
        .iter()
        .enumerate()
        .map(|(i, finding)| {
            let mut component = component_for(finding, rules, &refs[i]);
            if let Some(verdict) = verdict_of(extras.judged, i) {
                if let Some(props) = component["properties"].as_array_mut() {
                    props.push(json!({
                        "name": "quantumrust:profile-verdict",
                        "value": verdict.label(),
                    }));
                }
            }
            component
        })
        .collect();
    components.extend(declared.iter().map(declared_component));

    let mut bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "quantumrust",
                    "version": env!("CARGO_PKG_VERSION"),
                }]
            }
        },
        "components": components,
    });
    if let Some(subject) = extras.subject {
        let mut component = json!({
            "type": if subject.library { "library" } else { "application" },
            "bom-ref": subject.purl(),
            "name": subject.name,
            "purl": subject.purl(),
        });
        if let Some(version) = &subject.version {
            component["version"] = json!(version);
        }
        bom["metadata"]["component"] = component;
    }
    if let Some(judged) = extras.judged {
        bom["metadata"]["properties"] = profile_metadata(judged)
            .into_iter()
            .map(|(name, value)| json!({ "name": name, "value": value }))
            .collect();
    }
    let edges: Vec<Value> = dependencies(findings)
        .into_iter()
        .map(|(i, js)| {
            json!({
                "ref": refs[i],
                "dependsOn": js.iter().map(|&j| refs[j].clone()).collect::<Vec<_>>(),
            })
        })
        .collect();
    if !edges.is_empty() {
        bom["dependencies"] = Value::Array(edges);
    }
    bom
}

pub(crate) fn verdict_of(judged: Option<&Judged>, i: usize) -> Option<Verdict> {
    judged.and_then(|j| j.verdicts.get(i).copied())
}

pub(crate) fn profile_metadata(judged: &Judged) -> Vec<(&'static str, String)> {
    vec![
        ("quantumrust:profile", judged.profile_id.clone()),
        ("quantumrust:profile-name", judged.profile_name.clone()),
        ("quantumrust:profile-tally", judged.tally()),
        ("quantumrust:profile-note", NOT_A_CERTIFICATE.to_string()),
    ]
}

pub fn dependencies(findings: &[Finding]) -> Vec<(usize, Vec<usize>)> {
    let mut by_node: std::collections::HashMap<u32, Vec<usize>> = std::collections::HashMap::new();
    for (i, f) in findings.iter().enumerate() {
        by_node.entry(f.node_id).or_default().push(i);
    }
    let mut uses: std::collections::BTreeMap<usize, std::collections::BTreeSet<usize>> =
        std::collections::BTreeMap::new();
    for (j, producer) in findings.iter().enumerate() {
        for node in &producer.taint_nodes {
            for &i in by_node.get(node).into_iter().flatten() {
                if findings[i].node_id != producer.node_id {
                    uses.entry(i).or_default().insert(j);
                }
            }
        }
    }
    uses.into_iter()
        .map(|(i, js)| (i, js.into_iter().collect()))
        .collect()
}

fn declared_component(dep: &manifest::DeclaredDependency) -> Value {
    let mut properties = vec![
        json!({"name": "quantumrust:evidence", "value": "manifest"}),
        json!({
            "name": "quantumrust:note",
            "value": "declared dependency; no call site found in the analysed crate \
                      (analysis is crate-local)"
        }),
    ];
    if let Some(version) = &dep.version {
        properties.push(json!({"name": "quantumrust:version-req", "value": version}));
    }
    json!({
        "type": "cryptographic-asset",
        "name": dep.name,
        "properties": properties,
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": { "type": "unknown" },
        },
    })
}

fn component_for(finding: &Finding, rules: &RuleSet, bom_ref: &str) -> Value {
    let spec = crypto_spec(finding, rules);

    let mut algorithm = Map::new();
    algorithm.insert("primitive".into(), json!(spec.primitive));
    if !spec.crypto_functions.is_empty() {
        algorithm.insert("cryptoFunctions".into(), json!(spec.crypto_functions));
    }
    let parameter_set = parameter_set(finding, &spec);
    for (key, value) in [
        ("algorithmFamily", &spec.algorithm_family),
        ("mode", &spec.mode),
        ("parameterSetIdentifier", &parameter_set),
    ] {
        if let Some(value) = value {
            algorithm.insert(key.into(), json!(value));
        }
    }
    if let Some(level) = quantum_security_level(finding, rules) {
        algorithm.insert("nistQuantumSecurityLevel".into(), json!(level));
    }

    let mut crypto_properties = Map::new();
    crypto_properties.insert("assetType".into(), json!(spec.asset_type));
    crypto_properties.insert("algorithmProperties".into(), Value::Object(algorithm));
    if let Some(oid) = &spec.oid {
        crypto_properties.insert("oid".into(), json!(oid));
    }

    json!({
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "name": finding.contextual_signature,
        "cryptoProperties": Value::Object(crypto_properties),
        "evidence": {
            "occurrences": [{
                "location": finding.location.file,
                "line": finding.location.line,
                "symbol": finding.contextual_signature,
                "additionalContext": format!("matched by rule {}", finding.rule_id),
            }]
        },
        "properties": properties_for(finding),
    })
}

pub fn via_text(via: &[cpg_core::ViaFrame]) -> String {
    via.iter()
        .map(|v| match &v.location {
            Some(l) => format!("{} ({}:{})", v.symbol, l.file, l.line),
            None => v.symbol.clone(),
        })
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn properties_for(finding: &Finding) -> Vec<Value> {
    let mut properties = vec![
        json!({ "name": "quantumrust:rule", "value": finding.rule_id }),
        json!({
            "name": "quantumrust:quantum-status",
            "value": qv_label(finding.qv_status),
        }),
    ];
    if !finding.taint_chain.is_empty() {
        let chain: Vec<String> = finding
            .taint_chain
            .iter()
            .map(|loc| format!("{}:{}", loc.file, loc.line))
            .collect();
        properties.push(json!({
            "name": "quantumrust:taint-chain",
            "value": chain.join(" -> "),
        }));
    }
    if !finding.via.is_empty() {
        properties.push(json!({ "name": "quantumrust:via", "value": via_text(&finding.via) }));
    }
    for part in &finding.with {
        properties.push(json!({ "name": "quantumrust:part", "value": part_text(part) }));
    }
    properties
}

pub(crate) fn parameter_set(finding: &Finding, spec: &CryptoSpec) -> Option<String> {
    finding
        .key_size
        .map(|bits| bits.to_string())
        .or_else(|| finding.parameter_set.clone())
        .or_else(|| spec.parameter_set_identifier.clone())
        .or_else(|| {
            spec.algorithm_family
                .is_none()
                .then(|| finding.with.iter().find_map(|p| p.parameter_set.clone()))
                .flatten()
        })
}

pub fn quantum_security_level(finding: &Finding, rules: &RuleSet) -> Option<u8> {
    std::iter::once(level_of(
        &finding.rule_id,
        finding.parameter_set.as_deref(),
        rules,
    ))
    .chain(
        finding
            .with
            .iter()
            .map(|part| level_of(&part.rule_id, part.parameter_set.as_deref(), rules)),
    )
    .flatten()
    .min()
}

fn level_of(rule_id: &str, parameter_set: Option<&str>, rules: &RuleSet) -> Option<u8> {
    let rule = rules.rules.iter().find(|rule| rule.id == rule_id)?;
    match parameter_set.and_then(|id| rule.parameter_set(id)) {
        Some(set) => set.nist_quantum_security_level,
        None => rule.crypto.nist_quantum_security_level,
    }
}

pub fn parts_text(parts: &[cpg_core::Part], rules: &RuleSet) -> String {
    parts
        .iter()
        .map(|p| {
            let name = headline::rule_name(&p.rule_id, p.parameter_set.as_deref(), rules)
                .unwrap_or_else(|| display_symbol(&p.signature));
            format!("{name} [{}, {}]", p.rule_id, qv_label(p.qv_status))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub(crate) fn part_text(part: &cpg_core::Part) -> String {
    format!(
        "{} {} ({})",
        part.rule_id,
        part.signature,
        qv_label(part.qv_status)
    )
}

pub(crate) fn crypto_spec(finding: &Finding, rules: &RuleSet) -> CryptoSpec {
    rules
        .rules
        .iter()
        .find(|rule| rule.id == finding.rule_id)
        .map(|rule| rule.crypto.clone())
        .unwrap_or_default()
}

pub(crate) fn bom_refs(findings: &[Finding]) -> Vec<String> {
    let base: Vec<String> = findings.iter().map(bom_ref).collect();
    let mut count: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for r in &base {
        *count.entry(r.as_str()).or_default() += 1;
    }
    let mut taken: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    findings
        .iter()
        .zip(&base)
        .map(|(f, r)| {
            let mut out = if count[r.as_str()] > 1 {
                let parts: Vec<&str> = f.with.iter().map(|p| p.rule_id.as_str()).collect();
                let key = format!(
                    "{}|{}|{}|{}|{}|{}",
                    f.rule_id,
                    f.location.file,
                    f.location.line,
                    f.contextual_signature,
                    f.parameter_set.as_deref().unwrap_or(""),
                    parts.join(","),
                );
                format!("crypto-{:016x}", fnv1a(&key))
            } else {
                r.clone()
            };
            let seen = taken.entry(out.clone()).or_default();
            *seen += 1;
            if *seen > 1 {
                out = format!("{out}-{seen}");
            }
            out
        })
        .collect()
}

pub(crate) fn bom_ref(finding: &Finding) -> String {
    let key = format!(
        "{}|{}|{}|{}",
        finding.rule_id, finding.location.file, finding.location.line, finding.contextual_signature
    );
    format!("crypto-{:016x}", fnv1a(&key))
}

fn fnv1a(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

const GROUP_HEADER: &str = "<tr><th></th><th>Tier</th><th>Score</th><th>f(b) &times; Crit</th>\
<th>Blast</th><th>Scope</th><th>Rule</th><th>Call site</th><th>Status</th><th>Key</th>\
<th>Location</th></tr>";

const COLUMNS: usize = 11;

const CHAIN_OPEN_UP_TO: usize = 10;

pub struct ScoredFinding<'a> {
    pub finding: &'a Finding,
    pub tier: u8,
    pub risk: f64,
    pub severity: f64,
    pub blast_factor: f64,
    pub criticality: f64,
    pub blast_radius: u64,
    pub conservative: bool,
    pub resolves_to: Option<String>,
    pub call_symbol: Option<String>,
    pub refactor_scope: Option<usize>,
    pub chain_absence: Option<&'static str>,
    pub algorithm: String,
    pub advice: migration::Advice,
    pub verdict: Option<Verdict>,
    pub parts: String,
}

impl ScoredFinding<'_> {
    fn priority_cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .severity
            .total_cmp(&self.severity)
            .then_with(|| other.risk.total_cmp(&self.risk))
    }
}

pub fn ranked<'s, 'a>(scored: &'s [ScoredFinding<'a>]) -> Vec<&'s ScoredFinding<'a>> {
    let mut rows: Vec<&ScoredFinding<'a>> = scored.iter().collect();
    rows.sort_by(|a, b| {
        a.priority_cmp(b)
            .then_with(|| a.finding.location.file.cmp(&b.finding.location.file))
            .then_with(|| a.finding.location.line.cmp(&b.finding.location.line))
    });
    rows
}

#[cfg(test)]
impl<'a> ScoredFinding<'a> {
    pub(crate) fn for_test(finding: &'a Finding) -> Self {
        Self {
            finding,
            tier: 1,
            risk: 4.5,
            severity: 2.0,
            blast_factor: 4.5,
            criticality: 1.0,
            blast_radius: 5,
            conservative: false,
            resolves_to: None,
            call_symbol: None,
            refactor_scope: None,
            chain_absence: None,
            algorithm: "RSA".into(),
            advice: migration::Advice::Keep("test"),
            verdict: None,
            parts: String::new(),
        }
    }
}

pub fn display_symbol(symbol: &str) -> String {
    if symbol.chars().count() <= 100 {
        symbol.to_string()
    } else {
        abbreviate(symbol)
    }
}

fn abbreviate(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut depth = 0usize;
    let mut chars = path.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '<' => {
                let generic = i > 0
                    && path[..i]
                        .chars()
                        .next_back()
                        .is_some_and(|p| p.is_alphanumeric() || p == '_');
                depth += 1;
                if generic && depth >= 1 {
                    out.push_str("<…>");
                    let mut inner = 1usize;
                    for (_, d) in chars.by_ref() {
                        match d {
                            '<' => inner += 1,
                            '>' => {
                                inner -= 1;
                                if inner == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    depth -= 1;
                } else {
                    out.push(c);
                }
            }
            '>' => {
                depth = depth.saturating_sub(1);
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

pub fn render_dashboard(scored: &[ScoredFinding<'_>], analysed: &str) -> String {
    render_dashboard_with(scored, analysed, None)
}

pub fn render_dashboard_with(
    scored: &[ScoredFinding<'_>],
    analysed: &str,
    judged: Option<&Judged>,
) -> String {
    let profile_view = judged
        .map(|j| {
            format!(
                "<div class=policy><b>Against profile: {name} ({id})</b> &mdash; {tally}. \
                 <span class=pnote>{note}.</span></div>",
                name = crate::xml::escape(&j.profile_name),
                id = crate::xml::escape(&j.profile_id),
                tally = j.tally(),
                note = NOT_A_CERTIFICATE,
            )
        })
        .unwrap_or_default();
    let rows = ranked(scored);
    let panel = headline::render_html(&headline::headline(scored));
    let migration_view =
        migration::render_html(&migration::plan(scored), &migration::unplanned(scored));

    let count = |s: QvStatus| scored.iter().filter(|r| r.finding.qv_status == s).count();
    let conservative = scored.iter().filter(|r| r.conservative).count();
    let resolved_count = scored.iter().filter(|r| r.resolves_to.is_some()).count();
    let render_rows = |rows: &[&ScoredFinding<'_>], numbered: bool| -> String {
        rows.iter()
            .enumerate()
            .map(|(i, r)| {
                let f = r.finding;
                let esc = crate::xml::escape;
                let chain: Vec<String> = f
                    .taint_chain
                    .iter()
                    .map(|loc| format!("{}:{}", esc(&loc.file), loc.line))
                    .collect();
                let flag = if r.conservative {
                    " <span class=flag title=\"the algorithm was not resolved; the \
                 severity is its class ceiling\">upper bound</span>"
                } else {
                    ""
                };
                let key = f
                    .key_size
                    .map(|k| format!("{k}-bit"))
                    .unwrap_or_else(|| "&mdash;".into());
                let resolved = match &r.resolves_to {
                    Some(target) => {
                        let short = esc(&abbreviate(target));
                        format!(
                            "<div class=res title=\"the trait call resolves to this impl\">\
                         &rarr; {short}</div>"
                        )
                    }
                    None if r
                        .call_symbol
                        .as_deref()
                        .is_some_and(|s| s.starts_with("<dyn ")) =>
                    {
                        "<div class=dyn title=\"dynamic dispatch has no statically \
                     resolvable target; the LLVM layer's vtable node covers it\">\
                     &rarr; dyn, unresolved</div>"
                            .to_string()
                    }
                    None => String::new(),
                };
                let parts = if f.with.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<div class=parts title=\"read off the call's arguments\">with {}</div>",
                        esc(&r.parts)
                    )
                };
                let via = if f.via.is_empty() {
                    String::new()
                } else {
                    let names: Vec<String> =
                        f.via.iter().map(|v| esc(&abbreviate(&v.symbol))).collect();
                    format!(
                        "<div class=via title=\"reached through a dependency\">via {}</div>",
                        names.join(" &rarr; ")
                    )
                };
                format!(
                    "<tr class=\"{status}\"><td class=n>{rank}</td>\
                 <td class=\"tier t{tier}\">T{tier}</td>\
                 <td class=risk>{risk:.2}{flag}</td>\
                 <td class=calc>{bf:.2} &times; {crit:.1}</td>\
                 <td class=n>{blast}</td><td class=n>{scope}</td>\
                 <td class=rule>{rule}</td><td class=sig{title}>{sig}{resolved}{parts}{via}</td>\
                 <td>{label}{verdict}</td><td>{key}</td>\
                 <td class=loc>{file}:{line}</td></tr>{chain}",
                    status = qv_label(f.qv_status),
                    rank = if numbered {
                        (i + 1).to_string()
                    } else {
                        String::new()
                    },
                    tier = r.tier,
                    risk = r.risk,
                    bf = r.blast_factor,
                    crit = r.criticality,
                    blast = r.blast_radius,
                    scope = r
                        .refactor_scope
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "&mdash;".into()),
                    rule = esc(&f.rule_id),
                    sig = esc(&display_symbol(&f.contextual_signature)),
                    title = if display_symbol(&f.contextual_signature) == f.contextual_signature {
                        String::new()
                    } else {
                        format!(" title=\"{}\"", esc(&f.contextual_signature))
                    },
                    resolved = resolved,
                    parts = parts,
                    via = via,
                    label = qv_label(f.qv_status),
                    verdict = r
                        .verdict
                        .map(|v| format!(" <span class=\"verdict {0}\">{0}</span>", v.label()))
                        .unwrap_or_default(),
                    file = esc(&f.location.file),
                    line = f.location.line,
                    chain = if chain.is_empty() {
                        match r.chain_absence {
                            Some(why) => format!(
                                "<tr class=chainrow><td colspan={COLUMNS}>\
                             <span class=nochain>no taint chain &mdash; {why}</span>\
                             </td></tr>"
                            ),
                            None => String::new(),
                        }
                    } else {
                        format!(
                            "<tr class=chainrow><td colspan={COLUMNS}><details{open}>\
                         <summary>taint chain &middot; {hops} hop{plural}</summary>\
                         <div class=chain>{path}</div></details></td></tr>",
                            open = if chain.len() <= CHAIN_OPEN_UP_TO {
                                " open"
                            } else {
                                ""
                            },
                            hops = chain.len(),
                            plural = if chain.len() == 1 { "" } else { "s" },
                            path = chain.join(" &rarr; "),
                        )
                    },
                )
            })
            .collect()
    };

    let by_risk = render_rows(&rows, true);

    let mut groups: BTreeMap<&str, Vec<&ScoredFinding<'_>>> = BTreeMap::new();
    for r in &rows {
        groups
            .entry(r.finding.rule_id.as_str())
            .or_default()
            .push(r);
    }
    let mut ordered: Vec<(&str, Vec<&ScoredFinding<'_>>)> = groups.into_iter().collect();
    ordered.sort_by(|a, b| a.1[0].priority_cmp(b.1[0]).then_with(|| a.0.cmp(b.0)));
    let by_rule: String = ordered
        .iter()
        .map(|(rule, findings)| {
            format!(
                "<details class=rulegroup><summary>\
                 <span class=gr>{rule}</span>\
                 <span class=gc>{n} finding{plural}</span>\
                 <span class=gs>{status}</span>\
                 <span class=gm>Tier {tier}, top score {worst:.2}</span></summary>\
                 <table>{GROUP_HEADER}{body}</table></details>",
                rule = crate::xml::escape(rule),
                n = findings.len(),
                plural = if findings.len() == 1 { "" } else { "s" },
                status = qv_label(findings[0].finding.qv_status),
                tier = findings[0].tier,
                worst = findings[0].risk,
                body = render_rows(findings, false),
            )
        })
        .collect();

    format!(
        "<!doctype html><meta charset=utf-8><title>QuantumRust &mdash; {analysed}</title>\
<style>\
body{{font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:2rem;color:#1a1a1a}}\
h1{{font-size:1.4rem;margin:0 0 .25rem}}\
.target{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.95rem;\
color:#1a1a1a;background:#eef1f4;display:inline-block;padding:.15rem .5rem;\
border-radius:4px;margin:0 0 .5rem}}\
.sub{{color:#666;margin:0 0 1.25rem}}\
.tally{{display:flex;gap:1.5rem;margin:0 0 1.25rem;padding:.75rem 1rem;background:#f6f7f9;border-radius:6px}}\
.tally div{{font-size:.85rem;color:#555}}\
.tally b{{display:block;font-size:1.3rem;color:#1a1a1a}}\
table{{border-collapse:collapse;width:100%;font-size:.82rem}}\
th{{text-align:left;padding:.4rem .55rem;border-bottom:2px solid #ccc;white-space:nowrap}}\
td{{padding:.35rem .55rem;border-bottom:1px solid #eee;vertical-align:top}}\
.n,.risk{{text-align:right;white-space:nowrap}}\
.risk{{font-weight:600}}\
.calc,.loc{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#666;white-space:nowrap}}\
.rule{{white-space:nowrap;font-variant-numeric:tabular-nums}}\
.sig{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere;max-width:38rem}}\
.res{{color:#0a6b3d;font-size:.92em;margin-top:.15rem}}\
.parts{{color:#444;font-size:.92em;margin-top:.15rem}}\
.dyn{{color:#8a6d00;font-size:.92em;margin-top:.15rem}}\
tr.quantum-vulnerable td.risk{{color:#a4262c}}\
tr.quantum-resistant{{color:#777}}\
.flag{{font-weight:400;font-size:.72rem;color:#8a6d00;background:#fff4cc;padding:.05rem .3rem;border-radius:3px;margin-left:.3rem}}\
.chainrow td{{border-bottom:1px solid #eee;padding:0 .55rem .45rem}}\
.chainrow details{{margin:0}}\
.chainrow summary{{cursor:pointer;color:#666;font-size:.76rem;list-style:none;display:inline-block;\
padding:.1rem .45rem;background:#f2f3f5;border-radius:3px;user-select:none}}\
.chainrow summary::-webkit-details-marker{{display:none}}\
.chainrow summary::before{{content:'\\25B8 ';color:#999}}\
.chainrow details[open] summary::before{{content:'\\25BE '}}\
.chainrow summary:hover{{background:#e6e8eb}}\
.nochain{{color:#8a8f98;font-size:.76rem;font-style:italic}}\
.chain{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.76rem;color:#555;\
margin:.4rem 0 .2rem;padding:.5rem .65rem;background:#fafbfc;border-left:2px solid #d0d3d8;\
border-radius:0 3px 3px 0;overflow-wrap:anywhere;line-height:1.7}}\
tr:not(.chainrow) td{{border-bottom:none}}\
tr.chainrow+tr td{{border-top:1px solid #eee}}\
input[name=view]{{position:absolute;opacity:0;pointer-events:none}}\
.tabs{{display:flex;gap:.25rem;margin:0 0 .75rem;border-bottom:1px solid #dcdfe3}}\
.tabs label{{cursor:pointer;padding:.4rem .9rem;font-size:.85rem;color:#666;\
border:1px solid transparent;border-bottom:none;border-radius:4px 4px 0 0;margin-bottom:-1px}}\
.tabs label:hover{{color:#1a1a1a;background:#f6f7f9}}\
#v-risk:checked~.tabs label[for=v-risk],#v-rule:checked~.tabs label[for=v-rule],\
#v-mig:checked~.tabs label[for=v-mig]\
{{color:#1a1a1a;font-weight:600;background:#fff;border-color:#dcdfe3;border-bottom:1px solid #fff}}\
.pane{{display:none}}\
#v-risk:checked~#p-risk,#v-rule:checked~#p-rule,#v-mig:checked~#p-mig{{display:block}}\
.std{{color:#666;font-size:.85em;margin-left:.3rem}}\
.rulegroup{{border:1px solid #e6e8eb;border-radius:5px;margin-bottom:.4rem;background:#fff}}\
.rulegroup summary{{cursor:pointer;padding:.55rem .8rem;list-style:none;user-select:none;\
display:flex;align-items:baseline;flex-wrap:wrap}}\
.rulegroup summary::-webkit-details-marker{{display:none}}\
.rulegroup summary::before{{content:'\\25B8';color:#999;margin-right:.55rem;font-size:.8rem}}\
.rulegroup[open] summary::before{{content:'\\25BE'}}\
.rulegroup summary:hover{{background:#f6f7f9}}\
.rulegroup[open] summary{{border-bottom:1px solid #e6e8eb;background:#fafbfc}}\
.rulegroup table{{margin:0}}\
.rulegroup td,.rulegroup th{{padding-left:.8rem}}\
.gr{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:600;font-size:.9rem}}\
.gc,.gs,.gm{{color:#666;font-size:.78rem;margin-left:.9rem}}\
.defs{{margin:0 0 1rem;padding:.7rem .9rem;background:#fbfcfd;border:1px solid #e6e8eb;\
border-radius:5px;font-size:.8rem;color:#444;line-height:1.6}}\
.defs p{{margin:0}}\
.defs p+p{{margin-top:.45rem}}\
.headline{{display:flex;flex-wrap:wrap;gap:.75rem;margin:0 0 .5rem}}\
.card{{flex:1 1 18rem;padding:.75rem 1rem;border-radius:6px;background:#f6f7f9;border-left:4px solid #bbb}}\
.card.t1{{border-left-color:#a4262c}}.card.t2{{border-left-color:#c77c02}}.card.t3{{border-left-color:#5b8a5b}}\
.card .k{{font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;color:#666}}\
.card .v{{font-size:1.35rem;font-weight:600;margin:.1rem 0}}\
.card .v small{{font-size:.85rem;font-weight:400;color:#666}}\
.card .d{{font-size:.8rem;color:#444}}\
.card .m{{font-size:.78rem;color:#666;margin-top:.3rem}}\
.hcaveat{{font-size:.78rem;color:#8a6d00;margin:0 0 .5rem}}\
.chips{{display:flex;flex-wrap:wrap;gap:.35rem;align-items:baseline;margin:0 0 1.25rem}}\
.ck{{font-size:.75rem;color:#666;margin-right:.25rem}}\
.chip{{font-size:.75rem;padding:.1rem .45rem;border-radius:10px;background:#eef1f4;border:1px solid #dcdfe3}}\
.chip.t1{{background:#fbe9ea;border-color:#efc4c6}}.chip.t2{{background:#fdf1dc;border-color:#f0d6a8}}\
.tier{{font-weight:600;white-space:nowrap}}.tier.t1{{color:#a4262c}}.tier.t2{{color:#c77c02}}.tier.t3{{color:#777}}\
.policy{{margin:0 0 1rem;padding:.6rem .9rem;border-left:4px solid #1a5fb4;background:#f2f6fc;\
border-radius:0 5px 5px 0;font-size:.85rem}}\
.pnote{{color:#666}}\
.verdict{{font-size:.72rem;padding:.05rem .35rem;border-radius:3px;margin-left:.3rem;white-space:nowrap}}\
.verdict.fail{{color:#a4262c;background:#fbe9ea}}.verdict.pass{{color:#0a6b3d;background:#e6f4ea}}\
.verdict.review{{color:#8a6d00;background:#fff4cc}}\
.note{{margin-top:1.5rem;padding:.85rem 1rem;background:#f6f7f9;border-left:3px solid #bbb;font-size:.82rem;color:#444}}\
.note p{{margin:.4rem 0}}\
</style>\
<h1>QuantumRust &mdash; crypto inventory and risk</h1>\
<p class=target>{analysed}</p>\
<p class=sub>Ranked tier first &mdash; by NIST IR 8547 tier &mdash; then within a tier by \
<code>Score = f(BlastRadius) &times; Criticality</code>, where \
<code>f(b) = 1 + log<sub>2</sub>(b + 1)</code>. No reach lifts a finding above a more severe tier.</p>\
{panel}\
{profile_view}\
<div class=tally>\
<div>findings<b>{total}</b></div>\
<div>quantum-vulnerable<b>{vuln}</b></div>\
<div>deprecated<b>{dep}</b></div>\
<div>quantum-resistant<b>{res}</b></div>\
<div>unresolved algorithm<b>{unknown}</b></div>\
<div>scored as upper bound<b>{conservative}</b></div>\
<div>trait calls resolved<b>{resolved_count}</b></div>\
</div>\
<div class=defs>\
<p><b>Blast</b> &mdash; how far the finding <i>reaches</i>: nodes forward-reachable over call
and data-flow edges. Drives the ranking, and call-graph imprecision inflates it.</p>\
<p><b>Scope</b> &mdash; how much a migration would <i>touch</i>: the taint-reachable subset
only. Kept separate so imprecision inflates the ranking without inflating the cost estimate.
Scope is normally the smaller of the two, and a wide gap is informative rather than a
contradiction.</p>\
</div>\
<input type=radio name=view id=v-risk checked><input type=radio name=view id=v-rule>\
<input type=radio name=view id=v-mig>\
<div class=tabs><label for=v-risk>By risk</label><label for=v-rule>By rule</label>\
<label for=v-mig>Migration</label></div>\
<div class=pane id=p-risk><table>\
<tr><th>#</th><th>Tier</th><th>Score</th><th>f(b) &times; Crit</th><th>Blast</th>\
<th>Scope</th><th>Rule</th><th>Call site</th><th>Status</th><th>Key</th><th>Location</th></tr>\
{by_risk}</table></div>\
<div class=pane id=p-rule>{by_rule}</div>\
<div class=pane id=p-mig>{migration_view}</div>\
<div class=note>\
<p><b>A <code>0.00</code> does not mean safe.</b> A quantum-resistant primitive (Tier 3) \
scores a true zero because it needs no <i>quantum</i> migration &mdash; it is still \
cryptography, and it is still in the inventory above.</p>\
<p><b>Scores compare only within a tier.</b> A Tier 2 row can score higher than a Tier 1 \
row and still rank below it: the tier is the standard's deadline, and reach decides only \
which call in a tier to migrate first.</p>\
<p><b>A <span class=res style=\"display:inline\">&rarr; arrow</span> under a call site is
trait resolution.</b> The caller wrote a trait path; the compiler resolves it to a concrete
impl, and that is what the algorithm attribution uses. A <span class=dyn style=\"display:inline\">&rarr;
dyn, unresolved</span> cannot be resolved statically &mdash; dynamic dispatch has no single
target, which is the case the LLVM layer's vtable node exists for.</p>\
<p><b>Rows marked <span class=flag>upper bound</span> were not resolved.</b> The tool \
could not name the algorithm, so its tier is the ceiling of what its class could be. \
The rank is a bound, not a measurement, and the panel never names one as most severe.</p>\
<p><b>Taint chains are collapsed.</b> Click one to see the data-flow path from the
key's construction to the operation that consumes it &mdash; the provenance behind the
finding, and the thing that makes it checkable without re-running the tool.</p>\
<p><b>Blast and Scope are different questions and use different edges.</b>
<i>Blast</i> is call-graph reach and drives the ranking; <i>Scope</i> is the
taint-reachable subset and estimates what a migration must touch. Call-graph
imprecision inflates the first without inflating the second, which is why they
are kept apart. A dash means the estimate was not requested.</p>\
<p><b>The analysis is crate-local unless asked.</b> Cryptography reached only through a \
dependency's internals is visible only with <code>--descend</code>, which reports it at the \
local call that reaches it; <code>--manifest-assets</code> lists declared crypto crates no \
call site reached.</p>\
<p><b>Nothing here certifies compliance.</b> Findings are reported against a named \
profile; compliance is the migration that follows discovery.</p>\
</div>",
        total = scored.len(),
        vuln = count(QvStatus::Vulnerable),
        dep = count(QvStatus::Deprecated),
        res = count(QvStatus::Resistant),
        unknown = count(QvStatus::Unknown),
        resolved_count = resolved_count,
        analysed = crate::xml::escape(analysed),
    )
}

#[cfg(test)]
mod dashboard_tests {
    use super::*;
    use cpg_core::{AlgorithmClass, SourceLoc};

    fn scored(symbol: &str, resolves_to: Option<&str>, call_symbol: Option<&str>) -> Finding {
        let _ = (resolves_to, call_symbol);
        Finding {
            rule_id: "R-RSA-005".into(),
            node_id: 1,
            algorithm_class: AlgorithmClass::Rsa,
            qv_status: QvStatus::Vulnerable,
            location: SourceLoc::new("src/main.rs", 22),
            contextual_signature: symbol.into(),
            taint_chain: Vec::new(),
            taint_nodes: Vec::new(),
            key_size: Some(2048),
            via: Vec::new(),
            parameter_set: None,
            with: Vec::new(),
        }
    }

    #[test]
    fn a_symbol_with_generics_survives_rendering() {
        let f = scored("rsa::pkcs1v15::SigningKey::<D>::new", None, None);
        let html = render_dashboard(
            &[ScoredFinding {
                finding: &f,
                tier: 1,
                algorithm: "RSA".into(),
                advice: migration::Advice::Keep("test"),
                verdict: None,
                parts: String::new(),
                risk: 9.17,
                severity: 2.0,
                blast_factor: 4.59,
                criticality: 1.0,
                blast_radius: 11,
                conservative: false,
                resolves_to: None,
                call_symbol: None,
                refactor_scope: None,
                chain_absence: None,
            }],
            "demo-crate",
        );
        assert!(
            html.contains("SigningKey::&lt;D&gt;::new"),
            "generics must be escaped, not eaten"
        );
        assert!(!html.contains("SigningKey::<D>::new"), "raw markup leaked");
    }

    #[test]
    fn a_resolved_trait_call_shows_its_impl_abbreviated() {
        let f = scored("signature::Signer::sign", None, None);
        let target = "<rsa::pkcs1v15::signing_key::SigningKey<digest::CoreWrapper<\
                      sha2::Sha256VarCore>> as signature::Signer>::sign";
        let html = render_dashboard(
            &[ScoredFinding {
                finding: &f,
                tier: 1,
                algorithm: "RSA".into(),
                advice: migration::Advice::Keep("test"),
                verdict: None,
                parts: String::new(),
                risk: 8.0,
                severity: 2.0,
                blast_factor: 4.0,
                criticality: 1.0,
                blast_radius: 7,
                conservative: false,
                resolves_to: Some(target.into()),
                call_symbol: Some("signature::Signer::sign".into()),
                refactor_scope: Some(3),
                chain_absence: None,
            }],
            "demo-crate",
        );
        assert!(
            html.contains("SigningKey&lt;…&gt;"),
            "generics collapse: {html:?}"
        );
        assert!(
            html.contains("as signature::Signer&gt;::sign"),
            "trait kept"
        );
        assert!(!html.contains("Sha256VarCore"), "the machinery is dropped");
    }

    #[test]
    fn a_dyn_call_is_shown_as_unresolved() {
        let f = scored("rsa::pkcs1v15::Signature", None, None);
        let html = render_dashboard(
            &[ScoredFinding {
                finding: &f,
                tier: 1,
                algorithm: "RSA".into(),
                advice: migration::Advice::Keep("test"),
                verdict: None,
                parts: String::new(),
                risk: 8.0,
                severity: 2.0,
                blast_factor: 4.0,
                criticality: 1.0,
                blast_radius: 7,
                conservative: false,
                resolves_to: None,
                call_symbol: Some("<dyn signature::Signer>::sign".into()),
                refactor_scope: None,
                chain_absence: None,
            }],
            "demo-crate",
        );
        assert!(html.contains("dyn, unresolved"));
    }

    #[test]
    fn a_via_path_is_a_cbom_property_and_a_dashboard_line() {
        let mut f = scored("rsa::RsaPrivateKey::new", None, None);
        f.via = vec![
            cpg_core::ViaFrame {
                symbol: "vault::seal".into(),
                location: Some(SourceLoc::new("v.rs", 2)),
            },
            cpg_core::ViaFrame {
                symbol: "rsa::RsaPrivateKey::new".into(),
                location: Some(SourceLoc::new("v.rs", 3)),
            },
        ];
        let props = properties_for(&f);
        assert!(props.iter().any(|p| p["name"] == "quantumrust:via"
            && p["value"] == "vault::seal (v.rs:2) -> rsa::RsaPrivateKey::new (v.rs:3)"));
        let html = render_dashboard(&[ScoredFinding::for_test(&f)], "demo-crate");
        assert!(html.contains("via vault::seal &rarr; rsa::RsaPrivateKey::new"));
    }

    #[test]
    fn a_taint_chain_becomes_a_collapsed_sub_row() {
        let mut f = scored("rsa::sign", None, None);
        f.taint_chain = vec![SourceLoc::new("src/a.rs", 1), SourceLoc::new("src/b.rs", 2)];
        let html = render_dashboard(
            &[ScoredFinding {
                finding: &f,
                tier: 1,
                algorithm: "RSA".into(),
                advice: migration::Advice::Keep("test"),
                verdict: None,
                parts: String::new(),
                risk: 9.0,
                severity: 2.0,
                blast_factor: 4.5,
                criticality: 1.0,
                blast_radius: 5,
                conservative: false,
                resolves_to: None,
                call_symbol: None,
                refactor_scope: None,
                chain_absence: None,
            }],
            "demo-crate",
        );
        assert!(
            html.contains("taint chain &middot; 2 hops"),
            "summary counts hops"
        );
        assert!(
            html.contains("src/a.rs:1 &rarr; src/b.rs:2"),
            "the path is there"
        );
        assert!(!html.contains("<th>Taint chain</th>"), "the chain is not a table column");
    }

    #[test]
    fn a_short_chain_is_expanded_and_a_long_one_is_not() {
        let short: Vec<SourceLoc> = (1..=3).map(|i| SourceLoc::new("src/a.rs", i)).collect();
        let long: Vec<SourceLoc> = (1..=11).map(|i| SourceLoc::new("src/a.rs", i)).collect();
        for (chain, expect_open) in [(short, true), (long, false)] {
            let mut f = scored("rsa::sign", None, None);
            let hops = chain.len();
            f.taint_chain = chain;
            let html = render_dashboard(
                &[ScoredFinding {
                    finding: &f,
                    tier: 1,
                    algorithm: "RSA".into(),
                    advice: migration::Advice::Keep("test"),
                    verdict: None,
                    parts: String::new(),
                    risk: 9.0,
                    severity: 2.0,
                    blast_factor: 4.5,
                    criticality: 1.0,
                    blast_radius: 5,
                    conservative: false,
                    resolves_to: None,
                    call_symbol: None,
                    refactor_scope: None,
                    chain_absence: None,
                }],
                "demo-crate",
            );
            assert_eq!(
                html.contains("<details open>"),
                expect_open,
                "{hops} hops should {} be open",
                if expect_open { "" } else { "not" }
            );
        }
    }

    #[test]
    fn a_finding_without_a_chain_has_no_sub_row() {
        let f = scored("rsa::sign", None, None);
        let html = render_dashboard(
            &[ScoredFinding {
                finding: &f,
                tier: 1,
                algorithm: "RSA".into(),
                advice: migration::Advice::Keep("test"),
                verdict: None,
                parts: String::new(),
                risk: 9.0,
                severity: 2.0,
                blast_factor: 4.5,
                criticality: 1.0,
                blast_radius: 5,
                conservative: false,
                resolves_to: None,
                call_symbol: None,
                refactor_scope: None,
                chain_absence: None,
            }],
            "demo-crate",
        );
        assert!(
            !html.contains("<tr class=chainrow>"),
            "no chain means no sub-row, not an empty disclosure to open"
        );
    }

    #[test]
    fn the_by_rule_view_groups_and_orders_by_the_strongest_finding() {
        let a = scored("rsa::weak", None, None);
        let mut b = scored("rsa::strong", None, None);
        b.rule_id = "R-RSA-001".into();
        let mut c = scored("rsa::mid", None, None);
        c.rule_id = "R-RSA-001".into();
        fn row(f: &Finding, risk: f64) -> ScoredFinding<'_> {
            ScoredFinding {
                finding: f,
                tier: 1,
                algorithm: "RSA".into(),
                advice: migration::Advice::Keep("test"),
                verdict: None,
                parts: String::new(),
                risk,
                severity: 2.0,
                blast_factor: risk / 2.0,
                criticality: 1.0,
                blast_radius: 1,
                conservative: false,
                resolves_to: None,
                call_symbol: None,
                refactor_scope: None,
                chain_absence: None,
            }
        }
        let html = render_dashboard(&[row(&a, 3.0), row(&b, 9.0), row(&c, 5.0)], "demo");
        let groups: Vec<&str> = html
            .match_indices("class=gr>")
            .map(|(i, _)| &html[i + 9..i + 18])
            .collect();
        assert_eq!(
            groups,
            vec!["R-RSA-001", "R-RSA-005"],
            "strongest group first"
        );
        assert!(html.contains("2 findings"), "R-RSA-001 groups its two");
        assert!(html.contains("1 finding<"), "singular for one");
    }

    #[test]
    fn the_page_carries_both_views_and_no_script() {
        let f = scored("rsa::sign", None, None);
        let html = render_dashboard(
            &[ScoredFinding {
                finding: &f,
                tier: 1,
                algorithm: "RSA".into(),
                advice: migration::Advice::Keep("test"),
                verdict: None,
                parts: String::new(),
                risk: 9.0,
                severity: 2.0,
                blast_factor: 4.5,
                criticality: 1.0,
                blast_radius: 5,
                conservative: false,
                resolves_to: None,
                call_symbol: None,
                refactor_scope: None,
                chain_absence: None,
            }],
            "demo",
        );
        assert!(html.contains("id=p-risk") && html.contains("id=p-rule"));
        assert!(
            html.contains("Blast</b>") && html.contains("Scope</b>"),
            "definitions present"
        );
        assert!(
            !html.contains("<script"),
            "no script: the file must open from disk"
        );
    }

    #[test]
    fn rows_are_ordered_by_risk() {
        let low = scored("low::call", None, None);
        let high = scored("high::call", None, None);
        fn row(f: &Finding, risk: f64) -> ScoredFinding<'_> {
            ScoredFinding {
                finding: f,
                tier: 1,
                algorithm: "RSA".into(),
                advice: migration::Advice::Keep("test"),
                verdict: None,
                parts: String::new(),
                risk,
                severity: 2.0,
                blast_factor: risk / 2.0,
                criticality: 1.0,
                blast_radius: 1,
                conservative: false,
                resolves_to: None,
                call_symbol: None,
                refactor_scope: None,
                chain_absence: None,
            }
        }
        let html = render_dashboard(&[row(&low, 1.0), row(&high, 9.0)], "demo-crate");
        assert!(
            html.find("high::call") < html.find("low::call"),
            "higher risk must come first"
        );
    }

    #[test]
    fn a_higher_scoring_tier2_row_still_ranks_below_tier1() {
        let tier1 = scored("isolated::rsa", None, None);
        let tier2 = scored("everywhere::aes128", None, None);
        let html = render_dashboard(
            &[
                ScoredFinding {
                    tier: 2,
                    severity: 1.0,
                    risk: 15.7,
                    ..ScoredFinding::for_test(&tier2)
                },
                ScoredFinding {
                    risk: 1.0,
                    ..ScoredFinding::for_test(&tier1)
                },
            ],
            "demo-crate",
        );
        let table = &html[html.find("id=p-risk").expect("ranked view")..];
        assert!(
            table.find("isolated::rsa") < table.find("everywhere::aes128"),
            "tier first, whatever the score"
        );
    }

    #[test]
    fn the_migration_tab_lists_each_replacement() {
        let f = scored("rsa::pkcs1v15::SigningKey::<D>::new", None, None);
        let advice = migration::Advice::Replace(migration::Replacement {
            role: migration::Role::Signature,
            to: "ML-DSA-65".into(),
            standard: "FIPS 204".into(),
            alternative: None,
            hybrid: None,
            classical: None,
            bytes: Some((512, 5261)),
            cpu_us: Some((800.0, 400.0)),
            target_level: 3,
            note: None,
        });
        let html = render_dashboard(
            &[ScoredFinding {
                advice,
                ..ScoredFinding::for_test(&f)
            }],
            "demo",
        );
        let pane = &html[html.find("id=p-mig").expect("migration pane")..];
        assert!(pane.contains("ML-DSA-65") && pane.contains("FIPS 204"));
        assert!(pane.contains("512 &rarr; 5261 B"), "bytes before and after");
        assert!(
            pane.contains("not populated"),
            "the unfilled cost dimensions are stated"
        );
        assert!(
            pane.contains("CPU per exchange")
                && pane.contains("800 us &rarr; 400 us per exchange (0.5x)")
        );
    }

    #[test]
    fn the_panel_precedes_the_ranking() {
        let f = scored("rsa::sign", None, None);
        let html = render_dashboard(&[ScoredFinding::for_test(&f)], "demo");
        let panel = html.find("Most severe").expect("panel present");
        assert!(panel < html.find("id=p-risk").expect("ranked view"));
        assert!(
            html.contains("most common"),
            "one finding is both, in one card"
        );
    }

    #[test]
    fn the_dashboard_shows_the_profile_tally_and_each_verdict() {
        let f = scored("rsa::sign", None, None);
        let mut row = ScoredFinding::for_test(&f);
        row.verdict = Some(Verdict::Fail);
        let judged = Judged {
            profile_id: "cnsa-2.0".into(),
            profile_name: "CNSA 2.0".into(),
            verdicts: vec![Verdict::Fail],
        };
        let html = render_dashboard_with(&[row], "demo", Some(&judged));
        let summary = html.find("Against profile").expect("profile summary");
        assert!(summary < html.find("id=p-risk").expect("ranked view"));
        for text in [
            "CNSA 2.0",
            "0 pass, 1 fail, 0 need review",
            NOT_A_CERTIFICATE,
        ] {
            assert!(html.contains(text), "missing {text}");
        }
        assert!(html.contains("<span class=\"verdict fail\">fail</span>"));
    }

    #[test]
    fn a_long_signature_is_shortened_for_reading() {
        let long = "<digest::core_api::wrapper::CoreWrapper<digest::core_api::ct_variable::\
                    CtVariableCoreWrapper<blake2::Blake2bVarCore, typenum::uint::UInt<typenum::\
                    uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>>> as \
                    core::default::Default>::default";
        let short = display_symbol(long);
        assert!(short.len() <= 100, "{short}");
        assert!(
            short.ends_with("as core::default::Default>::default"),
            "{short}"
        );
        assert_eq!(
            display_symbol("rsa::RsaPrivateKey::sign"),
            "rsa::RsaPrivateKey::sign"
        );

        let f = scored(long, None, None);
        let html = render_dashboard(&[ScoredFinding::for_test(&f)], "demo");
        assert!(html.contains(&crate::xml::escape(&short)));
        assert!(html.contains(&format!("title=\"{}\"", crate::xml::escape(long))));
    }

    #[test]
    fn the_crate_local_note_points_to_descent() {
        let f = scored("rsa::sign", None, None);
        let html = render_dashboard(&[ScoredFinding::for_test(&f)], "demo");
        assert!(html.contains("<code>--descend</code>"));
    }

    #[test]
    fn without_a_profile_the_dashboard_has_no_verdicts() {
        let f = scored("rsa::sign", None, None);
        let html = render_dashboard(&[ScoredFinding::for_test(&f)], "demo");
        assert!(!html.contains("Against profile"));
        assert!(!html.contains("class=\"verdict"));
    }
}

pub(crate) fn qv_label(s: QvStatus) -> &'static str {
    match s {
        QvStatus::Vulnerable => "quantum-vulnerable",
        QvStatus::Deprecated => "deprecated",
        QvStatus::Resistant => "quantum-resistant",
        QvStatus::Unknown => "unknown",
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use cpg_core::{AlgorithmClass, SourceLoc};

    fn representative() -> Vec<Finding> {
        let at = |rule_id: &str,
                  class: AlgorithmClass,
                  status: QvStatus,
                  symbol: &str,
                  line: u32,
                  key_size: Option<u32>| Finding {
            rule_id: rule_id.into(),
            node_id: line,
            algorithm_class: class,
            qv_status: status,
            location: SourceLoc::new("src/main.rs", line),
            contextual_signature: symbol.into(),
            taint_chain: Vec::new(),
            taint_nodes: Vec::new(),
            key_size,
            via: Vec::new(),
            parameter_set: None,
            with: Vec::new(),
        };

        let mut keygen = at(
            "R-RSA-001",
            AlgorithmClass::Rsa,
            QvStatus::Vulnerable,
            "rsa::RsaPrivateKey::new",
            21,
            Some(2048),
        );
        keygen.taint_chain = vec![
            SourceLoc::new("src/main.rs", 21),
            SourceLoc::new("src/main.rs", 23),
        ];

        vec![
            keygen,
            at(
                "R-RSA-002",
                AlgorithmClass::Rsa,
                QvStatus::Vulnerable,
                "<dyn rsa::signature::Signer>::sign",
                29,
                Some(2048),
            ),
            at(
                "R-SHA2-001",
                AlgorithmClass::Hash,
                QvStatus::Resistant,
                "rsa::sha2::OidSha256",
                23,
                None,
            ),
            at(
                "R-AES-002",
                AlgorithmClass::Symmetric,
                QvStatus::Deprecated,
                "<aes::Aes128 as crypto_common::KeyInit>::new",
                40,
                None,
            ),
        ]
    }

    #[test]
    fn cbom_json_snapshot() {
        insta::assert_json_snapshot!(emit_cbom(&representative(), &RuleSet::builtin()));
    }

    #[test]
    fn cbom_xml_snapshot() {
        insta::assert_snapshot!(emit_cbom_xml(&representative(), &RuleSet::builtin()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpg_core::{AlgorithmClass, SourceLoc};

    fn sample() -> Finding {
        Finding {
            rule_id: "R-RSA-002".into(),
            node_id: 1,
            algorithm_class: AlgorithmClass::Rsa,
            qv_status: QvStatus::Vulnerable,
            location: SourceLoc::new("src/main.rs", 15),
            contextual_signature: "rsa::RsaPrivateKey::sign".into(),
            taint_chain: vec![
                SourceLoc::new("src/main.rs", 15),
                SourceLoc::new("src/ffi.rs", 5),
            ],
            taint_nodes: Vec::new(),
            key_size: None,
            via: Vec::new(),
            parameter_set: None,
            with: Vec::new(),
        }
    }

    #[test]
    fn a_profile_puts_its_verdicts_in_both_cboms() {
        let rules = RuleSet::builtin();
        let profile = load_profile("cnsa-2.0").unwrap();
        let findings = vec![sample()];
        let judged = Judged::new(&profile, &findings, &rules);
        assert_eq!(judged.verdicts, [Verdict::Fail]);
        let extras = CbomExtras {
            judged: Some(&judged),
            ..CbomExtras::default()
        };

        let bom = emit_cbom_report(&findings, &rules, extras);
        let props = bom["components"][0]["properties"].as_array().unwrap();
        assert!(
            props.contains(&json!({"name": "quantumrust:profile-verdict", "value": "fail"})),
            "{props:#?}"
        );
        let meta = bom["metadata"]["properties"].as_array().unwrap();
        for (name, value) in [
            ("quantumrust:profile", "cnsa-2.0"),
            ("quantumrust:profile-tally", "0 pass, 1 fail, 0 need review"),
            ("quantumrust:profile-note", NOT_A_CERTIFICATE),
        ] {
            assert!(
                meta.contains(&json!({"name": name, "value": value})),
                "{meta:#?}"
            );
        }

        let xml = emit_cbom_xml_report(&findings, &rules, extras);
        for line in [
            r#"<property name="quantumrust:profile-verdict">fail</property>"#,
            r#"<property name="quantumrust:profile">cnsa-2.0</property>"#,
            r#"<property name="quantumrust:profile-tally">0 pass, 1 fail, 0 need review</property>"#,
        ] {
            assert!(xml.contains(line), "missing {line} in\n{xml}");
        }
    }

    #[test]
    fn the_cbom_names_its_subject_and_a_tool_version() {
        let rules = RuleSet::builtin();
        let subject = Subject {
            name: "snow".into(),
            version: Some("0.10.0".into()),
            library: true,
        };
        let extras = CbomExtras {
            subject: Some(&subject),
            ..CbomExtras::default()
        };
        let bom = emit_cbom_report(&[sample()], &rules, extras);
        assert_eq!(
            bom["metadata"]["component"],
            json!({
                "type": "library",
                "bom-ref": "pkg:cargo/snow@0.10.0",
                "name": "snow",
                "version": "0.10.0",
                "purl": "pkg:cargo/snow@0.10.0",
            })
        );
        let tool = bom["metadata"]["tools"]["components"][0]["version"]
            .as_str()
            .unwrap();
        assert_ne!(tool, "0.0.0");

        let xml = emit_cbom_xml_report(&[sample()], &rules, extras);
        let component = "<component type=\"library\" bom-ref=\"pkg:cargo/snow@0.10.0\">\n      \
                         <name>snow</name>\n      <version>0.10.0</version>\n      \
                         <purl>pkg:cargo/snow@0.10.0</purl>\n    </component>";
        assert!(xml.contains(component), "{xml}");
        assert!(
            xml.find("</tools>") < xml.find(component),
            "tools come first"
        );
    }

    fn folded(
        rule: &str,
        class: AlgorithmClass,
        status: QvStatus,
        parts: &[(&str, &str, QvStatus, Option<&str>)],
    ) -> Finding {
        Finding {
            rule_id: rule.into(),
            algorithm_class: class,
            qv_status: status,
            with: parts
                .iter()
                .map(|(rule_id, signature, qv_status, set)| cpg_core::Part {
                    rule_id: (*rule_id).into(),
                    signature: (*signature).into(),
                    qv_status: *qv_status,
                    parameter_set: set.map(str::to_string),
                })
                .collect(),
            ..sample()
        }
    }

    #[test]
    fn a_row_is_named_by_the_part_that_names_its_algorithm() {
        let rules = RuleSet::builtin();
        let row = folded(
            "R-RING-005",
            AlgorithmClass::Aead,
            QvStatus::Deprecated,
            &[(
                "R-RING-ALG-003",
                "ring::aead::AES_128_GCM",
                QvStatus::Deprecated,
                Some("AES-128"),
            )],
        );
        assert_eq!(algorithm_name(&row, &rules), "AES-128");
        assert_eq!(quantum_security_level(&row, &rules), Some(1));

        let bom = emit_cbom(std::slice::from_ref(&row), &rules);
        let component = &bom["components"][0];
        assert_eq!(
            component["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"],
            "AES-128"
        );
        let part = json!({
            "name": "quantumrust:part",
            "value": "R-RING-ALG-003 ring::aead::AES_128_GCM (deprecated)",
        });
        assert!(component["properties"].as_array().unwrap().contains(&part));
        let xml = emit_cbom_xml(std::slice::from_ref(&row), &rules);
        assert!(xml.contains(
            "<property name=\"quantumrust:part\">R-RING-ALG-003 ring::aead::AES_128_GCM (deprecated)</property>"
        ));
    }

    #[test]
    fn a_signing_row_keeps_its_name_and_lists_its_digest() {
        let rules = RuleSet::builtin();
        let row = folded(
            "R-RSA-005",
            AlgorithmClass::Rsa,
            QvStatus::Vulnerable,
            &[("R-SHA2-001", "sha2::OidSha256", QvStatus::Resistant, None)],
        );
        assert_eq!(algorithm_name(&row, &rules), "RSA");
        assert_eq!(quantum_security_level(&row, &rules), Some(0));
        let bom = emit_cbom(std::slice::from_ref(&row), &rules);
        let part = json!({
            "name": "quantumrust:part",
            "value": "R-SHA2-001 sha2::OidSha256 (quantum-resistant)",
        });
        assert!(bom["components"][0]["properties"]
            .as_array()
            .unwrap()
            .contains(&part));
    }

    #[test]
    fn without_a_profile_the_cbom_carries_no_verdicts() {
        let bom = emit_cbom(&[sample()], &RuleSet::builtin());
        assert!(bom["metadata"].get("properties").is_none());
        assert!(!bom.to_string().contains("quantumrust:profile"));
    }

    #[test]
    fn a_signature_depends_on_its_keygen() {
        let mut keygen = sample();
        keygen.rule_id = "R-RSA-001".into();
        keygen.node_id = 10;
        keygen.contextual_signature = "rsa::RsaPrivateKey::new".into();
        keygen.location = SourceLoc::new("src/main.rs", 9);
        let mut sign = sample();
        sign.node_id = 20;
        keygen.taint_nodes = vec![10, 15, 20];
        let findings = [keygen.clone(), sign.clone()];
        assert_eq!(dependencies(&findings), [(1, vec![0])]);
        let bom = emit_cbom(&findings, &RuleSet::builtin());
        assert_eq!(
            bom["dependencies"],
            serde_json::json!([{"ref": bom_ref(&sign), "dependsOn": [bom_ref(&keygen)]}])
        );
    }

    #[test]
    fn a_second_finding_on_the_producers_own_call_is_not_a_dependency() {
        let mut keygen = sample();
        keygen.rule_id = "R-RSA-001".into();
        keygen.node_id = 10;
        keygen.taint_nodes = vec![10, 20];
        let mut same_call = sample();
        same_call.rule_id = "R-SHA2-001".into();
        same_call.node_id = 10;
        let mut sign = sample();
        sign.node_id = 20;
        let findings = [keygen, same_call, sign];
        assert_eq!(dependencies(&findings), [(2, vec![0])]);
    }

    #[test]
    fn an_empty_inventory_has_no_components_or_dependencies() {
        let bom = emit_cbom(&[], &RuleSet::builtin());
        assert_eq!(bom["components"], serde_json::json!([]));
        assert!(bom.get("dependencies").is_none(), "{bom}");
    }

    #[test]
    fn xml_dependencies_follow_components() {
        let mut keygen = sample();
        keygen.rule_id = "R-RSA-001".into();
        keygen.node_id = 10;
        keygen.taint_nodes = vec![20];
        let mut sign = sample();
        sign.node_id = 20;
        let xml = emit_cbom_xml(&[keygen, sign], &RuleSet::builtin());
        let components = xml.find("</components>").expect("components");
        let dependencies = xml.find("<dependencies>").expect("dependencies");
        assert!(components < dependencies, "{xml}");
        assert!(xml.contains("<dependency ref=\"crypto-"), "{xml}");
    }

    #[test]
    fn cbom_has_cyclonedx_envelope() {
        let bom = emit_cbom(&[sample()], &RuleSet::builtin());
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["specVersion"], "1.7");
        assert_eq!(bom["components"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn crypto_properties_come_from_the_rule_not_the_algorithm_class() {
        let bom = emit_cbom(&[sample()], &RuleSet::builtin());
        let algorithm = &bom["components"][0]["cryptoProperties"]["algorithmProperties"];
        assert_eq!(algorithm["primitive"], "signature");
        assert_eq!(algorithm["nistQuantumSecurityLevel"], 0);
        assert!(algorithm["cryptoFunctions"]
            .as_array()
            .unwrap()
            .contains(&json!("sign")));
        assert_eq!(
            bom["components"][0]["cryptoProperties"]["oid"],
            "1.2.840.113549.1.1.1"
        );
    }

    #[test]
    fn a_read_key_size_reaches_the_cbom() {
        let mut keygen = sample();
        keygen.rule_id = "R-RSA-001".into();
        keygen.contextual_signature = "rsa::RsaPrivateKey::new".into();
        keygen.key_size = Some(4096);

        let bom = emit_cbom(&[keygen], &RuleSet::builtin());
        assert_eq!(
            bom["components"][0]["cryptoProperties"]["algorithmProperties"]
                ["parameterSetIdentifier"],
            "4096"
        );
    }

    #[test]
    fn a_fixed_parameter_set_survives_without_a_read_size() {
        let mut ed25519 = sample();
        ed25519.rule_id = "R-ED25519-002".into();
        ed25519.contextual_signature = "ed25519_dalek::SigningKey::sign".into();
        ed25519.key_size = None;

        let bom = emit_cbom(&[ed25519], &RuleSet::builtin());
        assert_eq!(
            bom["components"][0]["cryptoProperties"]["algorithmProperties"]
                ["parameterSetIdentifier"],
            "Ed25519"
        );
    }

    #[test]
    fn a_read_parameter_set_names_the_algorithm_and_its_level() {
        let rules = RuleSet::builtin();
        let kem = |set: Option<&str>| {
            let mut f = sample();
            f.rule_id = "R-MLKEM-001".into();
            f.algorithm_class = AlgorithmClass::Kem;
            f.qv_status = QvStatus::Resistant;
            f.contextual_signature = "ml_kem::KemCore::generate".into();
            f.parameter_set = set.map(str::to_string);
            f
        };
        let bom = emit_cbom(&[kem(Some("768"))], &rules);
        let props = &bom["components"][0]["cryptoProperties"]["algorithmProperties"];
        assert_eq!(props["parameterSetIdentifier"], "768");
        assert_eq!(props["nistQuantumSecurityLevel"], 3);
        assert_eq!(algorithm_name(&kem(Some("768")), &rules), "ML-KEM-768");
        assert_eq!(quantum_security_level(&kem(Some("1024")), &rules), Some(5));

        assert_eq!(algorithm_name(&kem(None), &rules), "ML-KEM");
        assert_eq!(quantum_security_level(&kem(None), &rules), None);

        let cnsa = load_profile("cnsa-2.0").expect("shipped");
        let verdict = |f: &Finding| {
            cnsa.judge_named(
                f,
                quantum_security_level(f, &rules),
                &algorithm_name(f, &rules),
            )
        };
        assert_eq!(verdict(&kem(Some("768"))), Verdict::Fail);
        assert_eq!(verdict(&kem(Some("1024"))), Verdict::Pass);
        assert_eq!(verdict(&kem(None)), Verdict::Review);
    }

    #[test]
    fn one_algorithm_class_yields_different_primitives_per_operation() {
        let mut encryption = sample();
        encryption.rule_id = "R-RSA-004".into();
        encryption.contextual_signature = "rsa::RsaPublicKey::encrypt".into();

        let bom = emit_cbom(&[sample(), encryption], &RuleSet::builtin());
        let primitive = |i: usize| {
            bom["components"][i]["cryptoProperties"]["algorithmProperties"]["primitive"].clone()
        };

        assert_eq!(primitive(0), "signature");
        assert_eq!(primitive(1), "pke");
    }

    #[test]
    fn every_component_carries_its_provenance() {
        let bom = emit_cbom(&[sample()], &RuleSet::builtin());
        let component = &bom["components"][0];
        let occurrence = &component["evidence"]["occurrences"][0];
        assert_eq!(occurrence["location"], "src/main.rs");
        assert_eq!(occurrence["line"], 15);

        let properties = component["properties"].as_array().unwrap();
        let named = |name: &str| {
            properties
                .iter()
                .find(|p| p["name"] == name)
                .map(|p| p["value"].clone())
        };
        assert_eq!(named("quantumrust:rule").unwrap(), "R-RSA-002");
        assert_eq!(
            named("quantumrust:taint-chain").unwrap(),
            "src/main.rs:15 -> src/ffi.rs:5"
        );
    }

    #[test]
    fn a_finding_with_no_chain_omits_the_property() {
        let mut finding = sample();
        finding.taint_chain.clear();
        let bom = emit_cbom(&[finding], &RuleSet::builtin());
        let properties = bom["components"][0]["properties"].as_array().unwrap();
        assert!(!properties
            .iter()
            .any(|p| p["name"] == "quantumrust:taint-chain"));
    }

    #[test]
    fn two_instances_on_one_line_get_two_bom_refs() {
        let rules = RuleSet::builtin();
        let mut p256 = sample();
        p256.parameter_set = Some("P-256".into());
        let mut p384 = sample();
        p384.parameter_set = Some("P-384".into());
        let mut lone = sample();
        lone.location.line += 100;
        let findings = [p256, p384, lone.clone()];
        let cbom = emit_cbom(&findings, &rules);
        let refs: Vec<&str> = cbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["bom-ref"].as_str().unwrap())
            .collect();
        assert_ne!(refs[0], refs[1], "{refs:?}");
        assert_eq!(refs[2], bom_ref(&lone));
        let xml = crate::xml::emit_cbom_xml(&findings, &rules);
        for r in &refs {
            assert_eq!(xml.matches(&format!("bom-ref=\"{r}\"")).count(), 1, "{r}");
        }
    }

    #[test]
    fn bom_refs_are_stable_and_distinguish_one_line_calling_two_apis() {
        let first = sample();
        let mut second = sample();
        second.contextual_signature = "rsa::pkcs1v15::SigningKey::new".into();

        assert_eq!(bom_ref(&first), bom_ref(&sample()), "must be deterministic");
        assert_ne!(
            bom_ref(&first),
            bom_ref(&second),
            "same rule and line, different API: refs must differ"
        );
    }

    #[test]
    fn cbom_is_byte_identical_across_runs() {
        let rules = RuleSet::builtin();
        let first = serde_json::to_string(&emit_cbom(&[sample()], &rules)).unwrap();
        let second = serde_json::to_string(&emit_cbom(&[sample()], &rules)).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn an_unknown_rule_degrades_to_neutral_properties() {
        let mut finding = sample();
        finding.rule_id = "R-NOT-SHIPPED".into();
        let bom = emit_cbom(&[finding], &RuleSet::builtin());
        let algorithm = &bom["components"][0]["cryptoProperties"]["algorithmProperties"];
        assert_eq!(algorithm["primitive"], "unknown");
    }
}
