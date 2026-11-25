use std::collections::{BTreeMap, BTreeSet};

use cpg_core::{AlgorithmClass, Finding, QvStatus};
use qr_rules::RuleSet;
use serde::Deserialize;

const TABLE: &str = include_str!("../../../data/pqc_replacements.toml");
const SPEED: &str = include_str!("../../../data/pqc_speed.json");

#[derive(Debug, Clone, Deserialize)]
struct Speed {
    date: String,
    machine: SpeedMachine,
    schemes: BTreeMap<String, BTreeMap<String, Timing>>,
}

#[derive(Debug, Clone, Deserialize)]
struct SpeedMachine {
    cpu: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Timing {
    median_us: f64,
}

fn speed() -> &'static Speed {
    static SPEED_CELL: std::sync::OnceLock<Speed> = std::sync::OnceLock::new();
    SPEED_CELL.get_or_init(|| serde_json::from_str(SPEED).expect("shipped speed table parses"))
}

#[derive(Clone, Copy)]
enum Exchange {
    Signature,
    Kem,
    DiffieHellman,
    KeyTransport,
}

fn exchange_us(scheme: &str, how: Exchange) -> Option<f64> {
    let ops = speed().schemes.get(scheme)?;
    let op = |name: &str| ops.get(name).map(|t| t.median_us);
    Some(match how {
        Exchange::Signature => op("sign")? + op("verify")?,
        Exchange::Kem => op("keygen")? + op("encaps")? + op("decaps")?,
        Exchange::DiffieHellman => 2.0 * (op("keygen")? + op("dh")?),
        Exchange::KeyTransport => op("encrypt")? + op("decrypt")?,
    })
}

pub fn speed_provenance() -> String {
    let s = speed();
    format!("{}, {}", s.machine.cpu, s.date)
}

#[derive(Debug, Clone, Deserialize)]
struct Table {
    default_level: u8,
    mtu_bytes: u32,
    scheme: Vec<Scheme>,
    classical: Vec<Classical>,
    role: Roles,
    upgrade: Vec<Upgrade>,
}

#[derive(Debug, Clone, Deserialize)]
struct Scheme {
    name: String,
    family: String,
    standard: String,
    level: u8,
    public_key: u32,
    #[serde(default)]
    signature: Option<u32>,
    #[serde(default)]
    ciphertext: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct Classical {
    name: String,
    strength: u16,
    public_key: u32,
    #[serde(default)]
    signature: Option<u32>,
    #[serde(default)]
    ciphertext: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct Roles {
    signature: RoleSpec,
    kem: RoleSpec,
}

#[derive(Debug, Clone, Deserialize)]
struct RoleSpec {
    primary: String,
    #[serde(default)]
    alternative: Option<String>,
    #[serde(default)]
    alternative_note: Option<String>,
    hybrid: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Upgrade {
    kind: String,
    from: Vec<String>,
    to: Vec<Target>,
    standard: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Target {
    name: String,
    level: u8,
}

fn table() -> &'static Table {
    static TABLE_CELL: std::sync::OnceLock<Table> = std::sync::OnceLock::new();
    TABLE_CELL.get_or_init(|| toml::from_str(TABLE).expect("shipped replacement table parses"))
}

pub fn level_of(name: &str) -> Option<u8> {
    let t = table();
    t.scheme
        .iter()
        .find(|s| s.name == name)
        .map(|s| s.level)
        .or_else(|| {
            t.upgrade
                .iter()
                .flat_map(|u| &u.to)
                .find(|x| x.name == name)
                .map(|x| x.level)
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Signature,
    KeyEstablishment,
    NotEstablished,
    Symmetric,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Role::Signature => "signature",
            Role::KeyEstablishment => "key establishment",
            Role::NotEstablished => "role not established",
            Role::Symmetric => "symmetric / hash",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Advice {
    Replace(Replacement),
    Keep(&'static str),
    Resolve(&'static str),
    Unplanned(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Replacement {
    pub role: Role,
    pub to: String,
    pub standard: String,
    pub alternative: Option<String>,
    pub hybrid: Option<String>,
    pub classical: Option<String>,
    pub bytes: Option<(u32, u32)>,
    pub cpu_us: Option<(f64, f64)>,
    pub target_level: u8,
    pub note: Option<&'static str>,
}

impl Replacement {
    pub fn exceeds_mtu(&self) -> bool {
        self.bytes
            .is_some_and(|(_, after)| after > table().mtu_bytes)
    }
}

pub fn recommend(
    finding: &Finding,
    rules: &RuleSet,
    name: &str,
    profile: Option<&crate::Profile>,
) -> Advice {
    recommend_at(finding, &[], rules, name, profile)
}

pub fn recommend_at(
    finding: &Finding,
    type_args: &[String],
    rules: &RuleSet,
    name: &str,
    profile: Option<&crate::Profile>,
) -> Advice {
    if let Some(p) = profile {
        let level = crate::quantum_security_level(finding, rules);
        match p.judge_named(finding, level, name) {
            crate::Verdict::Pass => return Advice::Keep("the profile accepts it"),
            crate::Verdict::Fail => return failed(finding, type_args, rules, name, p),
            crate::Verdict::Review => {}
        }
    }
    let floor = profile.and_then(|p| p.min_quantum_security_level);
    let accepts = |n: &str, level: u8| profile.is_none_or(|p| p.accepts(n, level));
    match finding.qv_status {
        QvStatus::Unknown => Advice::Resolve(
            "the algorithm was not resolved, so no replacement can be chosen for it",
        ),
        QvStatus::Deprecated => upgrade(name, &accepts, true).map_or(
            Advice::Resolve("deprecated, but no replacement is on record for this algorithm"),
            Advice::Replace,
        ),
        QvStatus::Resistant => {
            let below = crate::quantum_security_level(finding, rules)
                .zip(floor)
                .is_some_and(|(level, floor)| level < floor);
            if !below || profile.is_some_and(|p| p.allows(name)) {
                return Advice::Keep("already quantum-resistant at the target level");
            }
            strengthen(name, floor.unwrap_or(0), &accepts).map_or(
                Advice::Keep(
                    "quantum-resistant; below the profile's level, with no stronger set on record",
                ),
                Advice::Replace,
            )
        }
        QvStatus::Vulnerable => Advice::Replace(vulnerable(
            finding,
            type_args,
            rules,
            name,
            floor.unwrap_or(0),
        )),
    }
}

fn failed(
    finding: &Finding,
    type_args: &[String],
    rules: &RuleSet,
    name: &str,
    profile: &crate::Profile,
) -> Advice {
    let floor = profile.min_quantum_security_level.unwrap_or(0);
    let accepts = |n: &str, level: u8| profile.accepts(n, level);
    let replacement = match finding.qv_status {
        QvStatus::Unknown => {
            return Advice::Unplanned(
                "fails the profile, and the algorithm was not resolved, so no replacement \
                 can be chosen",
            )
        }
        QvStatus::Vulnerable => Some(vulnerable(finding, type_args, rules, name, floor)),
        QvStatus::Deprecated => upgrade(name, &accepts, true),
        QvStatus::Resistant => strengthen(name, floor, &accepts),
    };
    let every_side_accepted = |r: &Replacement| {
        r.to.split(" or ")
            .all(|to| profile.accepts(to, level_of(to).unwrap_or(r.target_level)))
    };
    match replacement.filter(every_side_accepted) {
        Some(r) => Advice::Replace(r),
        None => Advice::Unplanned("fails the profile, and no replacement it accepts is on record"),
    }
}

fn vulnerable(
    finding: &Finding,
    type_args: &[String],
    rules: &RuleSet,
    name: &str,
    floor: u8,
) -> Replacement {
    let classical = classical_of(finding, name, type_args);
    let strength_level = match classical.map(|c| c.strength) {
        Some(s) if s >= 256 => 5,
        Some(s) if s >= 192 => 3,
        _ => 0,
    };
    let target = table().default_level.max(floor).max(strength_level);
    match role_of(finding, rules) {
        Role::Signature => signature(classical, target),
        Role::KeyEstablishment => key_establishment(classical, name, target),
        _ => {
            let sig = signature(classical, target);
            let kem = key_establishment(classical, name, target);
            Replacement {
                role: Role::NotEstablished,
                to: format!("{} or {}", sig.to, kem.to),
                standard: format!("{} / {}", sig.standard, kem.standard),
                alternative: sig.alternative,
                hybrid: None,
                classical: classical.map(|c| c.name.clone()),
                bytes: None,
                cpu_us: None,
                target_level: target,
                note: Some(
                    "the call site does not fix the key's use: the first if it signs, \
                     the second if it encrypts or transports keys",
                ),
            }
        }
    }
}

fn role_of(finding: &Finding, rules: &RuleSet) -> Role {
    let spec = crate::crypto_spec(finding, rules);
    match spec.primitive.as_str() {
        "signature" => return Role::Signature,
        "pke" | "kem" | "key-agree" => return Role::KeyEstablishment,
        _ => {}
    }
    match finding.algorithm_class {
        AlgorithmClass::EdDsa => Role::Signature,
        AlgorithmClass::Ecdsa => Role::NotEstablished,
        AlgorithmClass::EcdhX25519 | AlgorithmClass::Ecdh | AlgorithmClass::Kem => {
            Role::KeyEstablishment
        }
        AlgorithmClass::Dsa => Role::Signature,
        AlgorithmClass::EcKey => Role::NotEstablished,
        AlgorithmClass::FiniteFieldDh if spec.algorithm_family.as_deref() == Some("DSA") => {
            Role::Signature
        }
        AlgorithmClass::FiniteFieldDh => Role::KeyEstablishment,
        _ => Role::NotEstablished,
    }
}

fn classical_of(finding: &Finding, name: &str, type_args: &[String]) -> Option<&'static Classical> {
    let t = table();
    let lookup = |n: &str| t.classical.iter().find(|c| c.name == n);
    let curve = call_curve(&finding.contextual_signature, type_args);
    match name {
        "RSA" => lookup(&format!("RSA-{}", finding.key_size?)),
        "DSA" => lookup(&format!("DSA-{}", finding.key_size?)),
        "ECDSA" => lookup(&format!("ECDSA-{}", curve?)),
        "ECDH" => lookup(&format!("ECDH-{}", curve?)),
        other => lookup(other),
    }
}

const CURVES: [(&str, &str, &str); 4] = [
    ("NistP256", "p256", "P256"),
    ("NistP384", "p384", "P384"),
    ("NistP521", "p521", "P521"),
    ("Secp256k1", "k256", "secp256k1"),
];

fn call_curve(sig: &str, type_args: &[String]) -> Option<&'static str> {
    let typed = curve_types(type_args.iter().map(String::as_str));
    if typed.is_empty() {
        curve_of(sig)
    } else {
        only(typed)
    }
}

fn curve_of(sig: &str) -> Option<&'static str> {
    let typed = curve_types(std::iter::once(sig));
    if !typed.is_empty() {
        return only(typed);
    }
    let mut via = BTreeSet::new();
    for (_, krate, curve) in CURVES {
        let needle = format!("{krate}::");
        for (at, _) in sig.match_indices(&needle) {
            let joined = sig[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
            if !joined {
                via.insert(curve);
            }
        }
    }
    only(via)
}

fn curve_types<'a>(texts: impl Iterator<Item = &'a str>) -> BTreeSet<&'static str> {
    let texts: Vec<&str> = texts.collect();
    CURVES
        .iter()
        .filter(|(ty, _, _)| texts.iter().any(|t| t.contains(ty)))
        .map(|&(_, _, curve)| curve)
        .collect()
}

fn only(found: BTreeSet<&'static str>) -> Option<&'static str> {
    let mut found = found.into_iter();
    match (found.next(), found.next()) {
        (Some(curve), None) => Some(curve),
        _ => None,
    }
}

fn scheme(family: &str, target: u8) -> &'static Scheme {
    let t = table();
    let mut sets: Vec<&Scheme> = t.scheme.iter().filter(|s| s.family == family).collect();
    sets.sort_by_key(|s| s.level);
    sets.iter()
        .find(|s| s.level >= target)
        .or(sets.last())
        .copied()
        .expect("every family in the role table has a parameter set")
}

fn signature(classical: Option<&Classical>, target: u8) -> Replacement {
    let spec = &table().role.signature;
    let to = scheme(&spec.primary, target);
    let alternative = spec.alternative.as_deref().map(|family| {
        let alt = scheme(family, target);
        match &spec.alternative_note {
            Some(note) => format!("{} ({}) — {note}", alt.name, alt.standard),
            None => format!("{} ({})", alt.name, alt.standard),
        }
    });
    Replacement {
        role: Role::Signature,
        to: to.name.clone(),
        standard: to.standard.clone(),
        alternative,
        hybrid: Some(spec.hybrid.clone()),
        classical: classical.map(|c| c.name.clone()),
        bytes: classical
            .and_then(|c| Some(c.public_key + c.signature?))
            .map(|before| (before, to.public_key + to.signature.unwrap_or(0))),
        cpu_us: classical
            .and_then(|c| exchange_us(&c.name, Exchange::Signature))
            .zip(exchange_us(&to.name, Exchange::Signature)),
        target_level: target,
        note: None,
    }
}

fn key_establishment(classical: Option<&Classical>, name: &str, target: u8) -> Replacement {
    let spec = &table().role.kem;
    let to = scheme(&spec.primary, target);
    let before = classical.map(|c| match c.ciphertext {
        Some(ct) if name == "RSA" => c.public_key + ct,
        _ => 2 * c.public_key,
    });
    Replacement {
        role: Role::KeyEstablishment,
        to: to.name.clone(),
        standard: to.standard.clone(),
        alternative: None,
        hybrid: Some(spec.hybrid.clone()),
        classical: classical.map(|c| c.name.clone()),
        bytes: before.map(|b| (b, to.public_key + to.ciphertext.unwrap_or(0))),
        cpu_us: classical
            .and_then(|c| {
                let how = if name == "RSA" {
                    Exchange::KeyTransport
                } else {
                    Exchange::DiffieHellman
                };
                exchange_us(&c.name, how)
            })
            .zip(exchange_us(&to.name, Exchange::Kem)),
        target_level: target,
        note: None,
    }
}

fn upgrade(
    name: &str,
    accepts: &dyn Fn(&str, u8) -> bool,
    deprecated: bool,
) -> Option<Replacement> {
    let up = table().upgrade.iter().find(|u| {
        u.from
            .iter()
            .chain(u.to.iter().map(|x| &x.name))
            .any(|n| n == name)
    })?;
    let to = up
        .to
        .iter()
        .find(|x| x.name != name && accepts(&x.name, x.level))?;
    Some(Replacement {
        role: Role::Symmetric,
        to: to.name.clone(),
        standard: up.standard.clone(),
        alternative: None,
        hybrid: None,
        classical: None,
        bytes: None,
        cpu_us: None,
        target_level: to.level,
        note: Some(match (deprecated, up.kind.as_str()) {
            (false, _) => "quantum-resistant already; the profile does not accept it",
            (true, "hash") => {
                "a hash replacement changes digest length wherever it is stored or compared"
            }
            (true, _) => {
                "Grover's algorithm halves a key's effective strength; 256-bit keys keep 128"
            }
        }),
    })
}

fn strengthen(name: &str, floor: u8, accepts: &dyn Fn(&str, u8) -> bool) -> Option<Replacement> {
    let t = table();
    let Some(current) = t.scheme.iter().find(|s| s.name == name) else {
        return upgrade(name, accepts, false);
    };
    let signs = current.signature.is_some();
    let primary = if signs {
        &t.role.signature.primary
    } else {
        &t.role.kem.primary
    };
    let bar = floor.max(current.level);
    [current.family.as_str(), primary.as_str()]
        .into_iter()
        .flat_map(|family| {
            let mut sets: Vec<&Scheme> = t.scheme.iter().filter(|s| s.family == family).collect();
            sets.sort_by_key(|s| s.level);
            sets
        })
        .find(|to| to.name != current.name && to.level >= bar && accepts(&to.name, to.level))
        .map(|to| Replacement {
            role: if signs {
                Role::Signature
            } else {
                Role::KeyEstablishment
            },
            to: to.name.clone(),
            standard: to.standard.clone(),
            alternative: None,
            hybrid: None,
            classical: None,
            bytes: Some((
                current.public_key + current.signature.or(current.ciphertext).unwrap_or(0),
                to.public_key + to.signature.or(to.ciphertext).unwrap_or(0),
            )),
            cpu_us: {
                let how = if signs {
                    Exchange::Signature
                } else {
                    Exchange::Kem
                };
                exchange_us(&current.name, how).zip(exchange_us(&to.name, how))
            },
            target_level: to.level,
            note: Some(if to.family == current.family {
                "quantum-resistant already; the profile asks for a higher category"
            } else {
                "quantum-resistant already; the profile does not name this family, and it \
                 does name this one"
            }),
        })
}

pub fn unplanned(scored: &[crate::ScoredFinding<'_>]) -> Vec<(String, u8, usize)> {
    let mut rows: BTreeMap<(String, u8), BTreeSet<(&str, u32)>> = BTreeMap::new();
    for r in scored {
        if matches!(r.advice, Advice::Unplanned(_)) {
            rows.entry((r.algorithm.clone(), r.tier))
                .or_default()
                .insert((r.finding.location.file.as_str(), r.finding.location.line));
        }
    }
    let mut out: Vec<(String, u8, usize)> = rows
        .into_iter()
        .map(|((algorithm, tier), sites)| (algorithm, tier, sites.len()))
        .collect();
    out.sort_by(|a, b| {
        a.1.cmp(&b.1)
            .then(b.2.cmp(&a.2))
            .then_with(|| a.0.cmp(&b.0))
    });
    out
}

fn unplanned_line(algorithm: &str, tier: u8, sites: usize) -> String {
    format!(
        "{algorithm} (Tier {tier}, {sites} site{}): fails the profile; no replacement it \
         accepts is on record",
        if sites == 1 { "" } else { "s" }
    )
}

#[derive(Debug, Clone)]
pub struct PlanRow {
    pub from: String,
    pub tier: u8,
    pub replacement: Replacement,
    pub sites: usize,
    pub findings: usize,
    pub refactor_scope: Option<usize>,
}

type PlanKey = (String, String, u8);
type Accumulated<'a> = (Replacement, BTreeSet<(&'a str, u32)>, usize, Option<usize>);

pub fn plan(scored: &[crate::ScoredFinding<'_>]) -> Vec<PlanRow> {
    let mut rows: BTreeMap<PlanKey, Accumulated<'_>> = BTreeMap::new();
    for r in scored {
        let Advice::Replace(rep) = &r.advice else {
            continue;
        };
        let from = rep.classical.clone().unwrap_or_else(|| r.algorithm.clone());
        let entry = rows
            .entry((from, rep.to.clone(), r.tier))
            .or_insert_with(|| (rep.clone(), BTreeSet::new(), 0, Some(0)));
        if entry.0.bytes != rep.bytes || entry.0.cpu_us != rep.cpu_us {
            entry.0.bytes = None;
            entry.0.cpu_us = None;
        }
        entry
            .1
            .insert((r.finding.location.file.as_str(), r.finding.location.line));
        entry.2 += 1;
        entry.3 = entry.3.zip(r.refactor_scope).map(|(a, b)| a + b);
    }
    let mut out: Vec<PlanRow> = rows
        .into_iter()
        .map(
            |((from, _, tier), (replacement, sites, findings, scope))| PlanRow {
                from,
                tier,
                replacement,
                sites: sites.len(),
                findings,
                refactor_scope: scope,
            },
        )
        .collect();
    out.sort_by(|a, b| {
        a.tier
            .cmp(&b.tier)
            .then(b.sites.cmp(&a.sites))
            .then_with(|| a.from.cmp(&b.from))
    });
    out
}

pub(crate) fn known_names() -> BTreeSet<String> {
    let t = table();
    t.scheme
        .iter()
        .flat_map(|s| [s.name.clone(), s.family.clone()])
        .chain(t.classical.iter().map(|c| c.name.clone()))
        .chain(t.upgrade.iter().flat_map(|u| {
            u.from
                .iter()
                .cloned()
                .chain(u.to.iter().map(|x| x.name.clone()))
        }))
        .collect()
}

pub fn default_level() -> u8 {
    table().default_level
}

fn bytes_text(r: &Replacement) -> String {
    match r.bytes {
        Some((before, after)) => format!(
            "{before} -> {after} B{}",
            if r.exceeds_mtu() {
                " (over one MTU)"
            } else {
                ""
            }
        ),
        None => "size not established".to_string(),
    }
}

fn cpu_text(r: &Replacement) -> String {
    match r.cpu_us {
        Some((before, after)) => format!(
            "{} -> {} per exchange ({:.1}x)",
            duration(before),
            duration(after),
            after / before
        ),
        None if r.role == Role::Symmetric => "not timed (symmetric)".to_string(),
        None => "CPU not established".to_string(),
    }
}

fn duration(us: f64) -> String {
    if us >= 1_000_000.0 {
        format!("{:.2} s", us / 1_000_000.0)
    } else if us >= 1_000.0 {
        format!("{:.2} ms", us / 1_000.0)
    } else {
        format!("{us:.0} us")
    }
}

pub fn render_text(plan: &[PlanRow], unplanned: &[(String, u8, usize)]) -> String {
    if plan.is_empty() && unplanned.is_empty() {
        return String::new();
    }
    let mut out = format!(
        "Migration plan (NIST category {} unless a profile or a stronger key raises it; \
         CPU timed on {}):\n",
        default_level(),
        speed_provenance()
    );
    for row in plan {
        let r = &row.replacement;
        out.push_str(&format!(
            "  {} ({}, Tier {}, {} site{}) -> {} [{}]; {}; {}\n",
            row.from,
            r.role.label(),
            row.tier,
            row.sites,
            if row.sites == 1 { "" } else { "s" },
            r.to,
            r.standard,
            bytes_text(r),
            cpu_text(r),
        ));
    }
    for (algorithm, tier, sites) in unplanned {
        out.push_str(&format!("  {}\n", unplanned_line(algorithm, *tier, *sites)));
    }
    out
}

pub fn render_html(plan: &[PlanRow], unplanned: &[(String, u8, usize)]) -> String {
    let esc = crate::xml::escape;
    let unplanned_html: String = unplanned
        .iter()
        .map(|(algorithm, tier, sites)| {
            format!(
                "<p class=sub>{}</p>",
                esc(&unplanned_line(algorithm, *tier, *sites))
            )
        })
        .collect();
    if plan.is_empty() && !unplanned.is_empty() {
        return unplanned_html;
    }
    if plan.is_empty() {
        return "<p class=sub>Nothing to migrate: no finding needs a replacement at the \
                target level.</p>"
            .to_string();
    }
    let rows: String = plan
        .iter()
        .map(|row| {
            let r = &row.replacement;
            let mut extra = Vec::new();
            if let Some(alt) = &r.alternative {
                extra.push(format!("alternative: {}", esc(alt)));
            }
            if let Some(h) = &r.hybrid {
                extra.push(format!("hybrid: {}", esc(h)));
            }
            if let Some(n) = r.note {
                extra.push(esc(n));
            }
            format!(
                "<tr><td class=rule>{from}</td><td class=\"tier t{tier}\">T{tier}</td>\
                 <td>{role}</td><td class=n>{sites}</td>\
                 <td><b>{to}</b> <span class=std>{std}</span>{extra}</td>\
                 <td class=calc>{bytes}</td><td class=calc>{cpu}</td>\
                 <td class=n>{scope}</td></tr>",
                from = esc(&row.from),
                tier = row.tier,
                role = r.role.label(),
                sites = row.sites,
                to = esc(&r.to),
                std = esc(&r.standard),
                extra = extra
                    .iter()
                    .map(|e| format!("<div class=res>{e}</div>"))
                    .collect::<String>(),
                bytes = bytes_text(r).replace("->", "&rarr;"),
                cpu = cpu_text(r).replace("->", "&rarr;"),
                scope = row
                    .refactor_scope
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "&mdash;".into()),
            )
        })
        .collect();
    format!(
        "<p class=sub>Each row is every finding that moves from one algorithm to one \
         replacement. Parameter sets target NIST category {level} &mdash; this project's \
         default &mdash; unless a <code>--profile</code> floor or a stronger classical key \
         raises it. <b>Bytes</b> are what one exchange puts on the wire (public key plus \
         signature, or both halves of a key exchange), from FIPS 203/204/205. <b>CPU</b> is \
         sign + verify for a signature, and both sides of an ephemeral key exchange for key \
         establishment, timed once with the RustCrypto implementations on {machine} \
         (<code>data/pqc_speed.json</code>) &mdash; that machine's figures for those crates, \
         not a property of the algorithms. Protocol impact and infrastructure are not \
         populated: they need deployment facts the tool does not have.</p>\
         <table><tr><th>From</th><th>Tier</th><th>Use</th><th>Sites</th>\
         <th>Replace with</th><th>Bytes per exchange</th><th>CPU per exchange</th>\
         <th>Scope</th></tr>{rows}</table>{unplanned_html}",
        level = default_level(),
        machine = crate::xml::escape(&speed_provenance()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpg_core::SourceLoc;

    fn finding(rule: &str, class: AlgorithmClass, status: QvStatus, sig: &str) -> Finding {
        Finding {
            rule_id: rule.into(),
            node_id: 1,
            algorithm_class: class,
            qv_status: status,
            location: SourceLoc::new("src/lib.rs", 1),
            contextual_signature: sig.into(),
            taint_chain: Vec::new(),
            taint_nodes: Vec::new(),
            key_size: None,
            via: Vec::new(),
            parameter_set: None,
            with: Vec::new(),
        }
    }

    fn advise(f: &Finding, profile: Option<&str>) -> Advice {
        let rules = RuleSet::builtin();
        let name = crate::headline::algorithm_name(f, &rules);
        let profile = profile.map(|id| crate::load_profile(id).expect("a shipped profile"));
        recommend(f, &rules, &name, profile.as_ref())
    }

    fn floor_only(level: u8) -> crate::Profile {
        crate::parse_profile(&format!(
            "id = \"floor\"\nname = \"floor\"\nmin_quantum_security_level = {level}\n\
             [status]\nvulnerable = \"fail\"\ndeprecated = \"fail\"\n\
             resistant = \"pass\"\nunknown = \"review\"\n"
        ))
        .expect("valid profile")
    }

    fn replaced(a: Advice) -> Replacement {
        match a {
            Advice::Replace(r) => r,
            other => panic!("expected a replacement, got {other:?}"),
        }
    }

    #[test]
    fn the_shipped_table_parses_and_every_family_has_sets() {
        let t = table();
        for family in ["ML-KEM", "ML-DSA", "SLH-DSA"] {
            assert!(t.scheme.iter().any(|s| s.family == family), "{family}");
        }
        assert_eq!(t.default_level, 3);
    }

    #[test]
    fn sizes_match_the_standards() {
        let s = |n: &str| table().scheme.iter().find(|s| s.name == n).unwrap();
        assert_eq!(
            (s("ML-DSA-65").public_key, s("ML-DSA-65").signature),
            (1952, Some(3309))
        );
        assert_eq!(
            (s("ML-KEM-768").public_key, s("ML-KEM-768").ciphertext),
            (1184, Some(1088))
        );
        assert_eq!(s("ML-KEM-1024").level, 5);
    }

    #[test]
    fn the_speed_table_covers_the_replacement_table() {
        for s in &table().scheme {
            let how = if s.signature.is_some() {
                Exchange::Signature
            } else {
                Exchange::Kem
            };
            assert!(
                exchange_us(&s.name, how).is_some_and(|us| us > 0.0),
                "{}",
                s.name
            );
        }
    }

    #[test]
    fn a_signature_goes_to_ml_dsa_with_slh_dsa_as_the_alternative() {
        let mut f = finding(
            "R-RSA-005",
            AlgorithmClass::Rsa,
            QvStatus::Vulnerable,
            "rsa::pkcs1v15::SigningKey::<D>::new",
        );
        f.key_size = Some(2048);
        let r = replaced(advise(&f, None));
        assert_eq!(
            (r.role, r.to.as_str(), r.standard.as_str()),
            (Role::Signature, "ML-DSA-65", "FIPS 204")
        );
        assert_eq!(r.bytes, Some((512, 1952 + 3309)));
        assert!(r.exceeds_mtu());
        let (before, after) = r.cpu_us.expect("RSA-2048 and ML-DSA-65 are both timed");
        assert!(before > 0.0 && after > 0.0);
        assert!(r.alternative.unwrap().starts_with("SLH-DSA-SHA2-192s"));
    }

    #[test]
    fn x25519_goes_to_ml_kem_and_names_the_hybrid() {
        let f = finding(
            "R-X25519-001",
            AlgorithmClass::EcdhX25519,
            QvStatus::Vulnerable,
            "x25519_dalek::StaticSecret::random_from_rng",
        );
        let r = replaced(advise(&f, None));
        assert_eq!(
            (r.role, r.to.as_str()),
            (Role::KeyEstablishment, "ML-KEM-768")
        );
        assert_eq!(r.bytes, Some((64, 1184 + 1088)));
        assert!(r.cpu_us.is_some(), "X25519 and ML-KEM-768 are both timed");
        assert!(r.hybrid.unwrap().contains("X25519MLKEM768"));
    }

    #[test]
    fn a_profile_floor_raises_the_parameter_set() {
        let f = finding(
            "R-X25519-001",
            AlgorithmClass::EcdhX25519,
            QvStatus::Vulnerable,
            "x25519_dalek::StaticSecret::random_from_rng",
        );
        assert_eq!(replaced(advise(&f, Some("cnsa-2.0"))).to, "ML-KEM-1024");
    }

    #[test]
    fn a_p384_key_is_not_downgraded() {
        let f = finding(
            "R-ECDSA-001",
            AlgorithmClass::Ecdsa,
            QvStatus::Vulnerable,
            "p384::ecdsa::SigningKey::random",
        );
        let r = replaced(advise(&f, None));
        assert_eq!(r.to, "ML-DSA-65");
        assert_eq!(r.bytes, Some((192, 1952 + 3309)));
    }

    #[test]
    fn an_rsa_key_of_unknown_use_gets_both_options() {
        let f = finding(
            "R-RSA-001",
            AlgorithmClass::Rsa,
            QvStatus::Vulnerable,
            "rsa::RsaPrivateKey::new",
        );
        let r = replaced(advise(&f, None));
        assert_eq!(r.role, Role::NotEstablished);
        assert_eq!(r.to, "ML-DSA-65 or ML-KEM-768");
        assert!(r.note.is_some());
    }

    #[test]
    fn a_bare_curve_key_is_not_assumed_to_sign() {
        let f = finding(
            "R-ECDSA-999",
            AlgorithmClass::Ecdsa,
            QvStatus::Vulnerable,
            "p256::elliptic_curve::SecretKey::<C>::public_key",
        );
        let r = replaced(advise(&f, None));
        assert_eq!(r.role, Role::NotEstablished);
        assert_eq!(r.to, "ML-DSA-65 or ML-KEM-768");
    }

    #[test]
    fn an_unresolved_algorithm_gets_no_recommendation() {
        let f = finding(
            "R-SIG-999",
            AlgorithmClass::Unknown,
            QvStatus::Unknown,
            "x::sign",
        );
        assert!(matches!(advise(&f, None), Advice::Resolve(_)));
    }

    #[test]
    fn tier2_is_replaced_within_its_kind() {
        let aes = finding(
            "R-AES-002",
            AlgorithmClass::Unknown,
            QvStatus::Deprecated,
            "aes::Aes128",
        );
        assert_eq!(replaced(advise(&aes, None)).to, "AES-256");
        let sha1 = finding(
            "R-SHA1-001",
            AlgorithmClass::Hash,
            QvStatus::Deprecated,
            "sha1::Sha1",
        );
        assert_eq!(replaced(advise(&sha1, None)).to, "SHA-256");
        assert_eq!(replaced(advise(&sha1, Some("cnsa-2.0"))).to, "SHA-384");
        let rules = RuleSet::builtin();
        let floor = floor_only(5);
        assert_eq!(
            replaced(recommend(&sha1, &rules, "SHA-1", Some(&floor))).to,
            "SHA-512"
        );
    }

    #[test]
    fn a_resistant_algorithm_is_kept_unless_the_profile_asks_for_more() {
        let kem = finding(
            "R-MLKEM-001",
            AlgorithmClass::Kem,
            QvStatus::Resistant,
            "ml_kem::MlKem768",
        );
        assert!(matches!(advise(&kem, None), Advice::Keep(_)));
        let sha = finding(
            "R-SHA2-001",
            AlgorithmClass::Hash,
            QvStatus::Resistant,
            "sha2::Sha256",
        );
        assert_eq!(replaced(advise(&sha, Some("cnsa-2.0"))).to, "SHA-384");
        let sha384 = finding(
            "R-SHA2-002",
            AlgorithmClass::Hash,
            QvStatus::Resistant,
            "sha2::Sha384",
        );
        assert!(matches!(advise(&sha384, Some("cnsa-2.0")), Advice::Keep(_)));
    }

    fn of_rule(id: &str) -> Finding {
        let rules = RuleSet::builtin();
        let rule = rules
            .rules
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("no rule {id}"));
        finding(id, rule.algorithm_class, rule.qv_status, "test")
    }

    #[test]
    fn every_profile_verdict_matches_the_advice() {
        let rules = RuleSet::builtin();
        let mut checked = 0;
        for profile in crate::builtin_profiles() {
            for rule in &rules.rules {
                let sets = std::iter::once(None).chain(
                    rule.parameter_sets
                        .iter()
                        .map(|s| Some(s.identifier.clone())),
                );
                for set in sets {
                    let mut f = finding(&rule.id, rule.algorithm_class, rule.qv_status, "test");
                    f.parameter_set = set;
                    let name = crate::headline::algorithm_name(&f, &rules);
                    let level = crate::quantum_security_level(&f, &rules);
                    let verdict = profile.judge_named(&f, level, &name);
                    let advice = recommend(&f, &rules, &name, Some(&profile));
                    let what = format!(
                        "{} {} ({name}) under {}",
                        rule.id,
                        f.parameter_set.as_deref().unwrap_or("-"),
                        profile.id
                    );
                    match (verdict, &advice) {
                        (crate::Verdict::Pass, Advice::Keep(_)) => {}
                        (crate::Verdict::Pass, other) => panic!("{what}: passes, but {other:?}"),
                        (crate::Verdict::Fail, Advice::Replace(r)) => {
                            for to in r.to.split(" or ") {
                                let level = level_of(to).unwrap_or(r.target_level);
                                assert!(
                                    profile.accepts(to, level),
                                    "{what}: replaced by {to}, which the profile does not accept"
                                );
                            }
                        }
                        (crate::Verdict::Fail, Advice::Unplanned(_)) => {}
                        (crate::Verdict::Fail, other) => panic!("{what}: fails, but {other:?}"),
                        (crate::Verdict::Review, _) => {}
                    }
                    checked += 1;
                }
            }
        }
        assert!(checked > 200, "only {checked} combinations");
    }

    #[test]
    fn every_failed_hash_or_cipher_has_a_replacement() {
        let rules = RuleSet::builtin();
        let mut unplanned = Vec::new();
        for profile in crate::builtin_profiles() {
            for rule in rules.rules.iter().filter(|r| {
                matches!(
                    r.algorithm_class,
                    AlgorithmClass::Hash | AlgorithmClass::Symmetric | AlgorithmClass::Aead
                ) && r.qv_status != QvStatus::Unknown
            }) {
                let sets = std::iter::once(None).chain(
                    rule.parameter_sets
                        .iter()
                        .map(|s| Some(s.identifier.clone())),
                );
                for set in sets {
                    let mut f = finding(&rule.id, rule.algorithm_class, rule.qv_status, "test");
                    f.parameter_set = set;
                    let name = crate::headline::algorithm_name(&f, &rules);
                    let level = crate::quantum_security_level(&f, &rules);
                    if profile.judge_named(&f, level, &name) != crate::Verdict::Fail {
                        continue;
                    }
                    if let Advice::Unplanned(_) = recommend(&f, &rules, &name, Some(&profile)) {
                        unplanned.push(format!("{} ({name}) under {}", rule.id, profile.id));
                    }
                }
            }
        }
        assert!(
            unplanned.is_empty(),
            "no replacement:\n  {}",
            unplanned.join("\n  ")
        );
    }

    #[test]
    fn every_named_vulnerable_scheme_has_a_size_and_cpu_cost() {
        let rules = RuleSet::builtin();
        let mut uncosted = Vec::new();
        let selector = |r: &&qr_rules::Rule| {
            r.algorithm_class == AlgorithmClass::Unknown
                && r.match_spec.signatures.is_empty()
                && r.match_spec.crates.is_empty()
        };
        for rule in rules
            .rules
            .iter()
            .filter(|r| r.qv_status == QvStatus::Vulnerable && !selector(r))
        {
            let declared = rule
                .crypto
                .parameter_set_identifier
                .iter()
                .filter(|id| !id.chars().all(|c| c.is_ascii_digit()))
                .map(|_| None);
            let sets = rule
                .parameter_sets
                .iter()
                .map(|s| Some(s.identifier.clone()));
            for set in declared.chain(sets) {
                let mut f = finding(&rule.id, rule.algorithm_class, rule.qv_status, "test");
                f.parameter_set = set;
                let name = crate::headline::algorithm_name(&f, &rules);
                if let Advice::Replace(r) = recommend(&f, &rules, &name, None) {
                    if r.bytes.is_none() || r.cpu_us.is_none() {
                        uncosted.push(format!("{} ({name})", rule.id));
                    }
                }
            }
        }
        let operation = |set: &str| match set {
            s if s.starts_with("ECDH-") || s == "X25519" => "R-RING-004",
            s if s.starts_with("ECDSA-") => "R-RING-002",
            "Ed25519" => "R-RING-003",
            "RSA" => "R-RING-001",
            other => panic!("no ring operation rule for the constant {other}"),
        };
        for rule in rules
            .rules
            .iter()
            .filter(|r| r.qv_status == QvStatus::Vulnerable && selector(r))
        {
            for set in &rule.parameter_sets {
                if set.identifier == "RSA" {
                    continue;
                }
                let lead = of_rule(operation(&set.identifier));
                let mut row = finding(
                    &lead.rule_id,
                    lead.algorithm_class,
                    QvStatus::Vulnerable,
                    "ring::test",
                );
                row.with = vec![cpg_core::Part {
                    rule_id: rule.id.clone(),
                    signature: "ring::test".into(),
                    qv_status: QvStatus::Vulnerable,
                    parameter_set: Some(set.identifier.clone()),
                }];
                let name = crate::headline::algorithm_name(&row, &rules);
                if let Advice::Replace(r) = recommend(&row, &rules, &name, None) {
                    if r.bytes.is_none() || r.cpu_us.is_none() {
                        uncosted.push(format!("{} {} ({name})", rule.id, set.identifier));
                    }
                }
            }
        }
        assert!(
            uncosted.is_empty(),
            "no costs:\n  {}",
            uncosted.join("\n  ")
        );
    }

    #[test]
    fn every_curve_the_rules_match_is_costed_in_both_roles() {
        let rules = RuleSet::builtin();
        let fallback = rules
            .rules
            .iter()
            .find(|r| r.id == "R-EC-999")
            .expect("R-EC-999");
        let generic = ["elliptic_curve", "primeorder"];
        let mut uncosted = Vec::new();
        for krate in fallback
            .match_spec
            .crates
            .iter()
            .filter(|c| !generic.contains(&c.as_str()))
        {
            for (rule, class, path) in [
                (
                    "R-ECDSA-001",
                    AlgorithmClass::Ecdsa,
                    "ecdsa::SigningKey::random",
                ),
                (
                    "R-ECDH-001",
                    AlgorithmClass::Ecdh,
                    "ecdh::EphemeralSecret::random",
                ),
            ] {
                let sig = format!("{krate}::{path}");
                let r = replaced(advise(
                    &finding(rule, class, QvStatus::Vulnerable, &sig),
                    None,
                ));
                if r.bytes.is_none() || r.cpu_us.is_none() {
                    uncosted.push(format!("{sig}: bytes {:?}, cpu {:?}", r.bytes, r.cpu_us));
                }
            }
        }
        assert!(
            uncosted.is_empty(),
            "no costs:\n  {}",
            uncosted.join("\n  ")
        );
    }

    #[test]
    fn every_classical_row_is_timed() {
        let mut untimed = Vec::new();
        for c in &table().classical {
            let mut needs = Vec::new();
            if c.signature.is_some() {
                needs.push(("signature", Exchange::Signature));
            }
            if c.ciphertext.is_some() {
                needs.push(("key transport", Exchange::KeyTransport));
            }
            if needs.is_empty() {
                needs.push(("Diffie-Hellman", Exchange::DiffieHellman));
            }
            for (label, how) in needs {
                if !exchange_us(&c.name, how).is_some_and(|us| us > 0.0) {
                    untimed.push(format!("{} ({label})", c.name));
                }
            }
        }
        assert!(untimed.is_empty(), "untimed:\n  {}", untimed.join("\n  "));
    }

    #[test]
    fn a_ring_key_exchange_row_is_costed_by_its_constant() {
        let mut row = finding(
            "R-RING-004",
            AlgorithmClass::Ecdh,
            QvStatus::Vulnerable,
            "ring::agreement::EphemeralPrivateKey::generate",
        );
        row.with = vec![cpg_core::Part {
            rule_id: "R-RING-ALG-001".into(),
            signature: "ring::agreement::X25519".into(),
            qv_status: QvStatus::Vulnerable,
            parameter_set: Some("X25519".into()),
        }];
        assert_eq!(
            crate::headline::algorithm_name(&row, &RuleSet::builtin()),
            "X25519"
        );
        let replacement = replaced(advise(&row, None));
        assert!(
            replacement.bytes.is_some() && replacement.cpu_us.is_some(),
            "{replacement:?}"
        );
    }

    #[test]
    fn cnsa_replaces_chacha20_with_aes_256() {
        assert_eq!(
            replaced(advise(&of_rule("R-CHACHA-002"), Some("cnsa-2.0"))).to,
            "AES-256"
        );
    }

    #[test]
    fn cnsa_replaces_camellia_256_with_aes_256() {
        assert_eq!(
            replaced(advise(&of_rule("R-CAMELLIA-001"), Some("cnsa-2.0"))).to,
            "AES-256"
        );
    }

    #[test]
    fn cnsa_replaces_sha3_with_sha_384() {
        assert_eq!(
            replaced(advise(&of_rule("R-SHA3-001"), Some("cnsa-2.0"))).to,
            "SHA-384"
        );
    }

    #[test]
    fn ir8547_keeps_aes_128_and_aes_192() {
        for id in ["R-AES-002", "R-AES-003"] {
            let advice = advise(&of_rule(id), Some("nist-ir-8547"));
            assert!(matches!(advice, Advice::Keep(_)), "{id}: {advice:?}");
        }
    }

    #[test]
    fn a_failure_with_no_accepted_replacement_is_unplanned() {
        let aes_only = crate::parse_profile(
            "id = \"aes-only\"\nname = \"AES only\"\nclosed = true\nallow = [\"AES-256\"]\n\
             [status]\nvulnerable = \"fail\"\ndeprecated = \"fail\"\n\
             resistant = \"pass\"\nunknown = \"review\"\n",
        )
        .expect("valid profile");
        let rules = RuleSet::builtin();
        let advice = recommend(&of_rule("R-SHA3-001"), &rules, "SHA-3", Some(&aes_only));
        assert!(matches!(advice, Advice::Unplanned(_)), "{advice:?}");
    }

    fn scored(f: &Finding) -> crate::ScoredFinding<'_> {
        scored_at(f, &[])
    }

    fn scored_at<'a>(f: &'a Finding, type_args: &[&str]) -> crate::ScoredFinding<'a> {
        let rules = RuleSet::builtin();
        let algorithm = crate::headline::algorithm_name(f, &rules);
        let types: Vec<String> = type_args.iter().map(|t| t.to_string()).collect();
        let advice = recommend_at(f, &types, &rules, &algorithm, None);
        crate::ScoredFinding {
            finding: f,
            tier: 1,
            risk: 0.0,
            severity: 0.0,
            blast_factor: 0.0,
            criticality: 0.0,
            blast_radius: 0,
            conservative: false,
            resolves_to: None,
            call_symbol: None,
            refactor_scope: None,
            chain_absence: None,
            algorithm,
            advice,
            verdict: None,
            parts: String::new(),
        }
    }

    #[test]
    fn the_curve_is_the_type_a_call_names_over_the_path_it_came_through() {
        let bytes = |sig: &str| {
            replaced(advise(
                &finding(
                    "R-ECDH-001",
                    AlgorithmClass::Ecdh,
                    QvStatus::Vulnerable,
                    sig,
                ),
                None,
            ))
            .bytes
        };
        let (p256, p384) = (Some((128, 2272)), Some((192, 2272)));
        assert_eq!(bytes("p384::ecdh::diffie_hellman::<p256::NistP256>"), p256);
        assert_eq!(
            bytes("elliptic_curve::ecdh::EphemeralSecret<NistP384>::random"),
            p384
        );
        assert_eq!(bytes("p384::ecdh::EphemeralSecret::random"), p384);
        assert_eq!(bytes("f::<p256::NistP256, p384::NistP384>"), None);
        assert_eq!(bytes("p256::f::<p384::g>"), None);
    }

    #[test]
    fn the_curve_is_read_from_the_call_s_type_arguments_first() {
        let rules = RuleSet::builtin();
        let at = |sig: &str, types: &[&str]| {
            let f = finding(
                "R-ECDH-001",
                AlgorithmClass::Ecdh,
                QvStatus::Vulnerable,
                sig,
            );
            let types: Vec<String> = types.iter().map(|t| t.to_string()).collect();
            let name = crate::headline::algorithm_name(&f, &rules);
            replaced(recommend_at(&f, &types, &rules, &name, None))
        };
        let (diffie_hellman, scalar) = (
            "p256::ecdh::diffie_hellman",
            "ecdsa::elliptic_curve::NonZeroScalar",
        );
        let r = at(diffie_hellman, &["p384::NistP384", scalar]);
        assert_eq!((r.to.as_str(), r.bytes), ("ML-KEM-768", Some((192, 2272))));
        let r = at(diffie_hellman, &["p521::NistP521", scalar]);
        assert_eq!((r.to.as_str(), r.bytes), ("ML-KEM-1024", Some((264, 3136))));
        let generic = "ecdsa::elliptic_curve::ecdh::EphemeralSecret::<C>::random";
        assert_eq!(at(generic, &["p384::NistP384"]).bytes, Some((192, 2272)));
        assert_eq!(at(diffie_hellman, &[scalar]).bytes, Some((128, 2272)));
        assert_eq!(at(generic, &[]).bytes, None);
        let two = ["p256::NistP256", "p384::NistP384"];
        assert_eq!(at(diffie_hellman, &two).bytes, None);
    }

    #[test]
    fn a_plan_row_is_one_classical_scheme() {
        let site = |line: u32, sig: &str| {
            let mut f = finding(
                "R-ECDH-001",
                AlgorithmClass::Ecdh,
                QvStatus::Vulnerable,
                sig,
            );
            f.location = SourceLoc::new("src/lib.rs", line);
            f
        };
        let generic = "elliptic_curve::ecdh::EphemeralSecret::<C>::random";
        let (p256, p384, unknown) = (
            site(1, "p256::ecdh::EphemeralSecret::random"),
            site(2, generic),
            site(3, generic),
        );
        let rows = plan(&[
            scored(&p256),
            scored_at(&p384, &["p384::NistP384"]),
            scored(&unknown),
        ]);
        type Row = (String, Option<(u32, u32)>, bool);
        let mut got: Vec<Row> = rows
            .iter()
            .map(|r| {
                let rep = &r.replacement;
                (r.from.clone(), rep.bytes, rep.cpu_us.is_some())
            })
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("ECDH".to_string(), None, false),
                ("ECDH-P256".to_string(), Some((128, 2272)), true),
                ("ECDH-P384".to_string(), Some((192, 2272)), true),
            ]
        );
    }

    #[test]
    fn a_plan_row_whose_sites_cost_differently_states_no_one_cost() {
        let sig = "p256::ecdh::EphemeralSecret::random";
        let a = finding(
            "R-ECDH-001",
            AlgorithmClass::Ecdh,
            QvStatus::Vulnerable,
            sig,
        );
        let mut b = a.clone();
        b.location = SourceLoc::new("src/lib.rs", 2);
        let slower = || {
            let mut row = scored(&b);
            match &mut row.advice {
                Advice::Replace(r) => r.cpu_us = r.cpu_us.map(|(x, y)| (2.0 * x, y)),
                other => panic!("{other:?}"),
            }
            row
        };
        for rows in [plan(&[scored(&a), slower()]), plan(&[slower(), scored(&a)])] {
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert!(rows[0].replacement.cpu_us.is_none(), "{rows:?}");
        }
    }

    #[test]
    fn strengthening_tries_every_set_and_never_goes_down() {
        let rules = RuleSet::builtin();
        let mut kem = finding(
            "R-MLKEM-001",
            AlgorithmClass::Kem,
            QvStatus::Resistant,
            "test",
        );
        kem.parameter_set = Some("768".into());
        let name = crate::headline::algorithm_name(&kem, &rules);
        assert_eq!(name, "ML-KEM-768");
        let profile = |body: &str| {
            crate::parse_profile(&format!(
                "id = \"t\"\nname = \"t\"\n{body}\n[status]\nvulnerable = \"fail\"\n\
                 deprecated = \"fail\"\nresistant = \"pass\"\nunknown = \"review\"\n"
            ))
            .expect("valid profile")
        };
        let closed = profile("closed = true\nallow = [\"ML-KEM-1024\"]");
        let to = |p: &crate::Profile| match recommend(&kem, &rules, &name, Some(p)) {
            Advice::Replace(r) => r.to,
            other => format!("{other:?}"),
        };
        assert_eq!(to(&closed), "ML-KEM-1024");
        let failed = crate::parse_profile(
            "id = \"t\"\nname = \"t\"\n[status]\nvulnerable = \"fail\"\n\
             deprecated = \"fail\"\nresistant = \"pass\"\nunknown = \"review\"\n\
             [verdicts]\n\"ML-KEM-768\" = \"fail\"\n",
        )
        .expect("valid profile");
        assert_eq!(to(&failed), "ML-KEM-1024");
    }

    #[test]
    fn x448_and_ed448_have_sizes() {
        let x448 = replaced(advise(&of_rule("R-X448-001"), None));
        assert_eq!(
            (x448.to.as_str(), x448.bytes),
            ("ML-KEM-768", Some((112, 2272)))
        );
        let ed448 = replaced(advise(&of_rule("R-ED448-001"), None));
        assert_eq!(
            (ed448.to.as_str(), ed448.bytes),
            ("ML-DSA-65", Some((171, 5261)))
        );
    }

    #[test]
    fn without_a_profile_the_advice_is_unchanged() {
        for id in ["R-CHACHA-002", "R-CAMELLIA-001", "R-SHA3-001"] {
            let advice = advise(&of_rule(id), None);
            assert!(matches!(advice, Advice::Keep(_)), "{id}: {advice:?}");
        }
        assert_eq!(replaced(advise(&of_rule("R-AES-002"), None)).to, "AES-256");
    }

    #[test]
    fn ecdh_is_key_establishment() {
        let f = finding(
            "R-TEST",
            AlgorithmClass::Ecdh,
            QvStatus::Vulnerable,
            "p256::ecdh::diffie_hellman",
        );
        assert_eq!(role_of(&f, &RuleSet::builtin()), Role::KeyEstablishment);
    }

    #[test]
    fn dsa_is_a_signature() {
        let f = finding(
            "R-TEST",
            AlgorithmClass::Dsa,
            QvStatus::Vulnerable,
            "dsa::SigningKey::generate",
        );
        assert_eq!(role_of(&f, &RuleSet::builtin()), Role::Signature);
    }
}
