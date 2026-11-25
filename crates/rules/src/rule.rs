use std::sync::OnceLock;

use serde::Deserialize;

use cpg_core::{AlgorithmClass, ConstArg, CpgError, QvStatus};

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub description: String,
    pub algorithm_class: AlgorithmClass,
    pub qv_status: QvStatus,
    #[serde(default)]
    pub nist_tier: Option<String>,
    #[serde(rename = "match")]
    pub match_spec: MatchSpec,
    #[serde(default)]
    pub taint: TaintSpec,
    #[serde(default)]
    pub crypto: CryptoSpec,
    #[serde(default)]
    pub parameter: ParameterSpec,
    #[serde(default)]
    pub parameter_sets: Vec<ParameterSet>,
    #[serde(skip)]
    compiled: OnceLock<Compiled>,
}

#[derive(Debug, Clone, Default)]
struct Compiled {
    exclude: Vec<Vec<String>>,
    signatures: Vec<Vec<String>>,
    anchors: Vec<String>,
    type_names: Vec<Vec<String>>,
    sinks: Vec<Vec<String>>,
    parameter_sets: Vec<Vec<Vec<String>>>,
    parameter_set_calls: Vec<(Vec<String>, Vec<Vec<String>>)>,
}

fn split_signature(signature: &str) -> Vec<String> {
    signature
        .to_lowercase()
        .split("::")
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[derive(Debug, Clone)]
pub struct Prepared {
    segments: Vec<String>,
}

impl Prepared {
    pub fn new(symbol: &str) -> Self {
        let normalized = normalize_generics(symbol).to_lowercase();
        Self {
            segments: path_segments(&normalized)
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }
}

pub fn link_of(canonical: Option<&str>) -> Option<String> {
    canonical.and_then(link_name).map(str::to_lowercase)
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ParameterSpec {
    #[serde(default)]
    pub key_size_arg: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ParameterSet {
    pub identifier: String,
    pub name: String,
    #[serde(default)]
    pub nist_quantum_security_level: Option<u8>,
    #[serde(default)]
    pub type_names: Vec<String>,
    #[serde(default)]
    pub crates: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CryptoSpec {
    #[serde(default = "default_asset_type")]
    pub asset_type: String,
    #[serde(default = "default_unknown")]
    pub primitive: String,
    #[serde(default)]
    pub algorithm_family: Option<String>,
    #[serde(default)]
    pub crypto_functions: Vec<String>,
    #[serde(default)]
    pub oid: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub parameter_set_identifier: Option<String>,
    #[serde(default)]
    pub nist_quantum_security_level: Option<u8>,
}

impl Default for CryptoSpec {
    fn default() -> Self {
        Self {
            asset_type: default_asset_type(),
            primitive: default_unknown(),
            algorithm_family: None,
            crypto_functions: Vec::new(),
            oid: None,
            mode: None,
            parameter_set_identifier: None,
            nist_quantum_security_level: None,
        }
    }
}

fn default_asset_type() -> String {
    "algorithm".to_string()
}

fn default_unknown() -> String {
    "unknown".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TaintSpec {
    #[serde(default)]
    pub sinks: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MatchSpec {
    #[serde(default, rename = "crate")]
    pub crate_name: Option<String>,
    #[serde(default)]
    pub crates: Vec<String>,
    #[serde(default)]
    pub signatures: Vec<String>,
    #[serde(default)]
    pub type_names: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl Rule {
    pub fn matches(&self, symbol: &str) -> bool {
        self.matches_call(symbol, None)
    }

    pub fn matches_call(&self, symbol: &str, canonical: Option<&str>) -> bool {
        self.matches_prepared(&Prepared::new(symbol), link_of(canonical).as_deref())
    }

    fn compiled(&self) -> &Compiled {
        self.compiled.get_or_init(|| {
            let m = &self.match_spec;
            Compiled {
                exclude: m.exclude.iter().map(|s| split_signature(s)).collect(),
                signatures: m.signatures.iter().map(|s| split_signature(s)).collect(),
                anchors: m
                    .crate_name
                    .iter()
                    .chain(m.crates.iter())
                    .map(|name| name.to_lowercase())
                    .collect(),
                type_names: m.type_names.iter().map(|s| split_signature(s)).collect(),
                sinks: self
                    .taint
                    .sinks
                    .iter()
                    .map(|s| split_signature(s))
                    .collect(),
                parameter_sets: self
                    .parameter_sets
                    .iter()
                    .map(|set| set.type_names.iter().map(|t| split_signature(t)).collect())
                    .collect(),
                parameter_set_calls: self
                    .parameter_sets
                    .iter()
                    .map(|set| {
                        (
                            set.crates.iter().map(|c| c.to_lowercase()).collect(),
                            set.paths.iter().map(|p| split_signature(p)).collect(),
                        )
                    })
                    .collect(),
            }
        })
    }

    pub fn matches_prepared(&self, subject: &Prepared, link: Option<&str>) -> bool {
        let c = self.compiled();
        if c.exclude
            .iter()
            .any(|w| segments_match(&subject.segments, w))
        {
            return false;
        }
        if !self.match_spec.signatures.is_empty() {
            return c
                .signatures
                .iter()
                .any(|w| segments_match(&subject.segments, w));
        }
        c.anchors.iter().any(|needle| {
            crate_match(&subject.segments, needle) || link.is_some_and(|link| extends(link, needle))
        })
    }

    pub fn parameter_set_of(&self, type_args: &[String]) -> Option<&ParameterSet> {
        if self.parameter_sets.is_empty() {
            return None;
        }
        let prepared: Vec<Prepared> = type_args.iter().map(|t| Prepared::new(t)).collect();
        let mut named = self
            .compiled()
            .parameter_sets
            .iter()
            .zip(&self.parameter_sets)
            .filter(|(wanted, _)| {
                prepared
                    .iter()
                    .any(|arg| wanted.iter().any(|w| segments_match(&arg.segments, w)))
            })
            .map(|(_, set)| set);
        let first = named.next()?;
        named.next().is_none().then_some(first)
    }

    pub fn parameter_sets_named<'a>(
        &'a self,
        args: &'a [Prepared],
    ) -> impl Iterator<Item = &'a ParameterSet> + 'a {
        self.compiled()
            .parameter_sets
            .iter()
            .zip(&self.parameter_sets)
            .filter(move |(wanted, _)| {
                args.iter()
                    .any(|arg| wanted.iter().any(|w| segments_match(&arg.segments, w)))
            })
            .map(|(_, set)| set)
    }

    pub fn parameter_set_for(
        &self,
        type_args: &[String],
        call: &Prepared,
    ) -> Option<&ParameterSet> {
        if let Some(set) = self.parameter_set_of(type_args) {
            return Some(set);
        }
        let mut named = self
            .compiled()
            .parameter_set_calls
            .iter()
            .zip(&self.parameter_sets)
            .filter(|((crates, paths), _)| {
                crates.iter().any(|c| crate_match(&call.segments, c))
                    || paths.iter().any(|p| contains_in_order(&call.segments, p))
            })
            .map(|(_, set)| set);
        let first = named.next()?;
        named.next().is_none().then_some(first)
    }

    pub fn parameter_set(&self, identifier: &str) -> Option<&ParameterSet> {
        self.parameter_sets
            .iter()
            .find(|set| set.identifier == identifier)
    }

    pub fn matches_type(&self, type_arg: &str) -> bool {
        self.matches_type_prepared(&Prepared::new(type_arg))
    }

    pub fn matches_type_prepared(&self, type_arg: &Prepared) -> bool {
        if self.match_spec.type_names.is_empty() {
            return false;
        }
        self.compiled()
            .type_names
            .iter()
            .any(|w| segments_match(&type_arg.segments, w))
    }

    pub fn excludes(&self, subject: &Prepared) -> bool {
        self.compiled()
            .exclude
            .iter()
            .any(|w| segments_match(&subject.segments, w))
    }

    pub fn matches_resolved(&self, instance: &Prepared, self_ty: &Prepared) -> bool {
        let c = self.compiled();
        if c.exclude
            .iter()
            .any(|w| segments_match(&instance.segments, w))
        {
            return false;
        }
        c.signatures
            .iter()
            .any(|w| segments_match(&instance.segments, w))
            || c.type_names
                .iter()
                .any(|w| segments_match(&self_ty.segments, w))
    }

    pub fn agrees_with(&self, call: &ResolvedCall) -> bool {
        if self.matches_resolved(&call.instance, &call.self_ty) {
            return true;
        }
        let c = self.compiled();
        if !self.match_spec.signatures.is_empty() {
            return c
                .signatures
                .iter()
                .any(|w| segments_match(&call.trait_method.segments, w));
        }
        call.crates
            .iter()
            .any(|root| c.anchors.iter().any(|needle| extends(root, needle)))
    }

    pub fn key_size(&self, const_args: &[ConstArg]) -> Option<u32> {
        let index = self.parameter.key_size_arg?;
        let value = const_args.iter().find(|arg| arg.index == index)?.value;
        u32::try_from(value).ok()
    }

    pub fn match_depth(&self, signature: &str) -> usize {
        let normalized = normalize_generics(signature).to_lowercase();
        self.match_spec
            .signatures
            .iter()
            .chain(self.match_spec.type_names.iter())
            .filter(|candidate| signature_match(&normalized, &candidate.to_lowercase()))
            .map(|candidate| candidate.split("::").filter(|s| !s.is_empty()).count())
            .max()
            .unwrap_or(0)
    }

    pub fn is_specific(&self) -> bool {
        !self.match_spec.signatures.is_empty()
    }

    pub fn anchors_crate(&self, krate: &str) -> bool {
        let krate = krate.to_lowercase();
        self.compiled()
            .anchors
            .iter()
            .any(|needle| extends(&krate, needle))
    }

    pub fn matches_by_signature(&self) -> bool {
        !self.match_spec.signatures.is_empty()
    }

    pub fn specificity(&self) -> u8 {
        if !self.match_spec.signatures.is_empty() {
            2
        } else if !self.match_spec.type_names.is_empty() {
            1
        } else {
            0
        }
    }

    pub fn is_sink(&self, symbol: &str) -> bool {
        self.is_sink_prepared(&Prepared::new(symbol))
    }

    pub fn is_sink_prepared(&self, subject: &Prepared) -> bool {
        if self.taint.sinks.is_empty() {
            return false;
        }
        self.compiled()
            .sinks
            .iter()
            .any(|w| segments_match(&subject.segments, w))
    }
}

pub fn parse_rule(text: &str) -> Result<Rule, CpgError> {
    toml::from_str(text).map_err(|e| CpgError::Extraction(format!("malformed rule: {e}")))
}

fn path_segments(symbol: &str) -> Vec<&str> {
    symbol
        .split("::")
        .map(|s| s.trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '_')))
        .map(strip_type_keyword)
        .filter(|s| !s.is_empty())
        .collect()
}

fn strip_type_keyword(segment: &str) -> &str {
    let unkeyed = ["dyn ", "impl "]
        .iter()
        .find_map(|kw| segment.strip_prefix(kw))
        .map(str::trim_start)
        .unwrap_or(segment);
    match unkeyed.find(" as ") {
        Some(pos) => unkeyed[..pos].trim_end(),
        None => unkeyed,
    }
}

fn crate_match(segments: &[String], needle: &str) -> bool {
    segments.first().is_some_and(|root| extends(root, needle))
}

fn extends(segment: &str, needle: &str) -> bool {
    segment
        .strip_prefix(needle)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('_'))
}

fn contains_in_order(segments: &[String], wanted: &[String]) -> bool {
    let mut remaining = wanted.iter().peekable();
    for segment in segments {
        if remaining.peek().is_some_and(|w| *w == segment) {
            remaining.next();
        }
    }
    !wanted.is_empty() && remaining.peek().is_none()
}

fn link_name(canonical: &str) -> Option<&str> {
    let trimmed = canonical.trim();
    let bare = !trimmed.is_empty() && !trimmed.contains("::") && !trimmed.contains('<');
    bare.then_some(trimmed)
}

fn signature_match(symbol: &str, signature: &str) -> bool {
    let symbol_segments = path_segments(symbol);
    let wanted: Vec<&str> = signature.split("::").filter(|s| !s.is_empty()).collect();
    segments_match(&symbol_segments, &wanted)
}

fn segments_match<A: AsRef<str>, B: AsRef<str>>(symbol_segments: &[A], wanted: &[B]) -> bool {
    let same = |a: &A, b: &B| a.as_ref() == b.as_ref();
    let (n, w) = (symbol_segments.len(), wanted.len());
    if w == 0 || w > n {
        return false;
    }
    let tail = &symbol_segments[n - w..];
    if tail.iter().zip(wanted).all(|(a, b)| same(a, b)) {
        return true;
    }
    if !same(&tail[w - 1], &wanted[w - 1]) {
        return false;
    }
    let mut remaining = wanted[..w - 1].iter().peekable();
    for segment in &symbol_segments[..n - 1] {
        if remaining.peek().is_some_and(|want| same(segment, want)) {
            remaining.next();
        }
    }
    remaining.peek().is_none()
}

fn normalize_generics(symbol: &str) -> String {
    let s = symbol.trim();
    let unwrapped = match s.strip_prefix('<') {
        Some(rest) => match matching_gt(rest) {
            Some(pos) => format!("{}{}", &rest[..pos], &rest[pos + 1..]),
            None => s.to_string(),
        },
        None => s.to_string(),
    };
    let mut out = String::with_capacity(unwrapped.len());
    let mut depth = 0usize;
    for c in unwrapped.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

fn matching_gt(s: &str) -> Option<usize> {
    let mut depth = 1usize;
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

pub fn qualified_self_type(symbol: &str) -> Option<&str> {
    let (self_ty, _) = split_qualified(symbol)?;
    (!self_ty.starts_with("dyn ")).then_some(self_ty)
}

fn split_qualified(symbol: &str) -> Option<(&str, String)> {
    let rest = symbol.trim().strip_prefix('<')?;
    let end = matching_gt(rest)?;
    let inner = &rest[..end];
    let mut depth = 0usize;
    for (i, c) in inner.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ' ' if depth == 0 && inner[i..].starts_with(" as ") => {
                let trait_rest = format!("{}{}", inner[i + 4..].trim(), &rest[end + 1..]);
                return Some((inner[..i].trim(), trait_rest));
            }
            _ => {}
        }
    }
    None
}

pub struct ResolvedCall {
    pub instance: Prepared,
    pub self_ty: Prepared,
    trait_method: Prepared,
    crates: Vec<String>,
}

const CORE_CONSTRUCTION: [&str; 5] = [
    "core::default::Default::default",
    "core::convert::From::from",
    "core::convert::Into::into",
    "core::convert::TryFrom::try_from",
    "core::convert::TryInto::try_into",
];

impl ResolvedCall {
    pub fn is_core_construction(&self) -> bool {
        CORE_CONSTRUCTION
            .iter()
            .any(|path| split_signature(path) == self.trait_method.segments)
            && self
                .self_ty
                .segments
                .last()
                .is_some_and(|last| !last.ends_with("error"))
    }

    pub fn self_root(&self) -> Option<&str> {
        self.self_ty.segments.first().map(String::as_str)
    }

    pub fn of(canonical: &str) -> Option<Self> {
        let (self_ty, trait_method) = split_qualified(canonical)?;
        if self_ty.starts_with("dyn ") {
            return None;
        }
        Some(Self {
            instance: Prepared::new(canonical),
            self_ty: Prepared::new(self_ty),
            trait_method: Prepared::new(&trait_method),
            crates: path_roots(canonical),
        })
    }
}

fn path_roots(symbol: &str) -> Vec<String> {
    let ident_start = |c: char| c.is_ascii_alphabetic() || c == '_';
    let mut roots: Vec<String> = symbol
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
        .filter_map(|run| {
            let (root, rest) = run.split_once("::")?;
            (root.starts_with(ident_start) && rest.starts_with(ident_start))
                .then(|| root.to_lowercase())
        })
        .collect();
    roots.sort();
    roots.dedup();
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_with(spec: MatchSpec) -> Rule {
        Rule {
            id: "R-TEST-001".into(),
            description: String::new(),
            algorithm_class: AlgorithmClass::Rsa,
            qv_status: QvStatus::Vulnerable,
            nist_tier: None,
            match_spec: spec,
            taint: TaintSpec::default(),
            crypto: CryptoSpec::default(),
            parameter: ParameterSpec::default(),
            parameter_sets: Vec::new(),
            compiled: OnceLock::new(),
        }
    }

    fn sink_rule(sinks: &[&str]) -> Rule {
        let mut rule = crate_rule("rsa");
        rule.taint = TaintSpec {
            sinks: sinks.iter().map(|s| s.to_string()).collect(),
        };
        rule
    }

    fn crate_rule(name: &str) -> Rule {
        rule_with(MatchSpec {
            crate_name: Some(name.into()),
            ..MatchSpec::default()
        })
    }

    fn signature_rule(signatures: &[&str]) -> Rule {
        rule_with(MatchSpec {
            crate_name: Some("rsa".into()),
            signatures: signatures.iter().map(|s| s.to_string()).collect(),
            ..MatchSpec::default()
        })
    }

    #[test]
    fn crate_match_is_root_anchored() {
        let rule = crate_rule("rsa");
        assert!(!rule.matches("demo_crate::sign_with_rsa"));
        assert!(rule.matches("rsa::RsaPrivateKey::new"));
        assert!(rule.matches("<rsa::pkcs1v15::Signature as x::Y>::to_bytes"));
        assert!(rule.matches("RSA_sign"));
    }

    #[test]
    fn a_module_named_like_a_crate_is_not_that_crate() {
        let rule = crate_rule("signature");
        for symbol in [
            "packet::signature::SignatureFields::typ",
            "packet::signature::SignatureFields::hash_algo",
            "packet::signature::subpacket::Subpacket::new",
            "packet::Signature::version",
        ] {
            assert!(!rule.matches(symbol), "{symbol} wrongly matched");
        }
        assert!(rule.matches("signature::Signer::sign"));
        assert!(rule.matches("<dyn signature::Signer>::sign"));
    }

    #[test]
    fn root_anchoring_holds_for_the_other_fallback_anchors() {
        assert!(!crate_rule("cipher").matches("openpgp::crypto::cipher::Mode::encrypt"));
        assert!(!crate_rule("digest").matches("openpgp::crypto::digest::Digest::update"));
        assert!(!crate_rule("rsa").matches("backend::rsa::sign_digest"));
        assert!(crate_rule("cipher").matches("cipher::BlockEncrypt::encrypt_block"));
        assert!(crate_rule("digest").matches("digest::Digest::digest"));
        assert!(crate_rule("rsa").matches("rsa::pkcs1v15::SigningKey::sign"));
    }

    #[test]
    fn a_foreign_callee_is_anchored_by_its_link_name() {
        let rule = crate_rule("rsa");
        assert!(!rule.matches("openssl_sys::RSA_generate_key_ex"));
        assert!(rule.matches_call(
            "openssl_sys::RSA_generate_key_ex",
            Some("RSA_generate_key_ex")
        ));
    }

    #[test]
    fn a_monomorphised_rust_path_is_not_an_anchor() {
        let rule = crate_rule("rsa");
        assert!(!rule.matches_call(
            "core::ops::function::FnOnce::call_once",
            Some("<rsa::key::RsaPrivateKey as core::ops::FnOnce<()>>::call_once")
        ));
    }

    #[test]
    fn turbofish_generics_do_not_match() {
        let rule = crate_rule("rsa");
        assert!(!rule.matches("core::ptr::drop_glue::<rsa::Signature>"));
        assert!(!rule.matches(
            "<core::result::Result<rsa::key::RsaPrivateKey, rsa::errors::Error>>::expect"
        ));
        assert!(rule.matches("<rsa::key::RsaPrivateKey>::new::<rand::rngs::thread::ThreadRng>"));
    }

    #[test]
    fn signatures_take_precedence_over_the_crate_anchor() {
        let rule = signature_rule(&["rsa::RsaPrivateKey::new"]);
        assert!(rule.matches("rsa::RsaPrivateKey::new"));
        assert!(!rule.matches("rsa::pkcs1v15::SigningKey::sign"));
    }

    #[test]
    fn signature_match_survives_reexport_paths() {
        let rule = signature_rule(&["rsa::RsaPrivateKey::new"]);
        assert!(rule.matches("rsa::key::RsaPrivateKey::new"));
        assert!(rule.matches("<rsa::key::RsaPrivateKey>::new::<rand::rngs::thread::ThreadRng>"));
        assert!(!rule.matches("rsa::key::RsaPrivateKey::from_components"));
    }

    #[test]
    fn trait_object_dispatch_is_not_hidden_by_the_dyn_keyword() {
        let anchor = crate_rule("rsa");
        assert!(anchor.matches("<dyn rsa::signature::Signer>::sign"));

        let named = signature_rule(&["rsa::sign"]);
        assert!(named.matches("<dyn rsa::signature::Signer>::sign"));

        assert!(!anchor.matches("<dyn std::fmt::Display>::fmt"));
    }

    #[test]
    fn a_qualified_path_matches_on_its_self_type() {
        let rule = signature_rule(&["aes::Aes256::new", "sha2::Sha256::digest"]);
        assert!(rule.matches("<aes::Aes256 as crypto_common::KeyInit>::new"));
        assert!(rule.matches("<sha2::Sha256 as digest::Digest>::digest"));
        assert!(!rule.matches("<aes::Aes128 as crypto_common::KeyInit>::new"));
    }

    #[test]
    fn a_family_can_span_several_crates() {
        let rule = rule_with(MatchSpec {
            crates: vec!["ecdsa".into(), "p256".into(), "k256".into()],
            ..MatchSpec::default()
        });
        assert!(rule.matches("p256::ecdsa::SigningKey::sign"));
        assert!(rule.matches("k256::ecdsa::VerifyingKey::verify"));
        assert!(!rule.matches("ed25519_dalek::SigningKey::sign"));
    }

    #[test]
    fn exclusions_are_checked_before_anything_else() {
        let mut rule = crate_rule("rsa");
        rule.match_spec.exclude = vec!["to_vec".into()];
        assert!(!rule.matches("rsa::signature::SignatureEncoding::to_vec"));
        assert!(rule.matches("rsa::RsaPrivateKey::new"));
    }

    #[test]
    fn specificity_is_having_named_the_api() {
        assert!(!crate_rule("rsa").is_specific());
        assert!(signature_rule(&["rsa::RsaPrivateKey::new"]).is_specific());
    }

    #[test]
    fn a_rule_matching_nothing_is_inert() {
        let rule = rule_with(MatchSpec::default());
        assert!(!rule.matches("rsa::RsaPrivateKey::new"));
    }

    #[test]
    fn parses_the_shipped_schema() {
        let rule = parse_rule(
            r#"
id = "R-RSA-001"
description = "RSA signing/key construction."
algorithm_class = "Rsa"
qv_status = "Vulnerable"
nist_tier = "Tier1"

[match]
crate = "rsa"
"#,
        )
        .expect("valid rule");
        assert_eq!(rule.id, "R-RSA-001");
        assert_eq!(rule.nist_tier.as_deref(), Some("Tier1"));
        assert!(rule.matches("rsa::RsaPrivateKey::new"));
    }

    #[test]
    fn a_malformed_rule_is_an_error_not_a_panic() {
        assert!(parse_rule("id = \"R-X\"").is_err());
    }

    #[test]
    fn crypto_metadata_defaults_are_neutral_not_wrong() {
        let rule = crate_rule("rsa");
        assert_eq!(rule.crypto.primitive, "unknown");
        assert_eq!(rule.crypto.asset_type, "algorithm");
        assert!(rule.crypto.crypto_functions.is_empty());
    }

    #[test]
    fn shipped_rules_declare_cyclonedx_properties() {
        let rule = parse_rule(
            r#"
id = "R-X"
algorithm_class = "Kem"
qv_status = "Resistant"

[match]
crate = "pqcrypto_mlkem"

[crypto]
primitive = "kem"
crypto_functions = ["encapsulate"]
nist_quantum_security_level = 3
"#,
        )
        .expect("valid rule");
        assert_eq!(rule.crypto.primitive, "kem");
        assert_eq!(rule.crypto.nist_quantum_security_level, Some(3));
    }

    #[test]
    fn sinks_match_on_the_operation_name() {
        let rule = sink_rule(&["sign_with_rng", "RSA_sign"]);
        assert!(rule.is_sink("rsa::signature::RandomizedSigner::sign_with_rng"));
        assert!(!rule.is_sink("rsa::RsaPrivateKey::new"));
    }

    #[test]
    fn an_ffi_sink_outside_the_rules_crate_still_matches() {
        let rule = sink_rule(&["RSA_sign"]);
        assert!(rule.is_sink("openssl_sys::RSA_sign"));
    }

    fn arg(index: u32, value: u128) -> ConstArg {
        ConstArg { index, value }
    }

    #[test]
    fn key_size_is_read_from_the_declared_argument() {
        let mut rule = crate_rule("rsa");
        rule.parameter.key_size_arg = Some(1);
        assert_eq!(rule.key_size(&[arg(1, 2048)]), Some(2048));
        assert_eq!(rule.key_size(&[arg(2, 2048)]), None);
    }

    #[test]
    fn a_rule_declaring_no_key_size_argument_reads_none() {
        assert_eq!(crate_rule("rsa").key_size(&[arg(1, 2048)]), None);
    }

    #[test]
    fn a_runtime_key_size_is_unknown_not_guessed() {
        let mut rule = crate_rule("rsa");
        rule.parameter.key_size_arg = Some(1);
        assert_eq!(rule.key_size(&[]), None);
    }

    #[test]
    fn a_rule_declaring_no_sinks_has_none() {
        assert!(!crate_rule("rsa").is_sink("rsa::RsaPrivateKey::sign"));
    }

    #[test]
    fn a_resolved_call_names_its_trait_and_every_crate_it_involves() {
        let cipher = ResolvedCall::of(
            "<ocb3::Ocb3<aes::autodetect::Aes128, typenum::uint::UTerm> as \
             crypto_common::KeyInit>::new_from_slice",
        )
        .expect("a trait impl");
        assert_eq!(
            cipher.trait_method.segments,
            ["crypto_common", "keyinit", "new_from_slice"]
        );
        assert_eq!(cipher.crates, ["aes", "crypto_common", "ocb3", "typenum"]);

        let hazmat = ResolvedCall::of(
            "<p256::arithmetic::scalar::Scalar as ecdsa::hazmat::SignPrimitive<p256::NistP256>>\
             ::try_sign_prehashed::<p256::arithmetic::scalar::Scalar>",
        )
        .expect("a trait impl");
        assert_eq!(
            hazmat.trait_method.segments,
            ["ecdsa", "hazmat", "signprimitive", "try_sign_prehashed"]
        );
        assert_eq!(hazmat.crates, ["ecdsa", "p256"]);

        for other in [
            "crypto_common::KeyInit::new",
            "<rsa::key::RsaPrivateKey>::new",
            "<dyn rsa::signature::Signer>::sign",
        ] {
            assert!(ResolvedCall::of(other).is_none(), "{other}");
        }
    }
}
