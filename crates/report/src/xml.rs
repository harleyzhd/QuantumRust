use cpg_core::Finding;
use qr_rules::RuleSet;

use crate::{crypto_spec, parameter_set, qv_label};

pub fn emit_cbom_xml(findings: &[Finding], rules: &RuleSet) -> String {
    emit_cbom_xml_with_manifest(findings, rules, &[])
}

pub fn emit_cbom_xml_with_manifest(
    findings: &[Finding],
    rules: &RuleSet,
    declared: &[crate::manifest::DeclaredDependency],
) -> String {
    emit_cbom_xml_report(
        findings,
        rules,
        crate::CbomExtras {
            declared,
            ..crate::CbomExtras::default()
        },
    )
}

pub fn emit_cbom_xml_report(
    findings: &[Finding],
    rules: &RuleSet,
    extras: crate::CbomExtras<'_>,
) -> String {
    let declared = extras.declared;
    let mut out = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    out.push('\n');
    out.push_str(r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.7" version="1">"#);
    out.push('\n');

    out.push_str("  <metadata>\n    <tools>\n      <components>\n");
    out.push_str("        <component type=\"application\">\n");
    out.push_str("          <name>quantumrust</name>\n");
    push_element(&mut out, 10, "version", env!("CARGO_PKG_VERSION"));
    out.push_str("        </component>\n");
    out.push_str("      </components>\n    </tools>\n");
    if let Some(subject) = extras.subject {
        out.push_str(&format!(
            "    <component type=\"{}\" bom-ref=\"{}\">\n",
            if subject.library {
                "library"
            } else {
                "application"
            },
            escape(&subject.purl())
        ));
        push_element(&mut out, 6, "name", &subject.name);
        if let Some(version) = &subject.version {
            push_element(&mut out, 6, "version", version);
        }
        push_element(&mut out, 6, "purl", &subject.purl());
        out.push_str("    </component>\n");
    }
    if let Some(judged) = extras.judged {
        out.push_str("    <properties>\n");
        for (name, value) in crate::profile_metadata(judged) {
            push_property(&mut out, 6, name, &value);
        }
        out.push_str("    </properties>\n");
    }
    out.push_str("  </metadata>\n");

    out.push_str("  <components>\n");
    let refs = crate::bom_refs(findings);
    for (i, finding) in findings.iter().enumerate() {
        push_component(
            &mut out,
            finding,
            rules,
            crate::verdict_of(extras.judged, i),
            &refs[i],
        );
    }
    for dep in declared {
        push_declared(&mut out, dep);
    }
    out.push_str("  </components>\n");

    let edges = crate::dependencies(findings);
    if !edges.is_empty() {
        out.push_str("  <dependencies>\n");
        for (i, js) in edges {
            out.push_str(&format!("    <dependency ref=\"{}\">\n", refs[i]));
            for j in js {
                out.push_str(&format!("      <dependency ref=\"{}\"/>\n", refs[j]));
            }
            out.push_str("    </dependency>\n");
        }
        out.push_str("  </dependencies>\n");
    }

    out.push_str("</bom>\n");
    out
}

fn push_declared(out: &mut String, dep: &crate::manifest::DeclaredDependency) {
    out.push_str("    <component type=\"cryptographic-asset\">\n");
    push_element(out, 6, "name", &dep.name);

    out.push_str("      <properties>\n");
    push_property(out, 8, "quantumrust:evidence", "manifest");
    push_property(
        out,
        8,
        "quantumrust:note",
        "declared dependency; no call site found in the analysed crate \
         (analysis is crate-local)",
    );
    if let Some(version) = &dep.version {
        push_property(out, 8, "quantumrust:version-req", version);
    }
    out.push_str("      </properties>\n");

    out.push_str("      <cryptoProperties>\n");
    push_element(out, 8, "assetType", "related-crypto-material");
    out.push_str("        <relatedCryptoMaterialProperties>\n");
    push_element(out, 10, "type", "unknown");
    out.push_str("        </relatedCryptoMaterialProperties>\n");
    out.push_str("      </cryptoProperties>\n");
    out.push_str("    </component>\n");
}

fn push_component(
    out: &mut String,
    finding: &Finding,
    rules: &RuleSet,
    verdict: Option<crate::Verdict>,
    bom_ref: &str,
) {
    let spec = crypto_spec(finding, rules);
    let indent = 4;

    out.push_str(&format!(
        "    <component type=\"cryptographic-asset\" bom-ref=\"{}\">\n",
        escape(bom_ref)
    ));
    push_element(out, indent + 2, "name", &finding.contextual_signature);

    out.push_str("      <properties>\n");
    push_property(out, indent + 4, "quantumrust:rule", &finding.rule_id);
    push_property(
        out,
        indent + 4,
        "quantumrust:quantum-status",
        qv_label(finding.qv_status),
    );
    if !finding.taint_chain.is_empty() {
        let chain: Vec<String> = finding
            .taint_chain
            .iter()
            .map(|loc| format!("{}:{}", loc.file, loc.line))
            .collect();
        push_property(
            out,
            indent + 4,
            "quantumrust:taint-chain",
            &chain.join(" -> "),
        );
    }
    if !finding.via.is_empty() {
        push_property(
            out,
            indent + 4,
            "quantumrust:via",
            &crate::via_text(&finding.via),
        );
    }
    for part in &finding.with {
        push_property(out, indent + 4, "quantumrust:part", &crate::part_text(part));
    }
    if let Some(verdict) = verdict {
        push_property(
            out,
            indent + 4,
            "quantumrust:profile-verdict",
            verdict.label(),
        );
    }
    out.push_str("      </properties>\n");

    out.push_str("      <evidence>\n        <occurrences>\n");
    out.push_str("          <occurrence>\n");
    push_element(out, indent + 8, "location", &finding.location.file);
    push_element(out, indent + 8, "line", &finding.location.line.to_string());
    push_element(out, indent + 8, "symbol", &finding.contextual_signature);
    push_element(
        out,
        indent + 8,
        "additionalContext",
        &format!("matched by rule {}", finding.rule_id),
    );
    out.push_str("          </occurrence>\n");
    out.push_str("        </occurrences>\n      </evidence>\n");

    out.push_str("      <cryptoProperties>\n");
    push_element(out, indent + 4, "assetType", &spec.asset_type);

    out.push_str("        <algorithmProperties>\n");
    push_element(out, indent + 6, "primitive", &spec.primitive);
    if let Some(family) = &spec.algorithm_family {
        push_element(out, indent + 6, "algorithmFamily", family);
    }
    if let Some(value) = parameter_set(finding, &spec) {
        push_element(out, indent + 6, "parameterSetIdentifier", &value);
    }
    if let Some(mode) = &spec.mode {
        push_element(out, indent + 6, "mode", mode);
    }
    if !spec.crypto_functions.is_empty() {
        out.push_str("          <cryptoFunctions>\n");
        for function in &spec.crypto_functions {
            push_element(out, indent + 8, "cryptoFunction", function);
        }
        out.push_str("          </cryptoFunctions>\n");
    }
    if let Some(level) = crate::quantum_security_level(finding, rules) {
        push_element(
            out,
            indent + 6,
            "nistQuantumSecurityLevel",
            &level.to_string(),
        );
    }
    out.push_str("        </algorithmProperties>\n");
    if let Some(oid) = &spec.oid {
        push_element(out, indent + 4, "oid", oid);
    }
    out.push_str("      </cryptoProperties>\n");

    out.push_str("    </component>\n");
}

fn push_element(out: &mut String, indent: usize, name: &str, text: &str) {
    out.push_str(&format!(
        "{:indent$}<{name}>{}</{name}>\n",
        "",
        escape(text),
        indent = indent
    ));
}

fn push_property(out: &mut String, indent: usize, name: &str, value: &str) {
    out.push_str(&format!(
        "{:indent$}<property name=\"{}\">{}</property>\n",
        "",
        escape(name),
        escape(value),
        indent = indent
    ));
}

pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpg_core::{AlgorithmClass, QvStatus, SourceLoc};

    fn finding(rule_id: &str, symbol: &str) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            node_id: 1,
            algorithm_class: AlgorithmClass::Rsa,
            qv_status: QvStatus::Vulnerable,
            location: SourceLoc::new("src/main.rs", 21),
            contextual_signature: symbol.into(),
            taint_chain: vec![SourceLoc::new("src/main.rs", 21)],
            taint_nodes: Vec::new(),
            via: Vec::new(),
            key_size: Some(2048),
            parameter_set: None,
            with: Vec::new(),
        }
    }

    #[test]
    fn a_via_path_is_an_xml_property() {
        let mut f = finding("R-RSA-001", "vault::seal");
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
        let xml = emit_cbom_xml(&[f], &RuleSet::builtin());
        assert!(xml.contains("quantumrust:via"), "{xml}");
        assert!(xml.contains("vault::seal (v.rs:2) -&gt; rsa::RsaPrivateKey::new (v.rs:3)"));
    }

    #[test]
    fn xml_has_the_cyclonedx_envelope() {
        let xml = emit_cbom_xml(
            &[finding("R-RSA-001", "rsa::RsaPrivateKey::new")],
            &RuleSet::builtin(),
        );
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
        assert!(xml.contains(r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.7" version="1">"#));
        assert!(xml.contains("<component type=\"cryptographic-asset\""));
        assert!(xml.trim_end().ends_with("</bom>"));
    }

    #[test]
    fn symbols_containing_markup_are_escaped() {
        let xml = emit_cbom_xml(
            &[finding("R-RSA-002", "<dyn rsa::signature::Signer>::sign")],
            &RuleSet::builtin(),
        );
        assert!(xml.contains("&lt;dyn rsa::signature::Signer&gt;::sign"));
        assert!(!xml.contains("<dyn rsa"));
    }

    #[test]
    fn both_formats_describe_the_same_components() {
        let findings = [
            finding("R-RSA-001", "rsa::RsaPrivateKey::new"),
            finding("R-RSA-002", "<dyn rsa::signature::Signer>::sign"),
            finding("R-SHA2-001", "rsa::sha2::OidSha256"),
        ];
        let rules = RuleSet::builtin();
        let json = crate::emit_cbom(&findings, &rules);
        let xml = emit_cbom_xml(&findings, &rules);

        let components = json["components"].as_array().unwrap();
        let asset_components = xml.matches("type=\"cryptographic-asset\"").count();
        assert_eq!(components.len(), asset_components);

        for component in components {
            let bom_ref = component["bom-ref"].as_str().unwrap();
            assert!(xml.contains(bom_ref), "{bom_ref} missing from XML");
            let name = component["name"].as_str().unwrap();
            assert!(
                xml.contains(&format!("<name>{}</name>", escape(name))),
                "{name} missing from XML"
            );
        }
    }

    #[test]
    fn xml_is_byte_identical_across_runs() {
        let findings = [finding("R-RSA-001", "rsa::RsaPrivateKey::new")];
        let rules = RuleSet::builtin();
        assert_eq!(
            emit_cbom_xml(&findings, &rules),
            emit_cbom_xml(&findings, &rules)
        );
    }
}
