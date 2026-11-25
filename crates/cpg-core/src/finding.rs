use serde::{Deserialize, Serialize};

use crate::model::SourceLoc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlgorithmClass {
    Rsa,
    FiniteFieldDh,
    Ecdsa,
    EdDsa,
    EcdhX25519,
    Ecdh,
    Dsa,
    EcKey,
    Hash,
    Aead,
    Kem,
    Symmetric,
    Kdf,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QvStatus {
    Vulnerable,
    Deprecated,
    Resistant,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViaFrame {
    pub symbol: String,
    pub location: Option<SourceLoc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part {
    pub rule_id: String,
    pub signature: String,
    pub qv_status: QvStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter_set: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub node_id: u32,
    pub algorithm_class: AlgorithmClass,
    pub qv_status: QvStatus,
    pub location: SourceLoc,
    pub contextual_signature: String,
    pub taint_chain: Vec<SourceLoc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taint_nodes: Vec<u32>,
    #[serde(default)]
    pub key_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub via: Vec<ViaFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter_set: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub with: Vec<Part>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn via_is_absent_from_json_when_empty_and_loads_when_missing() {
        let f = Finding {
            rule_id: "R-X".into(),
            node_id: 1,
            algorithm_class: AlgorithmClass::Hash,
            qv_status: QvStatus::Resistant,
            location: SourceLoc::new("src/lib.rs", 3),
            contextual_signature: "x".into(),
            taint_chain: Vec::new(),
            taint_nodes: Vec::new(),
            key_size: None,
            via: Vec::new(),
            parameter_set: None,
            with: Vec::new(),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("via"), "{json}");
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn parameter_set_is_absent_from_json_unless_read() {
        let mut f = Finding {
            rule_id: "R-MLKEM-001".into(),
            node_id: 1,
            algorithm_class: AlgorithmClass::Kem,
            qv_status: QvStatus::Resistant,
            location: SourceLoc::new("src/lib.rs", 3),
            contextual_signature: "ml_kem::KemCore::generate".into(),
            taint_chain: Vec::new(),
            taint_nodes: Vec::new(),
            key_size: None,
            via: Vec::new(),
            parameter_set: None,
            with: Vec::new(),
        };
        assert!(!serde_json::to_string(&f).unwrap().contains("parameter_set"));
        f.parameter_set = Some("768".into());
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(serde_json::from_str::<Finding>(&json).unwrap(), f);
    }
}
