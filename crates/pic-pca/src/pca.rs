//! PCA (Provenance Causal Authority) model
//!
//! CBOR serialization for COSE payload.
//! Based on PIC Spec v0.1

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Generic dynamic key-value map with nested support
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DynamicMap(pub HashMap<String, Value>);

impl DynamicMap {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn with(mut self, key: &str, value: &str) -> Self {
        self.0.insert(key.into(), Value::String(value.into()));
        self
    }

    pub fn with_map(mut self, key: &str, value: DynamicMap) -> Self {
        self.0
            .insert(key.into(), serde_json::to_value(value).unwrap());
        self
    }

    pub fn with_value(mut self, key: &str, value: Value) -> Self {
        self.0.insert(key.into(), value);
        self
    }

    pub fn with_array(mut self, key: &str, values: Vec<&str>) -> Self {
        let arr: Vec<Value> = values
            .into_iter()
            .map(|s| Value::String(s.into()))
            .collect();
        self.0.insert(key.into(), Value::Array(arr));
        self
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.0.get(key)?.as_str()
    }

    pub fn get_map(&self, key: &str) -> Option<DynamicMap> {
        let value = self.0.get(key)?;
        serde_json::from_value(value.clone()).ok()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Executor binding - identifies executor in federation context
pub type ExecutorBinding = DynamicMap;

/// Executor at current hop
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Executor {
    pub binding: ExecutorBinding,
}

/// Key material for signature verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyMaterial {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    pub alg: String,
}

/// CAT provenance - who signed the previous PCA
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CatProvenance {
    pub issuer: String,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    pub key: KeyMaterial,
}

/// Executor provenance - who signed the PoC
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutorProvenance {
    pub issuer: String,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    pub key: KeyMaterial,
}

/// Provenance chain - links to previous hop
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Provenance {
    pub cat: CatProvenance,
    pub executor: ExecutorProvenance,
}

/// Temporal constraints
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemporalConstraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<String>,
}

/// All constraints
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Constraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal: Option<TemporalConstraints>,
}

/// PCA Payload - signed with COSE_Sign1
///
/// issuer → COSE header kid
/// signature → COSE signature
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PcaPayload {
    /// Unique identifier for this hop (GUID)
    pub hop: String,
    /// Immutable origin principal
    pub p_0: String,
    /// Authority set (ops_i ⊆ ops_{i-1})
    pub ops: Vec<String>,
    /// Current executor
    pub executor: Executor,
    /// Causal chain reference (None for PCA_0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    /// Bounds on PCA validity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
}

impl PcaPayload {
    pub fn to_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>> {
        ciborium::from_reader(bytes)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pca_0() -> PcaPayload {
        let binding = ExecutorBinding::new().with("org", "acme-corp");

        PcaPayload {
            hop: "gateway".into(),
            p_0: "https://idp.example.com/users/alice".into(),
            ops: vec!["read:/user/*".into(), "write:/user/*".into()],
            executor: Executor { binding },
            provenance: None,
            constraints: Some(Constraints {
                temporal: Some(TemporalConstraints {
                    iat: Some("2025-12-11T10:00:00Z".into()),
                    exp: Some("2025-12-11T11:00:00Z".into()),
                    nbf: None,
                }),
            }),
        }
    }

    fn sample_pca_n() -> PcaPayload {
        let binding = ExecutorBinding::new().with("org", "acme-corp");

        PcaPayload {
            hop: "storage".into(),
            p_0: "https://idp.example.com/users/alice".into(),
            ops: vec!["read:/user/*".into()],
            executor: Executor { binding },
            provenance: Some(Provenance {
                cat: CatProvenance {
                    issuer: "https://cat.acme-corp.com".into(),
                    signature: vec![0u8; 64],
                    key: KeyMaterial {
                        public_key: vec![0u8; 32],
                        alg: "EdDSA".into(),
                    },
                },
                executor: ExecutorProvenance {
                    issuer: "spiffe://acme-corp/archive".into(),
                    signature: vec![0u8; 64],
                    key: KeyMaterial {
                        public_key: vec![0u8; 32],
                        alg: "EdDSA".into(),
                    },
                },
            }),
            constraints: Some(Constraints {
                temporal: Some(TemporalConstraints {
                    iat: Some("2025-12-11T10:00:00Z".into()),
                    exp: Some("2025-12-11T10:30:00Z".into()),
                    nbf: None,
                }),
            }),
        }
    }

    #[test]
    fn test_pca_0_cbor_roundtrip() {
        let pca = sample_pca_0();
        let cbor = pca.to_cbor().unwrap();
        let decoded = PcaPayload::from_cbor(&cbor).unwrap();
        assert_eq!(pca, decoded);
        assert_eq!(decoded.hop, "gateway");
        assert!(decoded.provenance.is_none());
    }

    #[test]
    fn test_pca_n_cbor_roundtrip() {
        let pca = sample_pca_n();
        let cbor = pca.to_cbor().unwrap();
        let decoded = PcaPayload::from_cbor(&cbor).unwrap();
        assert_eq!(pca, decoded);
        assert_eq!(decoded.hop, "storage");
        assert!(decoded.provenance.is_some());
    }

    #[test]
    fn test_json_roundtrip() {
        let pca = sample_pca_n();
        let json = pca.to_json().unwrap();
        let decoded = PcaPayload::from_json(&json).unwrap();
        assert_eq!(pca, decoded);
    }

    #[test]
    fn test_cbor_smaller_than_json() {
        let pca = sample_pca_n();
        let cbor = pca.to_cbor().unwrap();
        let json = pca.to_json().unwrap();

        println!("CBOR: {} bytes", cbor.len());
        println!("JSON: {} bytes", json.len());

        assert!(cbor.len() < json.len());
    }

    #[test]
    fn test_json_output() {
        let pca = sample_pca_n();
        let json = pca.to_json_pretty().unwrap();
        println!("{}", json);
    }

    #[test]
    fn test_monotonicity_ops_reduced() {
        let pca_0 = sample_pca_0();
        let pca_n = sample_pca_n();

        assert_eq!(pca_0.ops.len(), 2);
        assert_eq!(pca_n.ops.len(), 1);
        assert_eq!(pca_0.p_0, pca_n.p_0);
    }

    #[test]
    fn test_minimal_executor_binding() {
        let binding = ExecutorBinding::new().with("org", "simple-org");

        let pca = PcaPayload {
            hop: "service-a".into(),
            p_0: "https://idp.example.com/users/alice".into(),
            ops: vec!["read:/user/*".into()],
            executor: Executor { binding },
            provenance: None,
            constraints: None,
        };

        let cbor = pca.to_cbor().unwrap();
        let decoded = PcaPayload::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.executor.binding.get_str("org"), Some("simple-org"));
    }

    #[test]
    fn test_executor_binding_flexible() {
        let binding = ExecutorBinding::new()
            .with("org", "acme-corp")
            .with("region", "eu-west-1")
            .with("env", "prod");

        let pca = PcaPayload {
            hop: "api-gateway".into(),
            p_0: "https://idp.example.com/users/alice".into(),
            ops: vec!["invoke:*".into()],
            executor: Executor { binding },
            provenance: None,
            constraints: None,
        };

        let cbor = pca.to_cbor().unwrap();
        let decoded = PcaPayload::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.executor.binding.get_str("org"), Some("acme-corp"));
        assert_eq!(
            decoded.executor.binding.get_str("region"),
            Some("eu-west-1")
        );
    }

    #[test]
    fn test_nested_binding() {
        let k8s = DynamicMap::new()
            .with("cluster", "prod-eu")
            .with("namespace", "default");

        let binding = ExecutorBinding::new()
            .with("org", "acme-corp")
            .with_map("kubernetes", k8s)
            .with_array("regions", vec!["eu-west-1", "eu-west-2"]);

        let pca = PcaPayload {
            hop: "k8s-service".into(),
            p_0: "https://idp.example.com/users/alice".into(),
            ops: vec!["read:*".into()],
            executor: Executor { binding },
            provenance: None,
            constraints: None,
        };

        let json = pca.to_json_pretty().unwrap();
        println!("{}", json);

        let cbor = pca.to_cbor().unwrap();
        let decoded = PcaPayload::from_cbor(&cbor).unwrap();

        let k8s_decoded = decoded.executor.binding.get_map("kubernetes").unwrap();
        assert_eq!(k8s_decoded.get_str("cluster"), Some("prod-eu"));
        assert_eq!(k8s_decoded.get_str("namespace"), Some("default"));
    }

    #[test]
    fn test_binding_with_json_value() {
        let binding = ExecutorBinding::new().with("org", "acme-corp").with_value(
            "metadata",
            serde_json::json!({
                "version": "1.2.3",
                "replicas": 3,
                "labels": {
                    "app": "gateway",
                    "tier": "frontend"
                }
            }),
        );

        let pca = PcaPayload {
            hop: "gateway".into(),
            p_0: "https://idp.example.com/users/alice".into(),
            ops: vec!["read:*".into()],
            executor: Executor { binding },
            provenance: None,
            constraints: None,
        };

        let json = pca.to_json_pretty().unwrap();
        println!("{}", json);

        let cbor = pca.to_cbor().unwrap();
        let decoded = PcaPayload::from_cbor(&cbor).unwrap();

        let metadata = decoded.executor.binding.get("metadata").unwrap();
        assert_eq!(metadata["version"], "1.2.3");
        assert_eq!(metadata["replicas"], 3);
    }
}
