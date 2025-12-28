/*
 * Copyright Nitro Agility S.r.l.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! PoC (Proof of Continuity) payload model.
//!
//! Defines the PoC data structure for CBOR serialization within COSE_Sign1 envelope.
//! Based on PIC Spec v0.2.
//!
//! Key changes from v0.1:
//! - `proof.poi` replaced by `attestations[]` (Executor Attestation array)
//! - `proof.pop` is now per-attestation (inside each attestation that requires it)
//! - `proof.challenge` moved to COSE protected header
//! - `proof.key_material` removed (key is extracted from attestation credential)
//!
//! The PoC proves causal continuity by demonstrating that the executor:
//! 1. Holds a valid predecessor PCA
//! 2. Can attest its identity via one or more attestations
//! 3. Requests authority that is a subset of the predecessor's

use crate::pca::{Constraints, ExecutorBinding};
use serde::{Deserialize, Serialize};

/// Custom serializer for Option<Vec<u8>> with serde_bytes.
mod optional_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serde_bytes::Bytes::new(bytes).serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
        Ok(opt.map(|b| b.into_vec()))
    }
}

/// Executor Attestation - a verifiable document attesting executor properties.
///
/// Replaces the old `ProofOfIdentity` with a more flexible structure that
/// supports multiple attestation types and per-attestation PoP.
///
/// The `attestation_type` is a string to allow extensibility. Common values include:
/// - `"spiffe_svid"` - SPIFFE SVID (X.509), typically requires PoP
/// - `"vp"` - Verifiable Presentation, PoP implicit in VP signature
/// - `"tee_quote"` - TEE Quote (SGX, TDX, SEV), hardware-bound
/// - `"jwt"` - JWT token
/// - `"x509"` - Generic X.509 certificate
///
/// The PoP (when present) MUST sign `hash(protected_header + payload)` to bind
/// the attestation to this specific PoC context, preventing replay attacks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutorAttestation {
    /// Attestation type (extensible string, e.g., "spiffe_svid", "vp", "tee_quote")
    #[serde(rename = "type")]
    pub attestation_type: String,

    /// The credential bytes (X.509 cert, VP, TEE quote, JWT, etc.)
    /// Contains or references the public key for verification.
    #[serde(with = "serde_bytes")]
    pub credential: Vec<u8>,

    /// Proof of Possession - signature over hash(protected + payload).
    /// Present only if the attestation type requires it.
    /// The PoP binds this attestation to this specific PoC context.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "optional_bytes")]
    pub pop: Option<Vec<u8>>,
}

impl ExecutorAttestation {
    /// Creates a new attestation without PoP.
    ///
    /// Use this for attestation types where PoP is implicit (e.g., VP)
    /// or not applicable (e.g., TEE quote).
    pub fn new(attestation_type: impl Into<String>, credential: Vec<u8>) -> Self {
        Self {
            attestation_type: attestation_type.into(),
            credential,
            pop: None,
        }
    }

    /// Creates a new attestation with PoP.
    ///
    /// Use this for attestation types that require proof of possession
    /// (e.g., SPIFFE SVID, X.509 cert, JWT+DPoP).
    pub fn with_pop(
        attestation_type: impl Into<String>,
        credential: Vec<u8>,
        pop: Vec<u8>,
    ) -> Self {
        Self {
            attestation_type: attestation_type.into(),
            credential,
            pop: Some(pop),
        }
    }

    /// Returns true if this attestation has a PoP.
    pub fn has_pop(&self) -> bool {
        self.pop.is_some()
    }
}

/// Successor - proposed authority for the next hop.
///
/// Must satisfy monotonicity: `ops ⊆ predecessor.ops`.
/// Constraints must also be monotonically restricted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Successor {
    /// Requested operations (must be subset of predecessor)
    pub ops: Vec<String>,
    /// Next executor binding (if known at submission time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor: Option<ExecutorBinding>,
    /// Restricted constraints (must be subset of predecessor)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
}

/// PoC Payload - the CBOR content signed by the executor with COSE_Sign1.
///
/// COSE_Sign1 structure:
/// ```text
/// protected: { alg, kid, challenge }  <- challenge in header for freshness
/// payload: { predecessor, successor, attestations }
/// signature: ...
/// ```
///
/// The `kid` in the protected header identifies which key was used to sign
/// this PoC. The key can be resolved from one of the attestations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PocPayload {
    /// Predecessor PCA as raw COSE_Sign1 bytes.
    /// Stored as bytes to preserve original signature for verification.
    #[serde(with = "serde_bytes")]
    pub predecessor: Vec<u8>,

    /// Proposed authority for next hop
    pub successor: Successor,

    /// Executor attestations (replaces PoI).
    /// Multiple attestations can be provided (identity, environment, capabilities).
    pub attestations: Vec<ExecutorAttestation>,
}

impl PocPayload {
    /// Serializes to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Deserializes from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>> {
        ciborium::from_reader(bytes)
    }

    /// Serializes to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serializes to pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserializes from JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Finds an attestation by type.
    pub fn find_attestation(&self, attestation_type: &str) -> Option<&ExecutorAttestation> {
        self.attestations
            .iter()
            .find(|a| a.attestation_type == attestation_type)
    }
}

/// Builder for creating PoC payloads.
#[derive(Debug, Clone)]
pub struct PocBuilder {
    predecessor: Vec<u8>,
    ops: Vec<String>,
    executor: Option<ExecutorBinding>,
    constraints: Option<Constraints>,
    attestations: Vec<ExecutorAttestation>,
}

impl PocBuilder {
    /// Creates a new builder with the predecessor PCA bytes.
    pub fn new(predecessor_cose_bytes: Vec<u8>) -> Self {
        Self {
            predecessor: predecessor_cose_bytes,
            ops: Vec::new(),
            executor: None,
            constraints: None,
            attestations: Vec::new(),
        }
    }

    /// Sets the requested operations (must be subset of predecessor).
    pub fn ops(mut self, ops: Vec<String>) -> Self {
        self.ops = ops;
        self
    }

    /// Sets the next executor binding.
    pub fn executor(mut self, binding: ExecutorBinding) -> Self {
        self.executor = Some(binding);
        self
    }

    /// Sets the constraints.
    pub fn constraints(mut self, constraints: Constraints) -> Self {
        self.constraints = Some(constraints);
        self
    }

    /// Adds an attestation without PoP.
    pub fn attestation(
        mut self,
        attestation_type: impl Into<String>,
        credential: Vec<u8>,
    ) -> Self {
        self.attestations
            .push(ExecutorAttestation::new(attestation_type, credential));
        self
    }

    /// Adds an attestation with PoP.
    pub fn attestation_with_pop(
        mut self,
        attestation_type: impl Into<String>,
        credential: Vec<u8>,
        pop: Vec<u8>,
    ) -> Self {
        self.attestations
            .push(ExecutorAttestation::with_pop(attestation_type, credential, pop));
        self
    }

    /// Builds the PoC payload, returning an error if required fields are missing.
    pub fn build(self) -> Result<PocPayload, &'static str> {
        if self.ops.is_empty() {
            return Err("Ops cannot be empty");
        }

        if self.attestations.is_empty() {
            return Err("At least one attestation is required");
        }

        Ok(PocPayload {
            predecessor: self.predecessor,
            successor: Successor {
                ops: self.ops,
                executor: self.executor,
                constraints: self.constraints,
            },
            attestations: self.attestations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pca::{Executor, ExecutorBinding, PcaPayload, TemporalConstraints};

    fn sample_predecessor_bytes() -> Vec<u8> {
        let pca = PcaPayload {
            hop: 0,
            p_0: "https://idp.example.com/users/alice".into(),
            ops: vec!["read:/user/*".into(), "write:/user/*".into()],
            executor: Executor {
                binding: ExecutorBinding::new().with("org", "acme"),
            },
            provenance: None,
            constraints: None,
        };
        pca.to_cbor().unwrap()
    }

    #[test]
    fn test_poc_cbor_roundtrip() {
        let poc = PocPayload {
            predecessor: sample_predecessor_bytes(),
            successor: Successor {
                ops: vec!["read:/user/*".into()],
                executor: Some(ExecutorBinding::new().with("namespace", "prod")),
                constraints: Some(Constraints {
                    temporal: Some(TemporalConstraints {
                        iat: None,
                        exp: Some("2025-12-11T10:30:00Z".into()),
                        nbf: None,
                    }),
                }),
            },
            attestations: vec![
                ExecutorAttestation::with_pop("spiffe_svid", vec![0x01, 0x02, 0x03], vec![0x04, 0x05, 0x06]),
                ExecutorAttestation::new("tee_quote", vec![0x07, 0x08, 0x09]),
            ],
        };

        let cbor = poc.to_cbor().unwrap();
        let decoded = PocPayload::from_cbor(&cbor).unwrap();

        assert_eq!(poc, decoded);
        assert_eq!(decoded.successor.ops, vec!["read:/user/*"]);
        assert_eq!(decoded.attestations.len(), 2);
    }

    #[test]
    fn test_attestation_type_is_string() {
        let attestation = ExecutorAttestation::new("custom_type", vec![0x01]);
        assert_eq!(attestation.attestation_type, "custom_type");

        let attestation = ExecutorAttestation::new("spiffe_svid", vec![0x01]);
        assert_eq!(attestation.attestation_type, "spiffe_svid");
    }

    #[test]
    fn test_attestation_has_pop() {
        let with_pop = ExecutorAttestation::with_pop("x509", vec![0x01], vec![0x02]);
        assert!(with_pop.has_pop());

        let without_pop = ExecutorAttestation::new("vp", vec![0x01]);
        assert!(!without_pop.has_pop());
    }

    #[test]
    fn test_find_attestation() {
        let poc = PocPayload {
            predecessor: sample_predecessor_bytes(),
            successor: Successor {
                ops: vec!["read:/user/*".into()],
                executor: None,
                constraints: None,
            },
            attestations: vec![
                ExecutorAttestation::new("spiffe_svid", vec![0x01]),
                ExecutorAttestation::new("tee_quote", vec![0x02]),
            ],
        };

        assert!(poc.find_attestation("spiffe_svid").is_some());
        assert!(poc.find_attestation("tee_quote").is_some());
        assert!(poc.find_attestation("vp").is_none());
    }

    #[test]
    fn test_poc_builder() {
        let poc = PocBuilder::new(sample_predecessor_bytes())
            .ops(vec!["read:/user/*".into()])
            .executor(ExecutorBinding::new().with("namespace", "prod"))
            .attestation_with_pop("spiffe_svid", vec![0x01, 0x02], vec![0x03, 0x04])
            .attestation("tee_quote", vec![0x05, 0x06])
            .build()
            .unwrap();

        assert_eq!(poc.successor.ops, vec!["read:/user/*"]);
        assert!(poc.successor.executor.is_some());
        assert_eq!(poc.attestations.len(), 2);
    }

    #[test]
    fn test_poc_builder_empty_attestations_fails() {
        let result = PocBuilder::new(sample_predecessor_bytes())
            .ops(vec!["read:/user/*".into()])
            .build();

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "At least one attestation is required");
    }

    #[test]
    fn test_poc_builder_empty_ops_fails() {
        let result = PocBuilder::new(sample_predecessor_bytes())
            .attestation("vp", vec![0x01])
            .build();

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Ops cannot be empty");
    }

    #[test]
    fn test_monotonicity_example() {
        let poc = PocBuilder::new(sample_predecessor_bytes())
            .ops(vec!["read:/user/*".into()])
            .attestation("vp", vec![0x01])
            .build()
            .unwrap();

        assert_eq!(poc.successor.ops.len(), 1);
    }

    #[test]
    fn test_json_roundtrip() {
        let poc = PocPayload {
            predecessor: sample_predecessor_bytes(),
            successor: Successor {
                ops: vec!["read:/user/*".into()],
                executor: None,
                constraints: None,
            },
            attestations: vec![ExecutorAttestation::new("vp", b"eyJhbGciOiJFUzI1NiJ9...".to_vec())],
        };

        let json = poc.to_json().unwrap();
        let decoded = PocPayload::from_json(&json).unwrap();

        assert_eq!(poc, decoded);
    }

    #[test]
    fn test_multiple_attestation_types() {
        let poc = PocBuilder::new(sample_predecessor_bytes())
            .ops(vec!["read:/user/*".into()])
            .attestation_with_pop("spiffe_svid", vec![0x01], vec![0x02])
            .attestation("vp", vec![0x03])
            .attestation("tee_quote", vec![0x04])
            .attestation_with_pop("custom_attestation", vec![0x05], vec![0x06])
            .build()
            .unwrap();

        assert_eq!(poc.attestations.len(), 4);
        assert!(poc.find_attestation("spiffe_svid").unwrap().has_pop());
        assert!(!poc.find_attestation("vp").unwrap().has_pop());
        assert!(!poc.find_attestation("tee_quote").unwrap().has_pop());
        assert!(poc.find_attestation("custom_attestation").unwrap().has_pop());
    }
}