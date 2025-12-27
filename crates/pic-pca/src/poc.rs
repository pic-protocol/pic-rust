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
//! Based on PIC Spec v0.1.

use crate::pca::{Constraints, ExecutorBinding, KeyMaterial};
use serde::{Deserialize, Serialize};

// ============================================================================
// Proof Components
// ============================================================================

/// Proof of Identity - asserts the executor's claimed identity.
///
/// Supported types: `spiffe_svid`, `jwt`, `vc`, `x509`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProofOfIdentity {
    pub r#type: String,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

/// Proof of Possession - demonstrates control over a credential or key.
///
/// Supported types: `signature`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProofOfPossession {
    pub r#type: String,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

/// Challenge Response - freshness binding to a PCC (PIC Causal Challenge).
///
/// Supported types: `nonce`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChallengeResponse {
    pub r#type: String,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

/// Proof bundle containing all executor authentication components.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Proof {
    /// Proof of Identity
    pub poi: ProofOfIdentity,
    /// Proof of Possession
    pub pop: ProofOfPossession,
    /// Challenge response (present if PCC was issued)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<ChallengeResponse>,
    /// Public key for PoC signature verification
    pub key_material: KeyMaterial,
}

// ============================================================================
// Successor
// ============================================================================

/// Successor - proposed authority for the next hop.
///
/// Must satisfy monotonicity: `ops ⊆ predecessor.ops`.
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

// ============================================================================
// PoC Payload
// ============================================================================

/// PoC Payload - the CBOR content signed by the executor with COSE_Sign1.
///
/// The predecessor is stored as raw COSE bytes to:
/// - Avoid forced deserialization on creation
/// - Preserve original bytes for signature verification
/// - Enable efficient forwarding without re-encoding
///
/// CAT deserializes the predecessor when validating monotonicity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PocPayload {
    /// Predecessor PCA as raw COSE_Sign1 bytes
    #[serde(with = "serde_bytes")]
    pub predecessor: Vec<u8>,
    /// Proposed authority for next hop
    pub successor: Successor,
    /// Executor authentication proofs
    pub proof: Proof,
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
}

// ============================================================================
// Builder
// ============================================================================

/// Builder for creating PoC payloads with validation.
#[derive(Debug, Clone)]
pub struct PocBuilder {
    predecessor: Vec<u8>,
    ops: Vec<String>,
    executor: Option<ExecutorBinding>,
    constraints: Option<Constraints>,
    poi: Option<ProofOfIdentity>,
    pop: Option<ProofOfPossession>,
    challenge: Option<ChallengeResponse>,
    key_material: Option<KeyMaterial>,
}

impl PocBuilder {
    /// Creates a new builder with the predecessor PCA bytes.
    pub fn new(predecessor_cose_bytes: Vec<u8>) -> Self {
        Self {
            predecessor: predecessor_cose_bytes,
            ops: Vec::new(),
            executor: None,
            constraints: None,
            poi: None,
            pop: None,
            challenge: None,
            key_material: None,
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

    /// Sets the Proof of Identity.
    pub fn poi(mut self, poi_type: &str, value: Vec<u8>) -> Self {
        self.poi = Some(ProofOfIdentity {
            r#type: poi_type.into(),
            value,
        });
        self
    }

    /// Sets the Proof of Possession.
    pub fn pop(mut self, pop_type: &str, value: Vec<u8>) -> Self {
        self.pop = Some(ProofOfPossession {
            r#type: pop_type.into(),
            value,
        });
        self
    }

    /// Sets the challenge response.
    pub fn challenge(mut self, challenge_type: &str, value: Vec<u8>) -> Self {
        self.challenge = Some(ChallengeResponse {
            r#type: challenge_type.into(),
            value,
        });
        self
    }

    /// Sets the key material for signature verification.
    pub fn key_material(mut self, public_key: Vec<u8>, alg: &str) -> Self {
        self.key_material = Some(KeyMaterial {
            public_key,
            alg: alg.into(),
        });
        self
    }

    /// Builds the PoC payload, returning an error if required fields are missing.
    pub fn build(self) -> Result<PocPayload, &'static str> {
        let poi = self.poi.ok_or("PoI is required")?;
        let pop = self.pop.ok_or("PoP is required")?;
        let key_material = self.key_material.ok_or("Key material is required")?;

        if self.ops.is_empty() {
            return Err("Ops cannot be empty");
        }

        Ok(PocPayload {
            predecessor: self.predecessor,
            successor: Successor {
                ops: self.ops,
                executor: self.executor,
                constraints: self.constraints,
            },
            proof: Proof {
                poi,
                pop,
                challenge: self.challenge,
                key_material,
            },
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pca::{Executor, ExecutorBinding, PcaPayload, TemporalConstraints};

    /// Creates sample predecessor bytes (simulates COSE-signed PCA).
    fn sample_predecessor_bytes() -> Vec<u8> {
        let pca = PcaPayload {
            hop: "gateway".into(),
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
            proof: Proof {
                poi: ProofOfIdentity {
                    r#type: "spiffe_svid".into(),
                    value: vec![0x01, 0x02, 0x03],
                },
                pop: ProofOfPossession {
                    r#type: "signature".into(),
                    value: vec![0x04, 0x05, 0x06],
                },
                challenge: Some(ChallengeResponse {
                    r#type: "nonce".into(),
                    value: vec![0x07, 0x08, 0x09],
                }),
                key_material: KeyMaterial {
                    public_key: vec![0u8; 32],
                    alg: "EdDSA".into(),
                },
            },
        };

        let cbor = poc.to_cbor().unwrap();
        let decoded = PocPayload::from_cbor(&cbor).unwrap();

        assert_eq!(poc, decoded);
        assert_eq!(decoded.successor.ops, vec!["read:/user/*"]);
    }

    #[test]
    fn test_poc_json_roundtrip() {
        let poc = PocPayload {
            predecessor: sample_predecessor_bytes(),
            successor: Successor {
                ops: vec!["read:/user/*".into()],
                executor: None,
                constraints: None,
            },
            proof: Proof {
                poi: ProofOfIdentity {
                    r#type: "jwt".into(),
                    value: b"eyJhbGciOiJFUzI1NiJ9...".to_vec(),
                },
                pop: ProofOfPossession {
                    r#type: "signature".into(),
                    value: vec![0xAB; 64],
                },
                challenge: None,
                key_material: KeyMaterial {
                    public_key: vec![0u8; 32],
                    alg: "ES256".into(),
                },
            },
        };

        let json = poc.to_json().unwrap();
        let decoded = PocPayload::from_json(&json).unwrap();

        assert_eq!(poc, decoded);
    }

    #[test]
    fn test_poc_builder() {
        let poc = PocBuilder::new(sample_predecessor_bytes())
            .ops(vec!["read:/user/*".into()])
            .executor(ExecutorBinding::new().with("namespace", "prod"))
            .poi("spiffe_svid", vec![0x01, 0x02])
            .pop("signature", vec![0x03, 0x04])
            .challenge("nonce", vec![0x05, 0x06])
            .key_material(vec![0u8; 32], "EdDSA")
            .build()
            .unwrap();

        assert_eq!(poc.successor.ops, vec!["read:/user/*"]);
        assert!(poc.successor.executor.is_some());
        assert!(poc.proof.challenge.is_some());
    }

    #[test]
    fn test_poc_builder_minimal() {
        let poc = PocBuilder::new(sample_predecessor_bytes())
            .ops(vec!["read:/user/*".into()])
            .poi("jwt", vec![0x01])
            .pop("signature", vec![0x02])
            .key_material(vec![0u8; 32], "EdDSA")
            .build()
            .unwrap();

        assert!(poc.successor.executor.is_none());
        assert!(poc.successor.constraints.is_none());
        assert!(poc.proof.challenge.is_none());
    }

    #[test]
    fn test_poc_builder_missing_required() {
        let result = PocBuilder::new(sample_predecessor_bytes())
            .ops(vec!["read:/user/*".into()])
            .poi("jwt", vec![0x01])
            // Missing PoP
            .key_material(vec![0u8; 32], "EdDSA")
            .build();

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "PoP is required");
    }

    #[test]
    fn test_poc_builder_empty_ops() {
        let result = PocBuilder::new(sample_predecessor_bytes())
            .poi("jwt", vec![0x01])
            .pop("signature", vec![0x02])
            .key_material(vec![0u8; 32], "EdDSA")
            .build();

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Ops cannot be empty");
    }

    #[test]
    fn test_monotonicity_example() {
        // Predecessor has: read + write
        // Successor requests only: read
        // Valid monotonicity: ops ⊆ predecessor.ops

        let poc = PocBuilder::new(sample_predecessor_bytes())
            .ops(vec!["read:/user/*".into()])
            .poi("spiffe_svid", vec![0x01])
            .pop("signature", vec![0x02])
            .key_material(vec![0u8; 32], "EdDSA")
            .build()
            .unwrap();

        assert_eq!(poc.successor.ops.len(), 1);
    }
}