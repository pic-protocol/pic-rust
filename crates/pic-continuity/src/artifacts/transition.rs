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

//! PIC Continuity Transition COSE (`pic-continuity-transition+cose`): the
//! workload-signed causal authority transition.

use super::check_profile;
use crate::authority::indexed::KvTuple;
use crate::cose::CoseSigned;
use crate::error::RejectReason;
use serde::{Deserialize, Serialize};

/// Custom serializer for `Option<Vec<u8>>` with serde_bytes.
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

/// The exactly-one predecessor reference. Current Profile 0.2 requires
/// `type = "pca"` and `hash = SHA-256(exact signed current root.pca bytes)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Predecessor {
    /// Predecessor reference type; current Profile 0.2 requires
    /// [`crate::PREDECESSOR_TYPE_PCA`].
    #[serde(rename = "type")]
    pub predecessor_type: String,
    /// SHA-256 over the exact signed bytes of the current trusted
    /// PIC PCA COSE checkpoint.
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
}

/// Challenge pair of a transition: it answers the predecessor's challenge
/// and emits the next one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionChallenge {
    /// Echo of the predecessor checkpoint's `challenge.next_challenge`.
    #[serde(with = "serde_bytes")]
    pub previous_challenge: Vec<u8>,
    /// Fresh challenge for the successor checkpoint; must differ from
    /// `previous_challenge` and be non-empty.
    #[serde(with = "serde_bytes")]
    pub next_challenge: Vec<u8>,
}

/// Typed Proof of Relationship container. `type` controls how `evidence`
/// is parsed and validated; current Profile 0.2 requires `"sd-jwt"` with the
/// exact UTF-8 bytes of the issuer-signed SD-JWT presentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofOfRelationship {
    /// Evidence type; current Profile 0.2 requires
    /// [`crate::POR_TYPE_SD_JWT`].
    #[serde(rename = "type")]
    pub por_type: String,
    /// Type-specific evidence bytes; for `"sd-jwt"`, the exact UTF-8 bytes
    /// of the issuer-signed SD-JWT presentation.
    #[serde(with = "serde_bytes")]
    pub evidence: Vec<u8>,
}

impl ProofOfRelationship {
    /// An SD-JWT Proof of Relationship from the exact textual RFC 9901
    /// presentation string (issuer-signed JWT plus selected disclosures).
    /// The evidence stores its exact UTF-8 bytes; the presentation is not
    /// re-encoded.
    pub fn sd_jwt(presentation: &str) -> Self {
        Self {
            por_type: crate::POR_TYPE_SD_JWT.to_string(),
            evidence: presentation.as_bytes().to_vec(),
        }
    }
}

/// A section removal attenuation on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitmapAttenuation {
    /// Canonical LSB-first removal bitmap over the section's
    /// section-local indexes (see [`crate::authority::bitmap`]).
    #[serde(with = "serde_bytes")]
    pub remove_bitmap: Vec<u8>,
}

/// Execution-contract additions on the wire: canonical `[key, value]`
/// tuples, unindexed (the settlement verifier assigns indexes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAdditions {
    /// Proposed constraint entries; the settlement verifier deduplicates,
    /// sorts, and assigns the next section-local indexes.
    pub additions: Vec<KvTuple>,
}

/// The optional `attenuations` member of a transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AttenuationsWire {
    /// Removal-only attenuation of the `identity_context` section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_context: Option<BitmapAttenuation>,
    /// Removal-only attenuation of the `invariants` section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invariants: Option<BitmapAttenuation>,
    /// Additions-only attenuation of the `execution_contract` section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_contract: Option<ContractAdditions>,
}

impl AttenuationsWire {
    /// `true` when no section carries an attenuation; such a member should
    /// be omitted from the transition entirely.
    pub fn is_empty(&self) -> bool {
        self.identity_context.is_none()
            && self.invariants.is_none()
            && self.execution_contract.is_none()
    }

    /// Parses the wire form into validated
    /// [`Attenuations`](crate::authority::Attenuations), rejecting
    /// non-canonical bitmaps.
    pub fn parse(&self) -> Result<crate::authority::attenuation::Attenuations, RejectReason> {
        use crate::authority::attenuation::Attenuations;
        use crate::authority::bitmap::RemoveBitmap;
        Ok(Attenuations {
            identity_context: self
                .identity_context
                .as_ref()
                .map(|b| RemoveBitmap::from_bytes(&b.remove_bitmap))
                .transpose()?,
            invariants: self
                .invariants
                .as_ref()
                .map(|b| RemoveBitmap::from_bytes(&b.remove_bitmap))
                .transpose()?,
            execution_contract_additions: self
                .execution_contract
                .as_ref()
                .map(|a| a.additions.clone())
                .unwrap_or_default(),
        })
    }
}

/// PIC Continuity Transition COSE payload: the workload-signed causal
/// authority transition.
///
/// No `Eq`: `executor_evidence` may carry arbitrary CBOR, including floats.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PicTransitionPayload {
    /// PIC profile identifier; must equal [`crate::PROFILE_0_2`].
    pub profile: String,
    /// Proposed successor position: exactly predecessor position + 1.
    pub position: u64,
    /// The exactly-one reference to the current trusted checkpoint.
    pub predecessor: Predecessor,
    /// Challenge pair: answers the predecessor's challenge, emits the next.
    pub challenge: TransitionChallenge,
    /// Optional monotonic attenuations; omitted means "carry authority
    /// forward unchanged".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attenuations: Option<AttenuationsWire>,
    /// Proof of Relationship binding the proposing workload to the lineage.
    pub proof_of_relationship: ProofOfRelationship,
    /// Optional digest binding the transition to a concrete request, when
    /// the deployment requires request binding.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_bytes"
    )]
    pub request_digest: Option<Vec<u8>>,
    /// Optional executor-supplied evidence (arbitrary CBOR) evaluated by
    /// deployment conformance policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_evidence: Option<ciborium::Value>,
}

impl PicTransitionPayload {
    /// Rejects the payload unless `profile` is [`crate::PROFILE_0_2`].
    pub fn check_profile(&self) -> Result<(), RejectReason> {
        check_profile("pic-continuity-transition+cose", &self.profile)
    }
}

/// COSE-signed Transition.
pub type PicTransitionCose = CoseSigned<PicTransitionPayload>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_cbor_roundtrip() {
        let t = PicTransitionPayload {
            profile: crate::PROFILE_0_2.into(),
            position: 1,
            predecessor: Predecessor {
                predecessor_type: crate::PREDECESSOR_TYPE_PCA.into(),
                hash: vec![0xAA; 32],
            },
            challenge: TransitionChallenge {
                previous_challenge: b"c0".to_vec(),
                next_challenge: b"c1".to_vec(),
            },
            attenuations: Some(AttenuationsWire {
                invariants: Some(BitmapAttenuation {
                    remove_bitmap: vec![0x01],
                }),
                ..Default::default()
            }),
            proof_of_relationship: ProofOfRelationship {
                por_type: crate::POR_TYPE_SD_JWT.into(),
                evidence: b"<sd-jwt presentation bytes>".to_vec(),
            },
            request_digest: None,
            executor_evidence: None,
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&t, &mut buf).unwrap();
        let decoded: PicTransitionPayload = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(t, decoded);
        let parsed = decoded.attenuations.unwrap().parse().unwrap();
        assert_eq!(parsed.invariants.unwrap().indices(), vec![0]);
    }

    #[test]
    fn sd_jwt_constructor_keeps_exact_bytes() {
        let presentation = "<issuer-signed jwt>~<disclosure>~";
        let por = ProofOfRelationship::sd_jwt(presentation);
        assert_eq!(por.por_type, crate::POR_TYPE_SD_JWT);
        assert_eq!(por.evidence, presentation.as_bytes());
    }
}
