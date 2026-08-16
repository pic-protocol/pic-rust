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

//! The Initial Continuity Proposal (Profile 0.2).
//!
//! A self-describing JSON protocol object used before PIC continuity
//! exists: it supplies initialization material — in current Profile 0.2,
//! the execution contract. Its `type` member identifies the proposal
//! definition/schema ([`crate::PROPOSAL_TYPE_CONTINUITY_INITIAL`]) and
//! determines how the remaining payload is interpreted and validated.
//!
//! On the wire, the `continuity_proposal` token-exchange parameter value is
//! produced by serializing the proposal object as compact UTF-8 JSON and
//! applying unpadded Base64url encoding. The proposal is not a JWT or COSE
//! artifact.
//!
//! Current Profile 0.2 PIC-to-PIC advancement omits `continuity_proposal`;
//! the proposal is used only at initialization (e.g. OAuth-to-PIC exchange).

use crate::authority::AuthorityValue;
use crate::error::{ContinuityError, RejectReason};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The Initial Continuity Proposal JSON object:
/// `{ "type": ..., "executionContract": ... }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitialContinuityProposal {
    /// Proposal definition/schema identifier; must equal
    /// [`crate::PROPOSAL_TYPE_CONTINUITY_INITIAL`].
    #[serde(rename = "type")]
    pub proposal_type: String,
    /// The execution contract supplied by the caller. It constrains
    /// execution; it does not grant authority. At least one attribute with
    /// a valid value is required.
    #[serde(rename = "executionContract")]
    pub execution_contract: BTreeMap<String, AuthorityValue>,
}

impl InitialContinuityProposal {
    /// An Initial Continuity Proposal carrying `execution_contract`.
    pub fn new(execution_contract: BTreeMap<String, AuthorityValue>) -> Self {
        Self {
            proposal_type: crate::PROPOSAL_TYPE_CONTINUITY_INITIAL.to_string(),
            execution_contract,
        }
    }

    /// Validates the proposal: the `type` member identifies the Initial
    /// Continuity Proposal definition, and the execution contract carries
    /// at least one attribute whose value is a non-empty string or a
    /// non-empty array of non-empty strings.
    pub fn validate(&self) -> Result<(), RejectReason> {
        if self.proposal_type != crate::PROPOSAL_TYPE_CONTINUITY_INITIAL {
            return Err(RejectReason::Malformed(format!(
                "unknown continuity proposal type: {}",
                self.proposal_type
            )));
        }
        if self.execution_contract.is_empty() {
            return Err(RejectReason::EmptyExecutionContract);
        }
        for (k, v) in &self.execution_contract {
            v.validate(k)?;
        }
        Ok(())
    }

    /// Encodes the proposal as the `continuity_proposal` parameter value:
    /// compact UTF-8 JSON, then unpadded Base64url.
    pub fn to_continuity_proposal(&self) -> Result<String, ContinuityError> {
        let json = serde_json::to_string(self).map_err(|e| ContinuityError::Json(e.to_string()))?;
        Ok(URL_SAFE_NO_PAD.encode(json.as_bytes()))
    }

    /// Decodes and validates a `continuity_proposal` parameter value.
    pub fn from_continuity_proposal(value: &str) -> Result<Self, ContinuityError> {
        let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|e| {
            ContinuityError::Json(format!("continuity_proposal is not valid base64url: {e}"))
        })?;
        let proposal: Self = serde_json::from_slice(&bytes)
            .map_err(|e| ContinuityError::Json(format!("invalid proposal JSON: {e}")))?;
        proposal.validate()?;
        Ok(proposal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The walkthrough proposal: corporation ACME, department
    /// sensitive-documents.
    fn walkthrough_proposal() -> InitialContinuityProposal {
        let mut contract = BTreeMap::new();
        contract.insert("corporation".into(), AuthorityValue::One("ACME".into()));
        contract.insert(
            "department".into(),
            AuthorityValue::One("sensitive-documents".into()),
        );
        InitialContinuityProposal::new(contract)
    }

    #[test]
    fn json_shape_matches_reference() {
        let proposal = walkthrough_proposal();
        let json = serde_json::to_value(&proposal).unwrap();
        assert_eq!(
            json["type"],
            "https://pic-protocol.org/definitions/proposal-types/continuity-initial"
        );
        assert_eq!(json["executionContract"]["corporation"], "ACME");
        assert_eq!(
            json["executionContract"]["department"],
            "sensitive-documents"
        );
    }

    #[test]
    fn continuity_proposal_roundtrip() {
        let proposal = walkthrough_proposal();
        let encoded = proposal.to_continuity_proposal().unwrap();
        // Unpadded Base64url: no '=', '+', or '/'.
        assert!(!encoded.contains('=') && !encoded.contains('+') && !encoded.contains('/'));
        let decoded = InitialContinuityProposal::from_continuity_proposal(&encoded).unwrap();
        assert_eq!(decoded, proposal);
    }

    #[test]
    fn rejects_invalid_contracts() {
        // {}
        let empty = InitialContinuityProposal::new(BTreeMap::new());
        assert_eq!(
            empty.validate().unwrap_err(),
            RejectReason::EmptyExecutionContract
        );

        // { "corporation": "" }
        let mut contract = BTreeMap::new();
        contract.insert("corporation".into(), AuthorityValue::One("".into()));
        assert!(matches!(
            InitialContinuityProposal::new(contract)
                .validate()
                .unwrap_err(),
            RejectReason::InvalidAuthorityValue(_)
        ));

        // { "departments": [] }
        let mut contract = BTreeMap::new();
        contract.insert("departments".into(), AuthorityValue::Many(vec![]));
        assert!(matches!(
            InitialContinuityProposal::new(contract)
                .validate()
                .unwrap_err(),
            RejectReason::InvalidAuthorityValue(_)
        ));

        // wrong type URI
        let mut wrong = walkthrough_proposal();
        wrong.proposal_type = "https://example.com/other".into();
        assert!(matches!(
            wrong.validate().unwrap_err(),
            RejectReason::Malformed(_)
        ));
    }

    #[test]
    fn rejects_unsupported_json_value_types() {
        // Numbers, booleans, objects, and null are not valid contract values.
        let json = r#"{
            "type": "https://pic-protocol.org/definitions/proposal-types/continuity-initial",
            "executionContract": { "retryCount": 3 }
        }"#;
        let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
        assert!(InitialContinuityProposal::from_continuity_proposal(&encoded).is_err());
    }
}
