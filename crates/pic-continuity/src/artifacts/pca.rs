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

//! PIC PCA COSE (`pic-pca+cose`): the signed trusted authority checkpoint.

use super::check_profile;
use crate::authority::indexed::IndexedAuthorityMap;
use crate::cose::CoseSigned;
use crate::error::RejectReason;
use serde::{Deserialize, Serialize};

/// Challenge state carried by a PCA checkpoint: the challenge the next
/// transition must answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcaChallenge {
    /// The verifier-issued challenge the next transition must echo as its
    /// `previous_challenge`.
    #[serde(with = "serde_bytes")]
    pub next_challenge: Vec<u8>,
}

/// PIC PCA COSE payload: the signed trusted authority checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PicPcaPayload {
    /// PIC profile identifier; must equal [`crate::PROFILE_0_2`].
    pub profile: String,
    /// Stable lineage identifier for this continuity chain.
    ///
    /// The same value is mirrored into PIC Token JWT `jti`, giving logs and
    /// offline inspectors one correlation handle that survives advancement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage_id: Option<String>,
    /// Absolute NumericDate after which this lineage should no longer be
    /// advanced or accepted as a live token.
    ///
    /// When present, the same value is mirrored into PIC Token JWT `exp`. It is
    /// fixed at initialization and preserved by advancement, so exchanging a
    /// candidate cannot extend authority by minting a fresh token lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Position of this checkpoint in its lineage, starting at `0`.
    pub position: u64,
    /// The canonical Indexed Authority Map in force at this checkpoint.
    pub context_of_authority: IndexedAuthorityMap,
    /// Challenge state binding the next transition to this checkpoint.
    pub challenge: PcaChallenge,
}

impl PicPcaPayload {
    /// A Profile 0.2 checkpoint payload at `position` carrying `context`
    /// and the verifier-issued `next_challenge`.
    pub fn new(position: u64, context: IndexedAuthorityMap, next_challenge: Vec<u8>) -> Self {
        Self {
            profile: crate::PROFILE_0_2.to_string(),
            lineage_id: None,
            expires_at: None,
            position,
            context_of_authority: context,
            challenge: PcaChallenge { next_challenge },
        }
    }

    /// Adds the stable lineage identifier mirrored into PIC Token JWT `jti`.
    pub fn with_lineage_id(mut self, lineage_id: impl Into<String>) -> Self {
        self.lineage_id = Some(lineage_id.into());
        self
    }

    /// Carries a lineage identifier when the predecessor had one.
    pub fn with_optional_lineage_id(mut self, lineage_id: Option<String>) -> Self {
        self.lineage_id = lineage_id;
        self
    }

    /// Adds the absolute lineage expiration mirrored into PIC Token JWT `exp`.
    pub fn with_expires_at(mut self, expires_at: i64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Carries an absolute lineage expiration when the predecessor had one.
    pub fn with_optional_expires_at(mut self, expires_at: Option<i64>) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Rejects the payload unless `profile` is [`crate::PROFILE_0_2`].
    pub fn check_profile(&self) -> Result<(), RejectReason> {
        check_profile("pic-pca+cose", &self.profile)
    }

    /// Validates the checkpoint payload before it is signed or accepted.
    pub fn validate(&self) -> Result<(), RejectReason> {
        self.check_profile()?;
        if self.challenge.next_challenge.is_empty() {
            return Err(RejectReason::NextChallengeInvalid);
        }
        if self.lineage_id.as_deref().is_some_and(str::is_empty) {
            return Err(RejectReason::Malformed(
                "pca.lineage_id must not be empty".to_owned(),
            ));
        }
        if self.expires_at.is_some_and(|expires_at| expires_at <= 0) {
            return Err(RejectReason::Malformed(
                "pca.expires_at must be a positive NumericDate".to_owned(),
            ));
        }
        self.context_of_authority.validate()
    }
}

/// COSE-signed PCA checkpoint.
pub type PicPcaCose = CoseSigned<PicPcaPayload>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{AuthorityValue, Invariant, LogicalAuthority};
    use std::collections::BTreeMap;

    fn sample_map() -> IndexedAuthorityMap {
        let mut contract = BTreeMap::new();
        contract.insert("corporation".into(), AuthorityValue::One("ACME".into()));
        let logical = LogicalAuthority::new(
            None,
            vec![Invariant::new("storage:save", "save", "storage", "*")],
            contract,
        );
        IndexedAuthorityMap::from_logical(&logical).unwrap()
    }

    #[test]
    fn pca_cbor_roundtrip() {
        let pca = PicPcaPayload::new(0, sample_map(), b"challenge-0".to_vec());
        let mut buf = Vec::new();
        ciborium::into_writer(&pca, &mut buf).unwrap();
        let decoded: PicPcaPayload = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(pca, decoded);
        assert!(decoded.check_profile().is_ok());
    }

    #[test]
    fn lineage_id_roundtrips_when_present() {
        let pca = PicPcaPayload::new(0, sample_map(), b"challenge-0".to_vec())
            .with_lineage_id("picx-lineage-1");
        let mut buf = Vec::new();
        ciborium::into_writer(&pca, &mut buf).unwrap();
        let decoded: PicPcaPayload = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(decoded.lineage_id.as_deref(), Some("picx-lineage-1"));
        assert!(decoded.validate().is_ok());
    }

    #[test]
    fn expires_at_roundtrips_when_present() {
        let pca =
            PicPcaPayload::new(0, sample_map(), b"challenge-0".to_vec()).with_expires_at(1234);
        let mut buf = Vec::new();
        ciborium::into_writer(&pca, &mut buf).unwrap();
        let decoded: PicPcaPayload = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(decoded.expires_at, Some(1234));
        assert!(decoded.validate().is_ok());
    }

    #[test]
    fn empty_lineage_id_is_rejected() {
        let pca = PicPcaPayload::new(0, sample_map(), b"challenge-0".to_vec()).with_lineage_id("");

        assert!(matches!(
            pca.validate(),
            Err(RejectReason::Malformed(message)) if message.contains("lineage_id")
        ));
    }

    #[test]
    fn non_positive_expires_at_is_rejected() {
        let pca = PicPcaPayload::new(0, sample_map(), b"challenge-0".to_vec()).with_expires_at(0);

        assert!(matches!(
            pca.validate(),
            Err(RejectReason::Malformed(message)) if message.contains("expires_at")
        ));
    }
}
