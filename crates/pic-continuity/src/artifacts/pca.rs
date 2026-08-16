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
            position,
            context_of_authority: context,
            challenge: PcaChallenge { next_challenge },
        }
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
}
