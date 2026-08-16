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

//! PIC Continuity COSE (`pic-continuity+cose`): the signed continuity
//! container carrying a trusted PCA checkpoint and either no proposed
//! transitions (settled, `null`) or exactly one proposed transition
//! (candidate).

use super::{artifact_sha256, check_profile};
use crate::cose::CoseSigned;
use crate::error::RejectReason;
use serde::{Deserialize, Serialize};

/// The current trusted checkpoint carried by a Continuity: exact signed
/// PIC PCA COSE bytes and their SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuityRoot {
    /// SHA-256 of `pca`. Verifiers recompute it from `pca` and never trust
    /// the stored value ([`PicContinuityPayload::check_root_hash`]).
    #[serde(with = "serde_bytes")]
    pub pca_hash: Vec<u8>,
    /// Exact signed bytes of the current PIC PCA COSE checkpoint.
    #[serde(with = "serde_bytes")]
    pub pca: Vec<u8>,
}

/// PIC Continuity COSE payload.
///
/// `transitions` is always semantically present: `None` (CBOR null) means
/// settled; a candidate carries exactly one workload-signed PIC Continuity
/// Transition COSE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PicContinuityPayload {
    /// PIC profile identifier; must equal [`crate::PROFILE_0_2`].
    pub profile: String,
    /// The current trusted checkpoint (exact bytes plus digest).
    pub root: ContinuityRoot,
    /// `None` (CBOR null) for a settled state; exactly one workload-signed
    /// PIC Continuity Transition COSE (exact bytes) for a candidate.
    pub transitions: Option<Vec<serde_bytes::ByteBuf>>,
}

impl PicContinuityPayload {
    fn root_for(exact_pca_bytes: Vec<u8>) -> ContinuityRoot {
        ContinuityRoot {
            pca_hash: artifact_sha256(&exact_pca_bytes),
            pca: exact_pca_bytes,
        }
    }

    /// A settled Continuity: `transitions = null`.
    pub fn settled(exact_pca_bytes: Vec<u8>) -> Self {
        Self {
            profile: crate::PROFILE_0_2.to_string(),
            root: Self::root_for(exact_pca_bytes),
            transitions: None,
        }
    }

    /// A candidate Continuity: exactly one proposed transition.
    pub fn candidate(exact_pca_bytes: Vec<u8>, exact_transition_bytes: Vec<u8>) -> Self {
        Self {
            profile: crate::PROFILE_0_2.to_string(),
            root: Self::root_for(exact_pca_bytes),
            transitions: Some(vec![serde_bytes::ByteBuf::from(exact_transition_bytes)]),
        }
    }

    /// `true` when `transitions` is null (settled state).
    pub fn is_settled(&self) -> bool {
        self.transitions.is_none()
    }

    /// For a settled Continuity, `transitions` must be null.
    pub fn require_settled(&self) -> Result<(), RejectReason> {
        if self.is_settled() {
            Ok(())
        } else {
            Err(RejectReason::SettledCarriesTransitions)
        }
    }

    /// For a candidate, returns the exact bytes of the single transition.
    pub fn candidate_transition(&self) -> Result<&[u8], RejectReason> {
        match &self.transitions {
            Some(list) if list.len() == 1 => Ok(list[0].as_ref()),
            Some(list) => Err(RejectReason::TransitionCount(list.len())),
            None => Err(RejectReason::TransitionCount(0)),
        }
    }

    /// Recomputes and checks `root.pca_hash` against the exact `root.pca`
    /// bytes. Verifiers MUST recompute; the stored digest is never trusted.
    pub fn check_root_hash(&self) -> Result<(), RejectReason> {
        if artifact_sha256(&self.root.pca) == self.root.pca_hash {
            Ok(())
        } else {
            Err(RejectReason::PcaHashMismatch)
        }
    }

    /// Rejects the payload unless `profile` is [`crate::PROFILE_0_2`].
    pub fn check_profile(&self) -> Result<(), RejectReason> {
        check_profile("pic-continuity+cose", &self.profile)
    }
}

/// COSE-signed Continuity.
pub type PicContinuityCose = CoseSigned<PicContinuityPayload>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuity_settled_vs_candidate() {
        let pca_bytes = b"exact-signed-pca-bytes".to_vec();

        let settled = PicContinuityPayload::settled(pca_bytes.clone());
        assert!(settled.is_settled());
        assert!(settled.require_settled().is_ok());
        assert!(settled.check_root_hash().is_ok());
        assert_eq!(
            settled.candidate_transition().unwrap_err(),
            RejectReason::TransitionCount(0)
        );

        let candidate =
            PicContinuityPayload::candidate(pca_bytes.clone(), b"transition-bytes".to_vec());
        assert!(!candidate.is_settled());
        assert_eq!(
            candidate.require_settled().unwrap_err(),
            RejectReason::SettledCarriesTransitions
        );
        assert_eq!(
            candidate.candidate_transition().unwrap(),
            b"transition-bytes"
        );

        // Two transitions are unrepresentable through the constructors and
        // rejected when arriving from the wire.
        let mut two = candidate.clone();
        two.transitions = Some(vec![
            serde_bytes::ByteBuf::from(b"t1".to_vec()),
            serde_bytes::ByteBuf::from(b"t2".to_vec()),
        ]);
        assert_eq!(
            two.candidate_transition().unwrap_err(),
            RejectReason::TransitionCount(2)
        );
    }

    #[test]
    fn root_hash_recomputed_not_trusted() {
        let mut settled = PicContinuityPayload::settled(b"pca".to_vec());
        settled.root.pca_hash[0] ^= 0xFF;
        assert_eq!(
            settled.check_root_hash().unwrap_err(),
            RejectReason::PcaHashMismatch
        );
    }

    #[test]
    fn transitions_null_is_explicit_on_the_wire() {
        let settled = PicContinuityPayload::settled(b"pca".to_vec());
        let mut buf = Vec::new();
        ciborium::into_writer(&settled, &mut buf).unwrap();
        let decoded: PicContinuityPayload = ciborium::from_reader(buf.as_slice()).unwrap();
        assert!(decoded.is_settled());
    }
}
