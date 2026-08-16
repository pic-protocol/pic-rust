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

//! Profile 0.2 artifacts, one file per protocol object:
//!
//! - [`pca`] — PIC PCA COSE, the signed trusted authority checkpoint;
//! - [`continuity`] — PIC Continuity COSE, the signed continuity container;
//! - [`transition`] — PIC Continuity Transition COSE, the workload-signed
//!   causal authority transition;
//! - [`token`] — the PIC Token JWT external envelope.
//!
//! Every signed-artifact hash in Profile 0.2 (`root.pca_hash`,
//! `predecessor.hash`) is SHA-256 over the **exact signed artifact bytes** —
//! never over a decoded payload or a re-serialized structure. The helpers
//! here only accept raw byte slices, so the API shape enforces the rule.

pub mod continuity;
pub mod pca;
pub mod token;
pub mod transition;

pub use continuity::{ContinuityRoot, PicContinuityCose, PicContinuityPayload};
pub use pca::{PcaChallenge, PicPcaCose, PicPcaPayload};
pub use transition::{
    AttenuationsWire, BitmapAttenuation, ContractAdditions, PicTransitionCose,
    PicTransitionPayload, Predecessor, ProofOfRelationship, TransitionChallenge,
};

use crate::error::RejectReason;
use sha2::{Digest, Sha256};

/// SHA-256 over exact signed artifact bytes.
pub fn artifact_sha256(exact_signed_bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(exact_signed_bytes).to_vec()
}

/// Rejects a payload whose `profile` member is not [`crate::PROFILE_0_2`].
fn check_profile(artifact: &'static str, got: &str) -> Result<(), RejectReason> {
    if got == crate::PROFILE_0_2 {
        Ok(())
    } else {
        Err(RejectReason::ProfileMismatch {
            artifact,
            expected: crate::PROFILE_0_2.to_string(),
            got: got.to_string(),
        })
    }
}
