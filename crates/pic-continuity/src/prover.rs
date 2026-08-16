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

//! PIC Prover (Profile 0.2, centralized settlement).
//!
//! Builds one workload-signed advancement candidate from the current trusted
//! checkpoint, per the Prover procedure of the specification:
//!
//! 1. validate the predecessor continuity state;
//! 2. establish exactly one causal predecessor (`predecessor.hash` over the
//!    exact signed PIC PCA COSE bytes);
//! 3. carry the Proof of Relationship required by the profile;
//! 4. keep or attenuate the predecessor materialized authority — the
//!    candidate never states the resulting authority, the settlement
//!    authority materializes it;
//! 5. bind the concrete request when required;
//! 6. produce the candidate artifacts: Transition COSE → candidate
//!    Continuity COSE → candidate PIC Token JWT, all signed by the same
//!    PoR-bound workload key.

use crate::artifacts::token::{PicTokenClaims, sign_token};
use crate::artifacts::{
    AttenuationsWire, BitmapAttenuation, ContractAdditions, PicContinuityPayload, PicPcaCose,
    PicPcaPayload, PicTransitionCose, PicTransitionPayload, Predecessor, ProofOfRelationship,
    TransitionChallenge, artifact_sha256,
};
use crate::authority::attenuation::{Attenuations, materialize};
use crate::error::{ContinuityError, RejectReason};
use crate::trust::{ArtifactSigner, ArtifactVerifier};

/// What the workload asks the next checkpoint to be.
#[derive(Debug, Clone, Default)]
pub struct CandidateRequest {
    /// Requested attenuations (empty = keep the authority unchanged).
    pub attenuations: Attenuations,
    /// Fresh challenge material for the next transition.
    pub next_challenge: Vec<u8>,
    /// Proof of Relationship evidence for this hop.
    pub proof_of_relationship: Option<ProofOfRelationship>,
    /// Optional request/execution binding digest.
    pub request_digest: Option<Vec<u8>>,
    /// Optional executor evidence, when the deployment requires it.
    pub executor_evidence: Option<ciborium::Value>,
    /// Candidate JWT claims. `iss` is optional identity metadata in the
    /// centralized profile; `aud` conventionally names the settlement
    /// authority.
    pub iss: Option<String>,
    /// Candidate JWT audience; conventionally the settlement authority.
    pub aud: Option<String>,
    /// Candidate JWT issued-at (seconds since the Unix epoch).
    pub iat: Option<i64>,
}

/// The three workload-signed candidate artifacts.
#[derive(Debug, Clone)]
pub struct CandidateArtifacts {
    /// The candidate PIC Token JWT (compact JWS), ready to be submitted as
    /// the RFC 8693 `subject_token`.
    pub token: String,
    /// Exact signed candidate PIC Continuity COSE bytes.
    pub continuity_bytes: Vec<u8>,
    /// Exact signed PIC Continuity Transition COSE bytes.
    pub transition_bytes: Vec<u8>,
    /// The transition payload as built.
    pub transition: PicTransitionPayload,
}

/// Builds a candidate advancement from the exact signed bytes of the
/// current trusted PIC PCA COSE checkpoint.
///
/// When `realm` is provided, the predecessor checkpoint signature is
/// verified first (the Prover applies the Verifier procedure to its
/// predecessor); otherwise the payload is parsed and semantically validated
/// only, which fits workloads that trust their checkpoint delivery channel.
pub fn build_candidate(
    current_pca_bytes: &[u8],
    request: CandidateRequest,
    workload: &dyn ArtifactSigner,
    realm: Option<&dyn ArtifactVerifier>,
) -> Result<CandidateArtifacts, ContinuityError> {
    // 1. Validate the predecessor continuity state.
    let pca_cose = PicPcaCose::from_bytes(current_pca_bytes)?;
    let checkpoint: PicPcaPayload = match realm {
        Some(v) => pca_cose.verify_with(|data, sig| {
            if v.verify(data, sig) {
                Ok(())
            } else {
                Err(crate::cose::CoseError::VerificationFailed)
            }
        })?,
        None => pca_cose.payload_unverified()?,
    };
    checkpoint.validate()?;

    if request.next_challenge.is_empty() {
        return Err(RejectReason::NextChallengeInvalid.into());
    }
    let por = request
        .proof_of_relationship
        .ok_or_else(|| RejectReason::PorRejected("proof_of_relationship is required".into()))?;

    // 4. The Prover checks its own attenuations against the predecessor: an
    //    invalid candidate would be rejected at settlement anyway.
    materialize(&checkpoint.context_of_authority, &request.attenuations)?;

    // 2-5. Assemble the transition: exactly one predecessor, challenge
    //      continuity, attenuations, PoR, optional bindings.
    let attenuations_wire = to_wire(&request.attenuations);
    let transition = PicTransitionPayload {
        profile: crate::PROFILE_0_2.to_string(),
        position: checkpoint.position + 1,
        predecessor: Predecessor {
            predecessor_type: crate::PREDECESSOR_TYPE_PCA.to_string(),
            hash: artifact_sha256(current_pca_bytes),
        },
        challenge: TransitionChallenge {
            previous_challenge: checkpoint.challenge.next_challenge.clone(),
            next_challenge: request.next_challenge,
        },
        attenuations: attenuations_wire,
        proof_of_relationship: por,
        request_digest: request.request_digest,
        executor_evidence: request.executor_evidence,
    };

    // 6. Sign the three candidate artifacts with the same workload key.
    let transition_cose: PicTransitionCose = crate::cose::CoseSigned::sign_with(
        &transition,
        workload.kid(),
        workload.cose_algorithm(),
        |data| workload.sign(data),
    )?;
    let transition_bytes = transition_cose.to_bytes()?;

    let continuity =
        PicContinuityPayload::candidate(current_pca_bytes.to_vec(), transition_bytes.clone());
    let continuity_cose: crate::artifacts::PicContinuityCose = crate::cose::CoseSigned::sign_with(
        &continuity,
        workload.kid(),
        workload.cose_algorithm(),
        |data| workload.sign(data),
    )?;
    let continuity_bytes = continuity_cose.to_bytes()?;

    let mut claims = PicTokenClaims::for_continuity(&continuity_bytes);
    claims.iss = request.iss;
    claims.aud = request.aud;
    claims.iat = request.iat;
    claims.exp = checkpoint.expires_at;
    claims.jti = checkpoint.lineage_id.clone();
    let token = sign_token(&claims, workload)?;

    Ok(CandidateArtifacts {
        token,
        continuity_bytes,
        transition_bytes,
        transition,
    })
}

fn to_wire(attenuations: &Attenuations) -> Option<AttenuationsWire> {
    if attenuations.is_empty() {
        return None;
    }
    Some(AttenuationsWire {
        identity_context: attenuations
            .identity_context
            .as_ref()
            .map(|b| BitmapAttenuation {
                remove_bitmap: b.bytes().to_vec(),
            }),
        invariants: attenuations.invariants.as_ref().map(|b| BitmapAttenuation {
            remove_bitmap: b.bytes().to_vec(),
        }),
        execution_contract: if attenuations.execution_contract_additions.is_empty() {
            None
        } else {
            Some(ContractAdditions {
                additions: attenuations.execution_contract_additions.clone(),
            })
        },
    })
}
