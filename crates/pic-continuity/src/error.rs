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

//! Error types.
//!
//! [`RejectReason`] mirrors the individual checks of the Verifier procedure,
//! so a rejection always says *which* check failed. [`ContinuityError`] wraps
//! rejections together with encoding-level failures.

use thiserror::Error;

/// A semantic rejection: one of the Verifier or Prover checks failed.
///
/// Variants follow the settlement procedure of the Prover and Verifier
/// specification (Section 3) so callers can map a rejection back to the
/// exact spec check.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RejectReason {
    // -- candidate shape (steps 1-5) --
    /// The candidate could not be parsed into the expected artifact shape.
    #[error("candidate is malformed: {0}")]
    Malformed(String),
    /// An artifact declares a profile other than the one this crate
    /// implements ([`crate::PROFILE_0_2`]).
    #[error("profile mismatch on {artifact}: expected {expected}, got {got}")]
    ProfileMismatch {
        /// Which artifact carried the mismatching profile.
        artifact: &'static str,
        /// The profile identifier this crate requires.
        expected: String,
        /// The profile identifier found in the artifact.
        got: String,
    },
    /// A settled Continuity carried a non-null `transitions` member.
    #[error("settled continuity must carry transitions = null")]
    SettledCarriesTransitions,
    /// A candidate Continuity carried a number of transitions other than
    /// exactly one.
    #[error("candidate continuity must carry exactly one transition, got {0}")]
    TransitionCount(usize),

    // -- proof of relationship (steps 6-11) --
    /// `proof_of_relationship.type` is not the type the validator accepts.
    #[error("proof_of_relationship.type not accepted: {0}")]
    PorType(String),
    /// The Proof of Relationship evidence failed validation.
    #[error("proof of relationship rejected: {0}")]
    PorRejected(String),
    /// A workload signature over a candidate artifact did not verify.
    #[error("workload signature invalid on {0}")]
    WorkloadSignature(&'static str),

    // -- checkpoint binding (steps 12-16) --
    /// `root.pca` is not the exact bytes of a currently trusted checkpoint.
    #[error("root.pca is not the currently trusted checkpoint")]
    UntrustedCheckpoint,
    /// The recomputed SHA-256 of `root.pca` differs from `root.pca_hash`.
    #[error("root.pca_hash does not match SHA-256 of the exact root.pca bytes")]
    PcaHashMismatch,
    /// `predecessor.type` is not [`crate::PREDECESSOR_TYPE_PCA`].
    #[error("predecessor.type must be \"pca\"")]
    PredecessorType,
    /// `predecessor.hash` does not match the trusted checkpoint bytes.
    #[error("predecessor.hash does not match the trusted checkpoint bytes")]
    PredecessorHashMismatch,
    /// The proposed position is not exactly checkpoint position + 1.
    #[error("transition.position must equal checkpoint position + 1")]
    PositionProgression,
    /// `previous_challenge` does not echo the checkpoint's `next_challenge`.
    #[error("previous_challenge does not match the checkpoint next_challenge")]
    ChallengeContinuity,
    /// The proposed `next_challenge` is missing, empty, or not fresh.
    #[error("next_challenge is missing or empty")]
    NextChallengeInvalid,

    // -- attenuation (step 17) --
    /// A removal bitmap set a bit for an index the predecessor section does
    /// not have.
    #[error("remove bitmap references a nonexistent index in section {0}")]
    BitmapIndexOutOfRange(&'static str),
    /// A removal bitmap is empty or carries trailing zero bytes.
    #[error("remove bitmap is not canonical (empty or trailing zero bytes)")]
    BitmapNotCanonical,
    /// Two execution-contract additions resolved to the same canonical key.
    #[error("duplicate execution-contract addition key: {0}")]
    DuplicateAdditionKey(String),
    /// An authority value is empty or not a valid canonical tuple value.
    #[error("invalid authority value for key {0}")]
    InvalidAuthorityValue(String),
    /// The execution contract would end up with no attributes.
    #[error("execution contract must contain at least one attribute")]
    EmptyExecutionContract,

    // -- evidence and binding (step 18) --
    /// Deployment-required request/execution binding failed.
    #[error("request/execution binding rejected")]
    RequestBinding,
    /// Executor evidence or execution-contract conformance failed.
    #[error("executor evidence / execution-contract conformance rejected")]
    ContractConformance,

    // -- non-expansion, revocation, policy (step 19) --
    /// The materialized successor would carry authority its predecessor did
    /// not have.
    #[error("authority non-expansion violated")]
    NonExpansion,
    /// The continuity state is revoked.
    #[error("continuity state is revoked")]
    Revoked,
    /// Local deployment policy denied the advancement.
    #[error("local policy denied the advancement")]
    PolicyDenied,

    // -- settled-artifact verification --
    /// A settlement-authority (realm) signature did not verify.
    #[error("settlement-authority signature invalid on {0}")]
    RealmSignature(&'static str),
}

/// Any failure while producing or validating continuity state.
#[derive(Debug, Error)]
pub enum ContinuityError {
    /// A semantic Verifier or Prover check failed.
    #[error(transparent)]
    Reject(#[from] RejectReason),

    /// A COSE envelope could not be built, parsed, or verified.
    #[error("COSE error: {0}")]
    Cose(#[from] crate::cose::CoseError),

    /// CBOR (de)serialization of a payload failed.
    #[error("CBOR encoding failed: {0}")]
    Cbor(String),

    /// JSON (de)serialization of a JSON protocol object failed.
    #[error("JSON error: {0}")]
    Json(String),

    /// The JWS envelope of the PIC Token could not be built or parsed.
    #[error("JWS error: {0}")]
    Jws(String),
}
