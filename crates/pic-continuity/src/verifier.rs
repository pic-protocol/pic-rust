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

//! PIC Verifier (Profile 0.2).
//!
//! Two roles:
//!
//! - [`verify_settled`] — ordinary verification of a settled PIC Token JWT
//!   before any authority is exercised;
//! - [`SettlementAuthority`] — the trusted settlement role (PIC-X is one
//!   realization): validates a workload-signed advancement candidate through
//!   the complete numbered procedure of the specification and, on success,
//!   materializes the next checkpoint and issues the next settled token.
//!   [`issue_settled`] covers initialization (checkpoint 0).
//!
//! A valid signature establishes *integrity*, not *semantic validity*: the
//! semantic checks run independently and are never skipped because a
//! signature verified.

use crate::artifacts::token::{DecodedToken, PicTokenClaims, decode_token, sign_token};
use crate::artifacts::{
    PicContinuityCose, PicContinuityPayload, PicPcaCose, PicPcaPayload, PicTransitionCose,
    PicTransitionPayload, artifact_sha256,
};
use crate::authority::attenuation::{AttenuationOrder, Attenuations, materialize};
use crate::cose::CoseSigned;
use crate::error::{ContinuityError, RejectReason};
use crate::por::PorValidator;
use crate::trust::{
    ArtifactSigner, ArtifactVerifier, RevocationCheck, SettlementPolicy, TrustedCheckpoint,
};

// ---------------------------------------------------------------------------
// Ordinary verification of settled artifacts
// ---------------------------------------------------------------------------

/// A verified settled continuity state.
#[derive(Debug, Clone)]
pub struct SettledState {
    /// The verified PIC Token JWT claim set.
    pub claims: PicTokenClaims,
    /// The verified settled PIC Continuity payload (`transitions = null`).
    pub continuity: PicContinuityPayload,
    /// Exact signed PIC PCA COSE bytes of the current trusted checkpoint.
    pub pca_bytes: Vec<u8>,
    /// The decoded checkpoint payload: position, authority, challenge.
    pub checkpoint: PicPcaPayload,
}

/// Verifies a settled PIC Token JWT end to end:
/// realm JWT signature → `pic.root` exact bytes → realm Continuity signature
/// → `transitions = null` → exact `root.pca` bytes → recomputed
/// `root.pca_hash` → realm PCA signature → materialized authority.
pub fn verify_settled(
    token: &str,
    realm: &dyn ArtifactVerifier,
) -> Result<SettledState, ContinuityError> {
    let decoded = decode_token(token)?;
    check_token_type(&decoded)?;
    check_expected_jws_algorithm(&decoded, realm, "PIC Token JWT")?;
    if !realm.verify(&decoded.signing_input, &decoded.signature) {
        return Err(RejectReason::RealmSignature("PIC Token JWT").into());
    }
    let claims = decoded.claims;
    check_claims_profile(&claims)?;

    let continuity_bytes = claims.root_bytes()?;
    let continuity_cose = PicContinuityCose::from_bytes(&continuity_bytes)?;
    check_expected_cose_algorithm(continuity_cose.algorithm(), realm, "PIC Continuity COSE")?;
    let continuity: PicContinuityPayload = continuity_cose
        .verify_with(|data, sig| {
            if realm.verify(data, sig) {
                Ok(())
            } else {
                Err(crate::cose::CoseError::VerificationFailed)
            }
        })
        .map_err(|_| RejectReason::RealmSignature("PIC Continuity COSE"))?;
    continuity.check_profile()?;
    continuity.require_settled()?;
    continuity.check_root_hash()?;

    let pca_bytes = continuity.root.pca.clone();
    let pca_cose = PicPcaCose::from_bytes(&pca_bytes)?;
    check_expected_cose_algorithm(pca_cose.algorithm(), realm, "PIC PCA COSE")?;
    let checkpoint: PicPcaPayload = pca_cose
        .verify_with(|data, sig| {
            if realm.verify(data, sig) {
                Ok(())
            } else {
                Err(crate::cose::CoseError::VerificationFailed)
            }
        })
        .map_err(|_| RejectReason::RealmSignature("PIC PCA COSE"))?;
    checkpoint.validate()?;
    check_exp_matches_checkpoint(&claims, &checkpoint, "PIC Token JWT")?;

    Ok(SettledState {
        claims,
        continuity,
        pca_bytes,
        checkpoint,
    })
}

// ---------------------------------------------------------------------------
// Settlement (initialization)
// ---------------------------------------------------------------------------

/// Claims metadata for a settled token.
#[derive(Debug, Clone, Default)]
pub struct SettlementContext {
    /// Realm issuer identity, e.g. `https://pic-x.example.com/realms/acme`.
    pub iss: String,
    /// Subject claim for the settled token.
    pub sub: Option<String>,
    /// Audience claim for the settled token.
    pub aud: Option<String>,
    /// Issued-at (seconds since the Unix epoch).
    pub iat: Option<i64>,
    /// Expiry (seconds since the Unix epoch).
    pub exp: Option<i64>,
    /// Token identifier.
    pub jti: Option<String>,
}

/// A newly settled continuity state.
#[derive(Debug, Clone)]
pub struct SettledIssue {
    /// The settled PIC Token JWT (compact JWS).
    pub token: String,
    /// Exact signed bytes of the new PIC PCA COSE checkpoint.
    pub pca_bytes: Vec<u8>,
    /// The new checkpoint payload: position, authority, challenge.
    pub checkpoint: PicPcaPayload,
    /// Exact signed bytes of the settled PIC Continuity COSE.
    pub continuity_bytes: Vec<u8>,
}

/// Signs a checkpoint into the settled artifact chain:
/// PIC PCA COSE → settled PIC Continuity COSE (`transitions = null`) →
/// settled PIC Token JWT. This is the initialization path (checkpoint 0,
/// e.g. after an OAuth-to-PIC exchange) and the tail of every settlement.
pub fn issue_settled(
    checkpoint: PicPcaPayload,
    realm: &dyn ArtifactSigner,
    ctx: &SettlementContext,
) -> Result<SettledIssue, ContinuityError> {
    checkpoint.validate()?;
    let exp = match (checkpoint.expires_at, ctx.exp) {
        (Some(checkpoint_exp), Some(context_exp)) if checkpoint_exp != context_exp => {
            return Err(RejectReason::Malformed(
                "settlement context exp does not match pca.expires_at".to_owned(),
            )
            .into());
        }
        (Some(checkpoint_exp), _) => Some(checkpoint_exp),
        (None, context_exp) => context_exp,
    };

    let pca_cose: PicPcaCose =
        CoseSigned::sign_with(&checkpoint, realm.kid(), realm.cose_algorithm(), |data| {
            realm.sign(data)
        })?;
    let pca_bytes = pca_cose.to_bytes()?;

    let continuity = PicContinuityPayload::settled(pca_bytes.clone());
    let continuity_cose: PicContinuityCose =
        CoseSigned::sign_with(&continuity, realm.kid(), realm.cose_algorithm(), |data| {
            realm.sign(data)
        })?;
    let continuity_bytes = continuity_cose.to_bytes()?;

    let mut claims = PicTokenClaims::for_continuity(&continuity_bytes);
    claims.iss = Some(ctx.iss.clone());
    claims.sub = ctx.sub.clone();
    claims.aud = ctx.aud.clone();
    claims.iat = ctx.iat;
    claims.exp = exp;
    if let (Some(checkpoint_lineage), Some(context_jti)) = (&checkpoint.lineage_id, &ctx.jti)
        && checkpoint_lineage != context_jti
    {
        return Err(RejectReason::Malformed(
            "settlement context jti does not match pca.lineage_id".to_owned(),
        )
        .into());
    }
    claims.jti = ctx.jti.clone().or_else(|| checkpoint.lineage_id.clone());
    let token = sign_token(&claims, realm)?;

    Ok(SettledIssue {
        token,
        pca_bytes,
        checkpoint,
        continuity_bytes,
    })
}

// ---------------------------------------------------------------------------
// Settlement (centralized advancement)
// ---------------------------------------------------------------------------

/// The trusted settlement authority for Profile 0.2 centralized advancement.
pub struct SettlementAuthority<'a> {
    /// Store answering whether exact PCA bytes are currently trusted.
    pub trusted: &'a dyn TrustedCheckpoint,
    /// Proof of Relationship validator for this deployment.
    pub por: &'a dyn PorValidator,
    /// Revocation state lookup.
    pub revocation: &'a dyn RevocationCheck,
    /// Deployment policy hooks (request binding, conformance, local policy).
    pub policy: &'a dyn SettlementPolicy,
    /// The attenuation order used for the non-expansion check.
    pub order: &'a dyn AttenuationOrder,
    /// The realm signing key for the settled artifacts.
    pub realm: &'a dyn ArtifactSigner,
}

impl SettlementAuthority<'_> {
    /// Validates a workload-signed candidate PIC Token JWT and, on success,
    /// materializes checkpoint N+1 and issues the next settled token.
    ///
    /// The numbered comments follow the settlement procedure of the Prover
    /// and Verifier specification (Section 3.1).
    pub fn settle(
        &self,
        candidate_token: &str,
        ctx: &SettlementContext,
    ) -> Result<SettledIssue, ContinuityError> {
        // 1-2. Receive the candidate as untrusted input; parse without
        //      accepting authenticity; obtain pic.root bytes.
        let decoded = decode_token(candidate_token)
            .map_err(|e| RejectReason::Malformed(format!("candidate token: {e}")))?;
        check_token_type(&decoded)?;
        check_claims_profile(&decoded.claims)?;
        let continuity_bytes = decoded
            .claims
            .root_bytes()
            .map_err(|e| RejectReason::Malformed(format!("pic.root: {e}")))?;

        // 3. Parse the candidate Continuity without accepting authenticity;
        //    validate the presence and shape of root and transitions.
        let continuity_cose = PicContinuityCose::from_bytes(&continuity_bytes)
            .map_err(|e| RejectReason::Malformed(format!("candidate continuity: {e}")))?;
        let continuity: PicContinuityPayload = continuity_cose
            .payload_unverified()
            .map_err(|e| RejectReason::Malformed(format!("candidate continuity: {e}")))?;
        continuity.check_profile()?;
        if continuity.root.pca.is_empty() || continuity.root.pca_hash.is_empty() {
            return Err(RejectReason::Malformed("empty continuity root".into()).into());
        }

        // 4. Exactly one transition.
        let transition_bytes = continuity.candidate_transition()?.to_vec();

        // 5. Parse the Transition as untrusted input.
        let transition_cose = PicTransitionCose::from_bytes(&transition_bytes)
            .map_err(|e| RejectReason::Malformed(format!("transition: {e}")))?;
        let transition: PicTransitionPayload = transition_cose
            .payload_unverified()
            .map_err(|e| RejectReason::Malformed(format!("transition: {e}")))?;
        transition.check_profile()?;

        // 6-7. Validate the proof_of_relationship structure and type.
        let por = &transition.proof_of_relationship;
        if por.por_type != self.por.accepted_type() {
            return Err(RejectReason::PorType(por.por_type.clone()).into());
        }
        if por.evidence.is_empty() {
            return Err(RejectReason::PorRejected("empty evidence".into()).into());
        }

        // 8-10. Validate the evidence per the selected schema and obtain the
        //       accepted workload verification key.
        let workload = self.por.validate(por)?;

        // 11. Verify the three workload signatures with that key and their
        //     signer consistency.
        check_expected_cose_algorithm(
            transition_cose.algorithm(),
            workload.as_ref(),
            "PIC Continuity Transition COSE",
        )?;
        transition_cose
            .verify_with(|data, sig| {
                if workload.verify(data, sig) {
                    Ok(())
                } else {
                    Err(crate::cose::CoseError::VerificationFailed)
                }
            })
            .map_err(|_| RejectReason::WorkloadSignature("PIC Continuity Transition COSE"))?;
        check_expected_cose_algorithm(
            continuity_cose.algorithm(),
            workload.as_ref(),
            "candidate PIC Continuity COSE",
        )?;
        continuity_cose
            .verify_with(|data, sig| {
                if workload.verify(data, sig) {
                    Ok(())
                } else {
                    Err(crate::cose::CoseError::VerificationFailed)
                }
            })
            .map_err(|_| RejectReason::WorkloadSignature("candidate PIC Continuity COSE"))?;
        check_expected_jws_algorithm(&decoded, workload.as_ref(), "candidate PIC Token JWT")?;
        if !workload.verify(&decoded.signing_input, &decoded.signature) {
            return Err(RejectReason::WorkloadSignature("candidate PIC Token JWT").into());
        }

        // 12. root.pca must be the exact bytes of the currently trusted
        //     checkpoint.
        if !self.trusted.is_current_checkpoint(&continuity.root.pca) {
            return Err(RejectReason::UntrustedCheckpoint.into());
        }
        let checkpoint: PicPcaPayload = PicPcaCose::from_bytes(&continuity.root.pca)
            .map_err(|e| RejectReason::Malformed(format!("checkpoint: {e}")))?
            .payload_unverified()
            .map_err(|e| RejectReason::Malformed(format!("checkpoint: {e}")))?;
        checkpoint.validate()?;
        if let Some(checkpoint_lineage) = checkpoint.lineage_id.as_deref() {
            match decoded.claims.jti.as_deref() {
                Some(candidate_jti) if candidate_jti == checkpoint_lineage => {}
                Some(_) => {
                    return Err(RejectReason::Malformed(
                        "candidate token jti does not match checkpoint lineage_id".to_owned(),
                    )
                    .into());
                }
                None => {
                    return Err(RejectReason::Malformed(
                        "candidate token is missing jti for checkpoint lineage_id".to_owned(),
                    )
                    .into());
                }
            }
        }
        check_exp_matches_checkpoint(&decoded.claims, &checkpoint, "candidate PIC Token JWT")?;

        // 13. Recompute SHA-256(exact root.pca bytes) and compare.
        continuity.check_root_hash()?;

        // 14. Position progression.
        if transition.position != checkpoint.position + 1 {
            return Err(RejectReason::PositionProgression.into());
        }

        // 15. Predecessor reference: type "pca", hash over the exact
        //     trusted checkpoint bytes.
        if transition.predecessor.predecessor_type != crate::PREDECESSOR_TYPE_PCA {
            return Err(RejectReason::PredecessorType.into());
        }
        if transition.predecessor.hash != artifact_sha256(&continuity.root.pca) {
            return Err(RejectReason::PredecessorHashMismatch.into());
        }

        // 16. Challenge continuity and next-challenge validity.
        if transition.challenge.previous_challenge != checkpoint.challenge.next_challenge {
            return Err(RejectReason::ChallengeContinuity.into());
        }
        if transition.challenge.next_challenge.is_empty() {
            return Err(RejectReason::NextChallengeInvalid.into());
        }

        // 17. Validate removal bitmaps and execution-contract additions;
        //     materialize the successor authority (deterministic ordering
        //     and index assignment happen here).
        let attenuations: Attenuations = match &transition.attenuations {
            Some(wire) => wire.parse()?,
            None => Attenuations::default(),
        };
        let next_authority = materialize(&checkpoint.context_of_authority, &attenuations)?;

        // 18. Request/execution binding and executor evidence / conformance,
        //     when required by the deployment.
        if !self.policy.request_binding(&transition) {
            return Err(RejectReason::RequestBinding.into());
        }
        if !self.policy.conformance(&checkpoint, &transition) {
            return Err(RejectReason::ContractConformance.into());
        }

        // 19. Non-expansion under the selected attenuation order, revocation,
        //     and local policy.
        if !self
            .order
            .attenuates(&next_authority, &checkpoint.context_of_authority)
        {
            return Err(RejectReason::NonExpansion.into());
        }
        if self
            .revocation
            .is_revoked(&checkpoint, &continuity.root.pca)
        {
            return Err(RejectReason::Revoked.into());
        }
        if !self.policy.policy(&checkpoint, &next_authority) {
            return Err(RejectReason::PolicyDenied.into());
        }

        // 20. Materialize checkpoint N+1, transfer the accepted next
        //     challenge, and issue the settled artifacts.
        let next_checkpoint = PicPcaPayload::new(
            transition.position,
            next_authority,
            transition.challenge.next_challenge.clone(),
        )
        .with_optional_lineage_id(checkpoint.lineage_id.clone())
        .with_optional_expires_at(checkpoint.expires_at);
        issue_settled(next_checkpoint, self.realm, ctx)
    }
}

fn check_token_type(decoded: &DecodedToken) -> Result<(), RejectReason> {
    if decoded.typ == crate::FORMAT_PIC_TOKEN_JWT {
        Ok(())
    } else {
        Err(RejectReason::Malformed(format!(
            "PIC Token JWT typ must be {}, got {}",
            crate::FORMAT_PIC_TOKEN_JWT,
            decoded.typ
        )))
    }
}

fn check_claims_profile(claims: &PicTokenClaims) -> Result<(), RejectReason> {
    if claims.profile == crate::PROFILE_0_2 {
        Ok(())
    } else {
        Err(RejectReason::ProfileMismatch {
            artifact: "pic+jwt",
            expected: crate::PROFILE_0_2.to_string(),
            got: claims.profile.clone(),
        })
    }
}

fn check_expected_jws_algorithm(
    decoded: &DecodedToken,
    verifier: &dyn ArtifactVerifier,
    artifact: &'static str,
) -> Result<(), RejectReason> {
    let Some(expected) = verifier.expected_jws_algorithm() else {
        return Ok(());
    };
    if decoded.alg == expected {
        return Ok(());
    }
    Err(RejectReason::Malformed(format!(
        "{artifact} alg must be {expected}, got {}",
        decoded.alg
    )))
}

fn check_expected_cose_algorithm(
    actual: Option<crate::cose::SigningAlgorithm>,
    verifier: &dyn ArtifactVerifier,
    artifact: &'static str,
) -> Result<(), RejectReason> {
    let Some(expected) = verifier.expected_cose_algorithm() else {
        return Ok(());
    };
    if actual == Some(expected) {
        return Ok(());
    }
    Err(RejectReason::Malformed(format!(
        "{artifact} alg must be {expected}, got {}",
        actual
            .map(|algorithm| algorithm.to_string())
            .unwrap_or_else(|| "None".to_owned())
    )))
}

fn check_exp_matches_checkpoint(
    claims: &PicTokenClaims,
    checkpoint: &PicPcaPayload,
    artifact: &'static str,
) -> Result<(), RejectReason> {
    let Some(expires_at) = checkpoint.expires_at else {
        return Ok(());
    };
    match claims.exp {
        Some(exp) if exp == expires_at => Ok(()),
        Some(exp) => Err(RejectReason::Malformed(format!(
            "{artifact} exp does not match pca.expires_at: expected {expires_at}, got {exp}"
        ))),
        None => Err(RejectReason::Malformed(format!(
            "{artifact} is missing exp for pca.expires_at"
        ))),
    }
}
