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

//! Proof of Relationship validation boundary.
//!
//! `proof_of_relationship` is a typed container: `type` selects how
//! `evidence` is parsed and validated, and the selected schema must bind or
//! identify the workload verification key used to verify the three
//! workload-signed candidate artifacts.
//!
//! Current Profile 0.2 requires `type = "sd-jwt"` with the exact UTF-8 bytes
//! of the textual issuer-signed SD-JWT presentation as evidence. This crate
//! does **not** ship an SD-JWT (RFC 9901) implementation yet: deployments
//! plug their SD-JWT stack (issuer trust, disclosure processing, key
//! extraction) through [`PorValidator`]. PoR evidence supports the accepted
//! relationship; it is not, by itself, Proof of Continuity — the Verifier
//! still performs every other required check.

use crate::artifacts::ProofOfRelationship;
use crate::error::RejectReason;
use crate::trust::ArtifactVerifier;

/// Validates PoR evidence and yields the accepted workload verifier.
pub trait PorValidator {
    /// The `proof_of_relationship.type` value this validator accepts.
    /// Current Profile 0.2 requires `"sd-jwt"`.
    fn accepted_type(&self) -> &str {
        crate::POR_TYPE_SD_JWT
    }

    /// Parses and validates the evidence per the selected schema (issuer
    /// signature, issuer trust, required disclosures, claims), returning the
    /// verifier for the PoR-bound workload key.
    ///
    /// The caller has already checked `por.por_type` against
    /// [`accepted_type`](Self::accepted_type); implementations may rely on it.
    fn validate(
        &self,
        por: &ProofOfRelationship,
    ) -> Result<Box<dyn ArtifactVerifier>, RejectReason>;
}
