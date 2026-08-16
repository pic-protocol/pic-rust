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

//! PIC Profile 0.2 — continuity artifacts, Prover, and Verifier.
//!
//! Implements the artifact family and procedures of the
//! *PIC Prover and Verifier Specification* (draft 0.2):
//!
//! - [`artifacts`] — PIC PCA COSE, PIC Continuity COSE, PIC Continuity
//!   Transition COSE, and the PIC Token JWT envelope;
//! - [`authority`] — Logical Context of Authority, canonical Indexed
//!   Authority Map, removal bitmaps, execution-contract additions, and the
//!   non-expansion order;
//! - [`proposal`] — the Initial Continuity Proposal JSON object and its
//!   `continuity_proposal` wire encoding (compact JSON, unpadded Base64url);
//! - [`prover`] — builds a workload-signed advancement candidate from the
//!   current trusted checkpoint;
//! - [`verifier`] — ordinary verification of settled artifacts and the
//!   settlement-authority validation procedure (the role PIC-X realizes);
//! - [`por`] — the pluggable Proof of Relationship validation boundary;
//! - [`trust`] — the traits a host supplies (trusted checkpoints, key
//!   material, revocation, policy);
//! - [`cose`] — a generic, crypto-agnostic COSE_Sign1 envelope. Self
//!   contained by design: it is the candidate for extraction into its own
//!   crate when a second consumer needs it.
//!
//! The Verifier is pure: it performs no I/O, and everything environmental
//! (trusted checkpoint state, issuer trust, revocation, policy) enters
//! through the [`trust`] and [`por`] traits.
//!
//! # Roles
//!
//! | Role | Entry point |
//! |------|-------------|
//! | Workload / Prover | [`prover::build_candidate`] |
//! | Ordinary verifier | [`verifier::verify_settled`] |
//! | Settlement authority (realm) | [`verifier::SettlementAuthority::settle`], [`verifier::issue_settled`] |
//!
//! # Example: issue and verify a settled state
//!
//! The initialization path — a realm signs checkpoint 0 (for example after
//! an OAuth-to-PIC token exchange) and any holder of the realm public key
//! verifies the resulting PIC Token JWT offline:
//!
//! ```
//! use pic_continuity::artifacts::PicPcaPayload;
//! use pic_continuity::authority::{
//!     AuthorityValue, IndexedAuthorityMap, Invariant, LogicalAuthority,
//! };
//! use pic_continuity::trust::{Ed25519Signer, Ed25519Verifier};
//! use pic_continuity::verifier::{issue_settled, verify_settled, SettlementContext};
//! use std::collections::BTreeMap;
//!
//! // The realm signing key (settlement authority).
//! let realm_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
//! let realm = Ed25519Signer::new(realm_key, "https://pic-x.example.com/realms/acme#key-1");
//!
//! // A Logical Context of Authority, canonicalized deterministically.
//! let mut contract = BTreeMap::new();
//! contract.insert("corporation".into(), AuthorityValue::One("ACME".into()));
//! let logical = LogicalAuthority::new(
//!     None,
//!     vec![Invariant::new(
//!         "documents:read:document-42", "read", "documents", "document-42",
//!     )],
//!     contract,
//! );
//! let authority = IndexedAuthorityMap::from_logical(&logical)?;
//!
//! // Checkpoint 0 with its verifier-issued challenge.
//! let checkpoint = PicPcaPayload::new(0, authority, vec![0x7b; 32]);
//! let issued = issue_settled(checkpoint, &realm, &SettlementContext {
//!     iss: "https://pic-x.example.com/realms/acme".into(),
//!     ..Default::default()
//! })?;
//!
//! // Any workload with the realm public key verifies the settled token.
//! let verifier = Ed25519Verifier::new(realm.verifying_key());
//! let settled = verify_settled(&issued.token, &verifier)?;
//! assert_eq!(settled.checkpoint.position, 0);
//! # Ok::<(), pic_continuity::error::ContinuityError>(())
//! ```
//!
//! Advancement is the [`prover::build_candidate`] →
//! [`verifier::SettlementAuthority::settle`] round trip; the crate's
//! `walkthrough` integration test exercises the full lineage
//! (checkpoint 0 → 1 → 2) including attenuation and rejection paths.
//!
//! # Feature flags
//!
//! | Feature | Effect |
//! |---------|--------|
//! | `ed25519` *(default)* | [`trust::Ed25519Signer`] / [`trust::Ed25519Verifier`] and COSE `EdDSA` support via `ed25519-dalek` |
//! | `p256` | ECDSA P-256 (`ES256`) COSE helpers |
//! | `p384` | ECDSA P-384 (`ES384`) COSE helpers |
//! | `full` | All of the above |
//!
//! The core protocol logic is crypto-agnostic: with no features enabled the
//! crate still builds, and signing/verification enter through closures or
//! the [`trust::ArtifactSigner`] / [`trust::ArtifactVerifier`] traits.
//!
//! # What this crate does not do
//!
//! - **SD-JWT Proof of Relationship validation** — deployment-specific;
//!   supply it through [`por::PorValidator`].
//! - **Revocation state** — supply it through [`trust::RevocationCheck`].
//! - **Transport, storage, OAuth endpoints** — this crate is pure protocol
//!   logic; PIC-X is the reference deployment that hosts it.

#![warn(missing_docs)]

pub mod artifacts;
pub mod authority;
pub mod cose;
pub mod error;
pub mod por;
pub mod proposal;
pub mod prover;
pub mod trust;
pub mod verifier;

/// The active PIC profile identifier implemented by this crate.
pub const PROFILE_0_2: &str = "https://pic-protocol.org/profiles/0.2";

/// Profile 0.2 artifact format identifier for the PIC Token JWT.
pub const FORMAT_PIC_TOKEN_JWT: &str = "pic+jwt";
/// Profile 0.2 artifact format identifier for the PIC PCA COSE.
pub const FORMAT_PIC_PCA_COSE: &str = "pic-pca+cose";
/// Profile 0.2 artifact format identifier for the PIC Continuity COSE.
pub const FORMAT_PIC_CONTINUITY_COSE: &str = "pic-continuity+cose";
/// Profile 0.2 artifact format identifier for the PIC Continuity Transition COSE.
pub const FORMAT_PIC_TRANSITION_COSE: &str = "pic-continuity-transition+cose";

/// Stable semantic URI for the PIC token type (RFC 8693 token exchange binding).
pub const TOKEN_TYPE_PIC: &str = "https://pic-protocol.org/definitions/token-types/pic";
/// Stable semantic URI for the Initial Continuity Proposal type.
pub const PROPOSAL_TYPE_CONTINUITY_INITIAL: &str =
    "https://pic-protocol.org/definitions/proposal-types/continuity-initial";

/// The Proof of Relationship type required by current Profile 0.2.
pub const POR_TYPE_SD_JWT: &str = "sd-jwt";
/// The predecessor reference type required by current Profile 0.2.
pub const PREDECESSOR_TYPE_PCA: &str = "pca";

/// This crate's version, as published.
pub fn continuity_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
