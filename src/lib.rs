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

//! # PIC Protocol — Provenance Identity Continuity
//!
//! Rust implementation of the [PIC Protocol](https://www.pic-protocol.org):
//! verifiable authority continuity across distributed and agentic execution
//! chains, as defined by the
//! [PIC Specification](https://github.com/pic-protocol/pic-spec).
//!
//! Where a bearer token proves *possession*, a PIC continuity state proves
//! *provenance*: each hop of an execution chain carries a signed, verifiable
//! lineage of how its authority was derived — and authority can only be
//! attenuated along the way, never expanded.
//!
//! This crate is the facade over the protocol crates; today it re-exports
//! one implementation crate:
//!
//! - [`continuity`] — PIC Profile 0.2: the artifact family (PIC Token JWT,
//!   PIC PCA COSE, PIC Continuity COSE, PIC Continuity Transition COSE),
//!   the canonical Indexed Authority Map, the Prover (candidate
//!   construction), and the Verifier (settled-state verification and the
//!   settlement procedure).
//!
//! # Quick start
//!
#![cfg_attr(feature = "ed25519", doc = "```")]
#![cfg_attr(not(feature = "ed25519"), doc = "```ignore")]
//! use pic::continuity::artifacts::PicPcaPayload;
//! use pic::continuity::authority::{
//!     AuthorityValue, IndexedAuthorityMap, Invariant, LogicalAuthority,
//! };
//! use pic::continuity::trust::{Ed25519Signer, Ed25519Verifier};
//! use pic::continuity::verifier::{issue_settled, verify_settled, SettlementContext};
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
//! // Checkpoint 0 (e.g. after an OAuth-to-PIC token exchange).
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
//! # Ok::<(), pic::continuity::error::ContinuityError>(())
//! ```
//!
//! See the [`continuity`] module documentation for the full role map
//! (Prover, ordinary verifier, settlement authority) and feature flags.
//!
//! # Feature flags
//!
//! | Feature | Effect |
//! |---------|--------|
//! | `ed25519` *(default)* | Ed25519 signers/verifiers via `ed25519-dalek` |
//! | `p256` | ECDSA P-256 (`ES256`) |
//! | `p384` | ECDSA P-384 (`ES384`) |
//! | `crypto-full` / `full` | All of the above |

#![warn(missing_docs)]

/// PIC Profile 0.2: continuity artifacts, Prover, and Verifier.
pub mod continuity {
    pub use pic_continuity::*;
}
