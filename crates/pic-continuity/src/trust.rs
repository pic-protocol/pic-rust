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

//! Host-supplied trust boundaries.
//!
//! The Prover and Verifier are pure: key material, trusted checkpoint state,
//! revocation, and policy all enter through these traits. Defaults are
//! provided where the specification makes a check optional or
//! deployment-defined.

use crate::artifacts::{PicPcaPayload, PicTransitionPayload};
use crate::authority::indexed::IndexedAuthorityMap;
use crate::cose::{CoseError, SigningAlgorithm};

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

/// Signs PIC artifacts (COSE payloads and the JWS envelope) with one key.
///
/// Implemented by workloads (candidate artifacts) and by the settlement
/// authority (checkpoints and settled artifacts).
pub trait ArtifactSigner {
    /// Key identifier (SPIFFE ID, DID, URL, …) placed in the COSE protected
    /// header.
    fn kid(&self) -> &str;
    /// COSE algorithm this signer produces.
    fn cose_algorithm(&self) -> SigningAlgorithm;
    /// JOSE `alg` value for JWS signatures (for example `"EdDSA"`).
    fn jws_algorithm(&self) -> &str;
    /// Signs raw bytes.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CoseError>;
}

/// Verifies a raw signature over raw bytes with one key.
pub trait ArtifactVerifier {
    /// `true` when `signature` is a valid signature over `data`.
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool;
}

#[cfg(feature = "ed25519")]
mod ed25519_impl {
    use super::*;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    /// Ed25519 [`ArtifactSigner`].
    #[derive(Debug, Clone)]
    pub struct Ed25519Signer {
        key: SigningKey,
        kid: String,
    }

    impl Ed25519Signer {
        /// Wraps a signing key with its key identifier.
        pub fn new(key: SigningKey, kid: impl Into<String>) -> Self {
            Self {
                key,
                kid: kid.into(),
            }
        }

        /// The public key matching this signer.
        pub fn verifying_key(&self) -> VerifyingKey {
            self.key.verifying_key()
        }
    }

    impl ArtifactSigner for Ed25519Signer {
        fn kid(&self) -> &str {
            &self.kid
        }
        fn cose_algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::EdDSA
        }
        fn jws_algorithm(&self) -> &str {
            "EdDSA"
        }
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CoseError> {
            Ok(self.key.sign(data).to_bytes().to_vec())
        }
    }

    /// Ed25519 [`ArtifactVerifier`].
    #[derive(Debug, Clone)]
    pub struct Ed25519Verifier {
        key: VerifyingKey,
    }

    impl Ed25519Verifier {
        /// Wraps a public key.
        pub fn new(key: VerifyingKey) -> Self {
            Self { key }
        }
    }

    impl ArtifactVerifier for Ed25519Verifier {
        fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
            let Ok(sig) = Signature::from_slice(signature) else {
                return false;
            };
            self.key.verify(data, &sig).is_ok()
        }
    }
}

#[cfg(feature = "ed25519")]
pub use ed25519_impl::{Ed25519Signer, Ed25519Verifier};

// ---------------------------------------------------------------------------
// Settlement-side trust state
// ---------------------------------------------------------------------------

/// The settlement authority's knowledge of currently trusted checkpoints.
///
/// `root.pca` of a candidate must be the **exact signed bytes** of a
/// currently trusted PIC PCA COSE checkpoint; the store answers that
/// question. Terminating a checkpoint here is how revocation of a lineage
/// branch is realized operationally.
pub trait TrustedCheckpoint {
    /// `true` when `exact_pca_bytes` are byte-for-byte a currently trusted
    /// checkpoint.
    fn is_current_checkpoint(&self, exact_pca_bytes: &[u8]) -> bool;
}

/// Revocation state lookup. The default accepts everything; deployments
/// enable it per the PIC Revocation Specification.
pub trait RevocationCheck {
    /// `true` when the continuity state rooted at this checkpoint is revoked.
    fn is_revoked(&self, checkpoint: &PicPcaPayload, exact_pca_bytes: &[u8]) -> bool;
}

/// No revocation configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRevocation;

impl RevocationCheck for NoRevocation {
    fn is_revoked(&self, _checkpoint: &PicPcaPayload, _exact_pca_bytes: &[u8]) -> bool {
        false
    }
}

/// Deployment policy hooks evaluated during settlement. Every method
/// defaults to accepting, matching the checks the specification marks as
/// profile- or deployment-required.
pub trait SettlementPolicy {
    /// Request/execution binding validation, when the deployment requires
    /// it. Receives the whole transition (including `request_digest`).
    fn request_binding(&self, _transition: &PicTransitionPayload) -> bool {
        true
    }

    /// Executor evidence / execution-contract conformance validation, when
    /// required.
    fn conformance(&self, _checkpoint: &PicPcaPayload, _transition: &PicTransitionPayload) -> bool {
        true
    }

    /// Local policy over the materialized successor authority.
    fn policy(&self, _checkpoint: &PicPcaPayload, _next_authority: &IndexedAuthorityMap) -> bool {
        true
    }
}

/// The permissive default policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultPolicy;

impl SettlementPolicy for DefaultPolicy {}

/// An in-memory [`TrustedCheckpoint`] store, useful for tests and simple
/// single-process deployments.
#[derive(Debug, Clone, Default)]
pub struct InMemoryCheckpoints {
    current: Vec<Vec<u8>>,
}

impl InMemoryCheckpoints {
    /// An empty store: nothing is trusted yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks exact checkpoint bytes as currently trusted.
    pub fn insert(&mut self, exact_pca_bytes: Vec<u8>) {
        self.current.push(exact_pca_bytes);
    }

    /// Replaces a superseded checkpoint with its successor.
    pub fn replace(&mut self, old_exact_pca_bytes: &[u8], new_exact_pca_bytes: Vec<u8>) {
        self.current.retain(|b| b != old_exact_pca_bytes);
        self.current.push(new_exact_pca_bytes);
    }
}

impl TrustedCheckpoint for InMemoryCheckpoints {
    fn is_current_checkpoint(&self, exact_pca_bytes: &[u8]) -> bool {
        self.current.iter().any(|b| b == exact_pca_bytes)
    }
}
