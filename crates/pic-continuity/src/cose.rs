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

//! Generic COSE_Sign1 envelope (RFC 9052) for CBOR-serializable payloads.
//!
//! Crypto-agnostic: signing and verification are supplied as closures, with
//! Ed25519 / P-256 / P-384 convenience implementations behind features.
//!
//! This module is deliberately self-contained — it knows nothing about
//! Profile 0.2 — so it can be extracted into its own crate the moment a
//! second consumer needs it.

use coset::{CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, iana};
use serde::{Serialize, de::DeserializeOwned};

/// Generic COSE_Sign1 signed envelope wrapping a payload `T`.
#[derive(Debug, Clone)]
pub struct CoseSigned<T> {
    inner: CoseSign1,
    _marker: std::marker::PhantomData<T>,
}

/// COSE signing and verification errors.
#[derive(Debug, thiserror::Error)]
pub enum CoseError {
    /// The payload could not be serialized to CBOR.
    #[error("CBOR serialization failed: {0}")]
    CborSerialize(String),

    /// The payload bytes could not be deserialized from CBOR.
    #[error("CBOR deserialization failed: {0}")]
    CborDeserialize(String),

    /// The COSE_Sign1 structure could not be serialized.
    #[error("COSE serialization failed: {0}")]
    CoseSerialize(String),

    /// The bytes are not a valid COSE_Sign1 structure.
    #[error("COSE deserialization failed: {0}")]
    CoseDeserialize(String),

    /// The signature did not verify.
    #[error("Signature verification failed")]
    VerificationFailed,

    /// The COSE_Sign1 structure carries no payload.
    #[error("Missing payload")]
    MissingPayload,

    /// Key material could not be parsed.
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// The signature bytes have the wrong length for the algorithm.
    #[error("Invalid signature length")]
    InvalidSignatureLength,

    /// The protected-header algorithm differs from the expected one.
    #[error("Algorithm mismatch: expected {expected}, got {got}")]
    AlgorithmMismatch {
        /// The algorithm the caller required.
        expected: String,
        /// The algorithm found in the protected header.
        got: String,
    },
}

/// Supported COSE signing algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// EdDSA with Ed25519
    EdDSA,
    /// ECDSA with P-256 and SHA-256
    ES256,
    /// ECDSA with P-384 and SHA-384
    ES384,
}

impl std::fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningAlgorithm::EdDSA => write!(f, "EdDSA"),
            SigningAlgorithm::ES256 => write!(f, "ES256"),
            SigningAlgorithm::ES384 => write!(f, "ES384"),
        }
    }
}

impl SigningAlgorithm {
    fn to_iana(self) -> iana::Algorithm {
        match self {
            SigningAlgorithm::EdDSA => iana::Algorithm::EdDSA,
            SigningAlgorithm::ES256 => iana::Algorithm::ES256,
            SigningAlgorithm::ES384 => iana::Algorithm::ES384,
        }
    }
}

impl<T> CoseSigned<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Returns the key identifier (kid) from the protected header.
    ///
    /// The kid can be a SPIFFE ID, DID, URL, or any resolvable identifier
    /// that can be used to obtain the public key for verification.
    pub fn kid(&self) -> Option<String> {
        let kid = &self.inner.protected.header.key_id;
        if kid.is_empty() {
            None
        } else {
            String::from_utf8(kid.clone()).ok()
        }
    }

    /// Returns the signing algorithm from the protected header.
    pub fn algorithm(&self) -> Option<SigningAlgorithm> {
        match self.inner.protected.header.alg {
            Some(coset::RegisteredLabelWithPrivate::Assigned(iana::Algorithm::EdDSA)) => {
                Some(SigningAlgorithm::EdDSA)
            }
            Some(coset::RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256)) => {
                Some(SigningAlgorithm::ES256)
            }
            Some(coset::RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES384)) => {
                Some(SigningAlgorithm::ES384)
            }
            _ => None,
        }
    }

    /// Serializes the signed envelope to CBOR bytes.
    ///
    /// These are the *exact signed artifact bytes*: every Profile 0.2 hash
    /// (`root.pca_hash`, `predecessor.hash`) is computed over them.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CoseError> {
        self.inner
            .clone()
            .to_vec()
            .map_err(|e| CoseError::CoseSerialize(e.to_string()))
    }

    /// Deserializes a signed envelope from CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoseError> {
        let inner =
            CoseSign1::from_slice(bytes).map_err(|e| CoseError::CoseDeserialize(e.to_string()))?;
        Ok(Self {
            inner,
            _marker: std::marker::PhantomData,
        })
    }

    /// Extracts the payload without verifying the signature.
    ///
    /// Use only where the specification treats the artifact as untrusted
    /// input to be parsed before validation.
    pub fn payload_unverified(&self) -> Result<T, CoseError> {
        let payload = self
            .inner
            .payload
            .as_ref()
            .ok_or(CoseError::MissingPayload)?;

        ciborium::from_reader(payload.as_slice())
            .map_err(|e| CoseError::CborDeserialize(e.to_string()))
    }

    /// Signs a payload using a custom signing function (crypto-agnostic).
    ///
    /// The closure receives the to-be-signed bytes and returns the signature.
    pub fn sign_with<F>(
        payload: &T,
        kid: &str,
        alg: SigningAlgorithm,
        sign_fn: F,
    ) -> Result<Self, CoseError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, CoseError>,
    {
        let mut cbor_payload = Vec::new();
        ciborium::into_writer(payload, &mut cbor_payload)
            .map_err(|e| CoseError::CborSerialize(e.to_string()))?;

        let protected = HeaderBuilder::new()
            .algorithm(alg.to_iana())
            .key_id(kid.as_bytes().to_vec())
            .build();

        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(cbor_payload)
            .try_create_signature(&[], sign_fn)?
            .build();

        Ok(Self {
            inner: sign1,
            _marker: std::marker::PhantomData,
        })
    }

    /// Verifies the signature using a custom verification function.
    ///
    /// The closure receives `(data, signature)` and returns `Ok(())` if valid.
    pub fn verify_with<F>(&self, verify_fn: F) -> Result<T, CoseError>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<(), CoseError>,
    {
        self.inner
            .verify_signature(&[], |sig, data| verify_fn(data, sig))?;

        let payload = self
            .inner
            .payload
            .as_ref()
            .ok_or(CoseError::MissingPayload)?;

        ciborium::from_reader(payload.as_slice())
            .map_err(|e| CoseError::CborDeserialize(e.to_string()))
    }

    /// Validates that the envelope's algorithm matches the expected one.
    pub fn check_algorithm(&self, expected: SigningAlgorithm) -> Result<(), CoseError> {
        let actual = self.algorithm();
        if actual != Some(expected) {
            return Err(CoseError::AlgorithmMismatch {
                expected: expected.to_string(),
                got: actual
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "None".to_string()),
            });
        }
        Ok(())
    }
}

impl From<coset::CoseError> for CoseError {
    fn from(e: coset::CoseError) -> Self {
        CoseError::CoseSerialize(format!("{:?}", e))
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_impl {
    use super::*;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    impl<T> CoseSigned<T>
    where
        T: Serialize + DeserializeOwned,
    {
        /// Signs payload with Ed25519. Algorithm is set to EdDSA automatically.
        pub fn sign_ed25519(
            payload: &T,
            kid: &str,
            signing_key: &SigningKey,
        ) -> Result<Self, CoseError> {
            Self::sign_with(payload, kid, SigningAlgorithm::EdDSA, |data| {
                let sig = signing_key.sign(data);
                Ok(sig.to_bytes().to_vec())
            })
        }

        /// Verifies Ed25519 signature and returns the payload.
        pub fn verify_ed25519(&self, verifying_key: &VerifyingKey) -> Result<T, CoseError> {
            self.check_algorithm(SigningAlgorithm::EdDSA)?;

            self.verify_with(|data, sig| {
                let signature =
                    Signature::from_slice(sig).map_err(|_| CoseError::InvalidSignatureLength)?;
                verifying_key
                    .verify(data, &signature)
                    .map_err(|_| CoseError::VerificationFailed)
            })
        }
    }
}

#[cfg(feature = "p256")]
mod p256_impl {
    use super::*;
    use p256::ecdsa::{
        Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier,
    };

    impl<T> CoseSigned<T>
    where
        T: Serialize + DeserializeOwned,
    {
        /// Signs payload with P-256. Algorithm is set to ES256 automatically.
        pub fn sign_p256(
            payload: &T,
            kid: &str,
            signing_key: &SigningKey,
        ) -> Result<Self, CoseError> {
            Self::sign_with(payload, kid, SigningAlgorithm::ES256, |data| {
                let sig: Signature = signing_key.sign(data);
                Ok(sig.to_bytes().to_vec())
            })
        }

        /// Verifies P-256 signature and returns the payload.
        pub fn verify_p256(&self, verifying_key: &VerifyingKey) -> Result<T, CoseError> {
            self.check_algorithm(SigningAlgorithm::ES256)?;

            self.verify_with(|data, sig| {
                let signature =
                    Signature::from_slice(sig).map_err(|_| CoseError::InvalidSignatureLength)?;
                verifying_key
                    .verify(data, &signature)
                    .map_err(|_| CoseError::VerificationFailed)
            })
        }
    }
}

#[cfg(feature = "p384")]
mod p384_impl {
    use super::*;
    use p384::ecdsa::{
        Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier,
    };

    impl<T> CoseSigned<T>
    where
        T: Serialize + DeserializeOwned,
    {
        /// Signs payload with P-384. Algorithm is set to ES384 automatically.
        pub fn sign_p384(
            payload: &T,
            kid: &str,
            signing_key: &SigningKey,
        ) -> Result<Self, CoseError> {
            Self::sign_with(payload, kid, SigningAlgorithm::ES384, |data| {
                let sig: Signature = signing_key.sign(data);
                Ok(sig.to_bytes().to_vec())
            })
        }

        /// Verifies P-384 signature and returns the payload.
        pub fn verify_p384(&self, verifying_key: &VerifyingKey) -> Result<T, CoseError> {
            self.check_algorithm(SigningAlgorithm::ES384)?;

            self.verify_with(|data, sig| {
                let signature =
                    Signature::from_slice(sig).map_err(|_| CoseError::InvalidSignatureLength)?;
                verifying_key
                    .verify(data, &signature)
                    .map_err(|_| CoseError::VerificationFailed)
            })
        }
    }
}
