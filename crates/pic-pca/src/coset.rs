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

//! COSE_Sign1 signing for PIC payloads.
//!
//! Provides a generic `CoseSigned<T>` wrapper for signing and verifying
//! any CBOR-serializable payload using COSE_Sign1 envelope (RFC 9052).
//!
//! PIC-specific extensions:
//! - Challenge in protected header for freshness binding (PCC response)
//! - kid used as key identifier (SPIFFE ID, DID, URL, etc.)

use coset::{iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, Label};
use serde::{de::DeserializeOwned, Serialize};

/// Custom COSE header label for PIC challenge.
/// 
/// Using -65537 which is in the private use range (values < -65536).
/// This allows the challenge to be included in the protected header
/// and covered by the COSE signature.
pub const HEADER_CHALLENGE: i64 = -65537;

/// Generic COSE_Sign1 signed envelope.
///
/// Wraps any serializable payload `T` with a COSE_Sign1 signature.
#[derive(Debug, Clone)]
pub struct CoseSigned<T> {
    inner: CoseSign1,
    _marker: std::marker::PhantomData<T>,
}

/// COSE signing and verification errors.
#[derive(Debug, thiserror::Error)]
pub enum CoseError {
    #[error("CBOR serialization failed: {0}")]
    CborSerialize(String),

    #[error("CBOR deserialization failed: {0}")]
    CborDeserialize(String),

    #[error("COSE serialization failed: {0}")]
    CoseSerialize(String),

    #[error("COSE deserialization failed: {0}")]
    CoseDeserialize(String),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Missing payload")]
    MissingPayload,

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid signature length")]
    InvalidSignatureLength,

    #[error("Algorithm mismatch: expected {expected}, got {got}")]
    AlgorithmMismatch { expected: String, got: String },
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

    /// Returns the issuer (kid) from the protected header.
    /// 
    /// Alias for `kid()` for backward compatibility.
    #[deprecated(since = "0.2.0", note = "Use kid() instead")]
    pub fn issuer(&self) -> Option<String> {
        self.kid()
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

    /// Returns the challenge from the protected header (if present).
    /// 
    /// The challenge is used for freshness binding in PIC PoC.
    /// It is included in the protected header and covered by the signature.
    pub fn challenge(&self) -> Option<Vec<u8>> {
        self.inner
            .protected
            .header
            .rest
            .iter()
            .find_map(|(label, value)| {
                if let Label::Int(HEADER_CHALLENGE) = label {
                    if let ciborium::Value::Bytes(bytes) = value {
                        return Some(bytes.clone());
                    }
                }
                None
            })
    }

    /// Serializes the signed envelope to CBOR bytes.
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
    /// Use with caution: this bypasses signature verification.
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
        Self::sign_with_challenge(payload, kid, alg, None, sign_fn)
    }

    /// Signs a payload with an optional challenge in the protected header.
    ///
    /// The challenge is included in the protected header and covered by the signature,
    /// providing freshness binding for PIC PoC.
    ///
    /// # Arguments
    /// * `payload` - The payload to sign
    /// * `kid` - Key identifier (SPIFFE ID, DID, URL, etc.)
    /// * `alg` - Signing algorithm
    /// * `challenge` - Optional challenge bytes (PCC nonce)
    /// * `sign_fn` - Signing function
    pub fn sign_with_challenge<F>(
        payload: &T,
        kid: &str,
        alg: SigningAlgorithm,
        challenge: Option<&[u8]>,
        sign_fn: F,
    ) -> Result<Self, CoseError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, CoseError>,
    {
        let mut cbor_payload = Vec::new();
        ciborium::into_writer(payload, &mut cbor_payload)
            .map_err(|e| CoseError::CborSerialize(e.to_string()))?;

        let mut header_builder = HeaderBuilder::new()
            .algorithm(alg.to_iana())
            .key_id(kid.as_bytes().to_vec());

        if let Some(ch) = challenge {
            header_builder = header_builder.value(
                HEADER_CHALLENGE,
                ciborium::Value::Bytes(ch.to_vec()),
            );
        }

        let protected = header_builder.build();

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

    /// Verifies the signature using a custom verification function (crypto-agnostic).
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
    fn check_algorithm(&self, expected: SigningAlgorithm) -> Result<(), CoseError> {
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
            Self::sign_ed25519_with_challenge(payload, kid, None, signing_key)
        }

        /// Signs payload with Ed25519 and an optional challenge.
        pub fn sign_ed25519_with_challenge(
            payload: &T,
            kid: &str,
            challenge: Option<&[u8]>,
            signing_key: &SigningKey,
        ) -> Result<Self, CoseError> {
            Self::sign_with_challenge(payload, kid, SigningAlgorithm::EdDSA, challenge, |data| {
                let sig = signing_key.sign(data);
                Ok(sig.to_bytes().to_vec())
            })
        }

        /// Verifies Ed25519 signature and returns the payload.
        pub fn verify_ed25519(&self, verifying_key: &VerifyingKey) -> Result<T, CoseError> {
            self.check_algorithm(SigningAlgorithm::EdDSA)?;

            self.verify_with(|data, sig| {
                let signature = Signature::from_slice(sig)
                    .map_err(|_| CoseError::InvalidSignatureLength)?;
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
    use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};

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
            Self::sign_p256_with_challenge(payload, kid, None, signing_key)
        }

        /// Signs payload with P-256 and an optional challenge.
        pub fn sign_p256_with_challenge(
            payload: &T,
            kid: &str,
            challenge: Option<&[u8]>,
            signing_key: &SigningKey,
        ) -> Result<Self, CoseError> {
            Self::sign_with_challenge(payload, kid, SigningAlgorithm::ES256, challenge, |data| {
                let sig: Signature = signing_key.sign(data);
                Ok(sig.to_bytes().to_vec())
            })
        }

        /// Verifies P-256 signature and returns the payload.
        pub fn verify_p256(&self, verifying_key: &VerifyingKey) -> Result<T, CoseError> {
            self.check_algorithm(SigningAlgorithm::ES256)?;

            self.verify_with(|data, sig| {
                let signature = Signature::from_slice(sig)
                    .map_err(|_| CoseError::InvalidSignatureLength)?;
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
    use p384::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};

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
            Self::sign_p384_with_challenge(payload, kid, None, signing_key)
        }

        /// Signs payload with P-384 and an optional challenge.
        pub fn sign_p384_with_challenge(
            payload: &T,
            kid: &str,
            challenge: Option<&[u8]>,
            signing_key: &SigningKey,
        ) -> Result<Self, CoseError> {
            Self::sign_with_challenge(payload, kid, SigningAlgorithm::ES384, challenge, |data| {
                let sig: Signature = signing_key.sign(data);
                Ok(sig.to_bytes().to_vec())
            })
        }

        /// Verifies P-384 signature and returns the payload.
        pub fn verify_p384(&self, verifying_key: &VerifyingKey) -> Result<T, CoseError> {
            self.check_algorithm(SigningAlgorithm::ES384)?;

            self.verify_with(|data, sig| {
                let signature = Signature::from_slice(sig)
                    .map_err(|_| CoseError::InvalidSignatureLength)?;
                verifying_key
                    .verify(data, &signature)
                    .map_err(|_| CoseError::VerificationFailed)
            })
        }
    }
}

use crate::pca::PcaPayload;
use crate::poc::PocPayload;

/// COSE-signed PCA payload.
pub type SignedPca = CoseSigned<PcaPayload>;

/// COSE-signed PoC payload.
pub type SignedPoc = CoseSigned<PocPayload>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pca::{Executor, ExecutorBinding};

    fn sample_pca() -> PcaPayload {
        PcaPayload {
            hop: 0,
            p_0: "https://idp.example.com/users/alice".into(),
            ops: vec!["read:/user/*".into()],
            executor: Executor {
                binding: ExecutorBinding::new().with("org", "acme"),
            },
            provenance: None,
            constraints: None,
        }
    }

    #[test]
    fn test_sign_with_and_verify_with() {
        let pca = sample_pca();

        let signed: SignedPca = CoseSigned::sign_with(
            &pca,
            "https://cat.example.com",
            SigningAlgorithm::EdDSA,
            |_data| Ok(vec![0xAB; 64]),
        )
        .unwrap();

        assert_eq!(signed.kid(), Some("https://cat.example.com".into()));
        assert_eq!(signed.algorithm(), Some(SigningAlgorithm::EdDSA));
        assert!(signed.challenge().is_none());

        let verified = signed.verify_with(|_data, _sig| Ok(())).unwrap();

        assert_eq!(verified.hop, pca.hop);
        assert_eq!(verified.p_0, pca.p_0);
    }

    #[test]
    fn test_sign_with_challenge() {
        let pca = sample_pca();
        let challenge = b"nonce12345";

        let signed: SignedPca = CoseSigned::sign_with_challenge(
            &pca,
            "spiffe://example.com/service",
            SigningAlgorithm::EdDSA,
            Some(challenge),
            |_data| Ok(vec![0xAB; 64]),
        )
        .unwrap();

        assert_eq!(signed.kid(), Some("spiffe://example.com/service".into()));
        assert_eq!(signed.challenge(), Some(challenge.to_vec()));

        let verified = signed.verify_with(|_data, _sig| Ok(())).unwrap();
        assert_eq!(verified.hop, pca.hop);
    }

    #[test]
    fn test_challenge_none_when_not_provided() {
        let pca = sample_pca();

        let signed: SignedPca = CoseSigned::sign_with(
            &pca,
            "issuer",
            SigningAlgorithm::EdDSA,
            |_| Ok(vec![0xAB; 64]),
        )
        .unwrap();

        assert!(signed.challenge().is_none());
    }

    #[test]
    fn test_roundtrip_bytes_with_challenge() {
        let pca = sample_pca();
        let challenge = b"freshness-nonce";

        let signed: SignedPca = CoseSigned::sign_with_challenge(
            &pca,
            "did:web:example.com",
            SigningAlgorithm::ES256,
            Some(challenge),
            |_| Ok(vec![0xCD; 64]),
        )
        .unwrap();

        let bytes = signed.to_bytes().unwrap();
        let restored: SignedPca = CoseSigned::from_bytes(&bytes).unwrap();

        assert_eq!(restored.kid(), Some("did:web:example.com".into()));
        assert_eq!(restored.challenge(), Some(challenge.to_vec()));
    }

    #[test]
    fn test_payload_unverified() {
        let pca = sample_pca();

        let signed: SignedPca =
            CoseSigned::sign_with(&pca, "issuer", SigningAlgorithm::EdDSA, |_| {
                Ok(vec![0x00; 64])
            })
            .unwrap();

        let extracted = signed.payload_unverified().unwrap();
        assert_eq!(extracted.hop, 0);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_sign_verify() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let pca = sample_pca();

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let signed: SignedPca =
            CoseSigned::sign_ed25519(&pca, "ed25519-issuer", &signing_key).unwrap();

        assert_eq!(signed.algorithm(), Some(SigningAlgorithm::EdDSA));

        let verified = signed.verify_ed25519(&verifying_key).unwrap();

        assert_eq!(verified.hop, pca.hop);
        assert_eq!(verified.p_0, pca.p_0);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_with_challenge() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let pca = sample_pca();
        let challenge = b"pcc-nonce-abc123";

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let signed: SignedPca = CoseSigned::sign_ed25519_with_challenge(
            &pca,
            "spiffe://trust.example.com/ns/prod/sa/service-a",
            Some(challenge),
            &signing_key,
        )
        .unwrap();

        assert_eq!(signed.challenge(), Some(challenge.to_vec()));

        let verified = signed.verify_ed25519(&verifying_key).unwrap();
        assert_eq!(verified.hop, pca.hop);
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_ed25519_wrong_key_fails() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let pca = sample_pca();

        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_verifying_key = SigningKey::generate(&mut OsRng).verifying_key();

        let signed: SignedPca = CoseSigned::sign_ed25519(&pca, "issuer", &signing_key).unwrap();

        let result = signed.verify_ed25519(&wrong_verifying_key);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn test_algorithm_mismatch() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let pca = sample_pca();

        let signed: SignedPca =
            CoseSigned::sign_with(&pca, "issuer", SigningAlgorithm::ES256, |_| {
                Ok(vec![0x00; 64])
            })
            .unwrap();

        let verifying_key = SigningKey::generate(&mut OsRng).verifying_key();
        let result = signed.verify_ed25519(&verifying_key);

        assert!(matches!(result, Err(CoseError::AlgorithmMismatch { .. })));
    }

    #[test]
    #[cfg(feature = "p256")]
    fn test_p256_sign_verify() {
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        let pca = sample_pca();

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let signed: SignedPca = CoseSigned::sign_p256(&pca, "p256-issuer", &signing_key).unwrap();

        assert_eq!(signed.algorithm(), Some(SigningAlgorithm::ES256));

        let verified = signed.verify_p256(verifying_key).unwrap();

        assert_eq!(verified.hop, pca.hop);
    }

    #[test]
    #[cfg(feature = "p256")]
    fn test_p256_with_challenge() {
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        let pca = sample_pca();
        let challenge = b"p256-challenge";

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let signed: SignedPca = CoseSigned::sign_p256_with_challenge(
            &pca,
            "p256-issuer",
            Some(challenge),
            &signing_key,
        )
        .unwrap();

        assert_eq!(signed.challenge(), Some(challenge.to_vec()));

        let verified = signed.verify_p256(verifying_key).unwrap();
        assert_eq!(verified.hop, pca.hop);
    }

    #[test]
    #[cfg(feature = "p256")]
    fn test_p256_wrong_key_fails() {
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        let pca = sample_pca();

        let signing_key = SigningKey::random(&mut OsRng);
        let wrong_signing_key = SigningKey::random(&mut OsRng);
        let wrong_verifying_key = wrong_signing_key.verifying_key();

        let signed: SignedPca = CoseSigned::sign_p256(&pca, "issuer", &signing_key).unwrap();

        let result = signed.verify_p256(wrong_verifying_key);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "p384")]
    fn test_p384_sign_verify() {
        use p384::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        let pca = sample_pca();

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let signed: SignedPca = CoseSigned::sign_p384(&pca, "p384-issuer", &signing_key).unwrap();

        assert_eq!(signed.algorithm(), Some(SigningAlgorithm::ES384));

        let verified = signed.verify_p384(verifying_key).unwrap();

        assert_eq!(verified.hop, pca.hop);
    }

    #[test]
    #[cfg(feature = "p384")]
    fn test_p384_wrong_key_fails() {
        use p384::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        let pca = sample_pca();

        let signing_key = SigningKey::random(&mut OsRng);
        let wrong_signing_key = SigningKey::random(&mut OsRng);
        let wrong_verifying_key = wrong_signing_key.verifying_key();

        let signed: SignedPca = CoseSigned::sign_p384(&pca, "issuer", &signing_key).unwrap();

        let result = signed.verify_p384(wrong_verifying_key);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(all(feature = "ed25519", feature = "p256"))]
    fn test_cross_algorithm_ed25519_vs_p256() {
        use ed25519_dalek::SigningKey as Ed25519SigningKey;
        use p256::ecdsa::SigningKey as P256SigningKey;
        use rand::rngs::OsRng;

        let pca = sample_pca();

        let ed_key = Ed25519SigningKey::generate(&mut OsRng);
        let signed: SignedPca = CoseSigned::sign_ed25519(&pca, "issuer", &ed_key).unwrap();

        let p256_key = P256SigningKey::random(&mut OsRng);
        let result = signed.verify_p256(p256_key.verifying_key());

        assert!(matches!(result, Err(CoseError::AlgorithmMismatch { .. })));
    }

    #[test]
    #[cfg(all(feature = "ed25519", feature = "p384"))]
    fn test_cross_algorithm_ed25519_vs_p384() {
        use ed25519_dalek::SigningKey as Ed25519SigningKey;
        use p384::ecdsa::SigningKey as P384SigningKey;
        use rand::rngs::OsRng;

        let pca = sample_pca();

        let ed_key = Ed25519SigningKey::generate(&mut OsRng);
        let signed: SignedPca = CoseSigned::sign_ed25519(&pca, "issuer", &ed_key).unwrap();

        let p384_key = P384SigningKey::random(&mut OsRng);
        let result = signed.verify_p384(p384_key.verifying_key());

        assert!(matches!(result, Err(CoseError::AlgorithmMismatch { .. })));
    }
}