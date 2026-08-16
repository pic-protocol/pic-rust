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

//! Verification keys from published JWKs (RFC 7517).
//!
//! Every party that checks a PIC artifact starts from a key someone published: a relying party
//! reading a realm's `jwks_uri`, a workload verifying the checkpoint it was handed, a settlement
//! authority reading `cnf.jwk` out of a Proof of Relationship. Without this they each write the
//! same JWK reader, and each one is a place to get the algorithm agreement wrong.
//!
//! # Algorithm agreement
//!
//! A key can produce exactly one signature algorithm, and [`expected_algorithms_for_jwk`] says
//! which. That is what stops an artifact from *choosing* how it is verified: a candidate claiming
//! `alg` that its key cannot produce, or a JWK whose declared `alg` disagrees with its own key
//! material, is rejected before a signature is checked rather than after.
//!
//! # What is not here
//!
//! RSA. It is the shape identity providers publish, and an OAuth access token is not a PIC
//! artifact — a deployment that exchanges one reads it with its own code, and this crate stays
//! about the artifacts the profile defines.
//!
//! The curve implementations follow the crate's feature flags, so a build that enables none still
//! compiles and every reader here answers "unsupported".

use serde_json::Value;

use crate::cose::SigningAlgorithm;
use crate::trust::ArtifactVerifier;

/// Why a JWK could not become a verification key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwkError {
    /// The JWK carries a private component and is not a published verification key.
    #[error("the JWK carries a private key component")]
    NotPublic,
    /// A member the key type requires is missing.
    #[error("the JWK has no `{0}`")]
    Missing(&'static str),
    /// A member is present but not in the encoding a JWK uses.
    #[error("`{0}` is not unpadded base64url")]
    NotBase64Url(&'static str),
    /// A coordinate or key is the wrong length for its curve.
    #[error("{0}")]
    WrongLength(String),
    /// The key type or curve is one this build does not verify with.
    #[error("unsupported key: {0}")]
    Unsupported(String),
    /// The `alg` the JWK declares is not the one its key material can produce.
    #[error("JWK `alg` `{declared}` does not match key material algorithm `{actual}`")]
    AlgorithmDisagreement {
        /// What the JWK said.
        declared: String,
        /// What the key can actually produce.
        actual: &'static str,
    },
}

/// The algorithms one key can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedAlgorithms {
    /// The JOSE `alg` a JWS signed by this key names.
    pub jose: &'static str,
    /// The COSE algorithm, when the key can sign PIC COSE artifacts.
    pub cose: Option<SigningAlgorithm>,
}

/// The algorithms this JWK's key material can produce, whatever it claims.
///
/// Reading the key type rather than trusting `alg` is the point: `alg` is a claim, key material is
/// a fact. When the JWK declares an `alg` that disagrees with its own material, that is an error
/// rather than a preference to honour.
pub fn expected_algorithms_for_jwk(jwk: &Value) -> Result<ExpectedAlgorithms, JwkError> {
    let key_type = member(jwk, "kty").ok_or(JwkError::Missing("kty"))?;
    let curve = member(jwk, "crv").unwrap_or_default();

    let expected = match (key_type, curve) {
        ("OKP", "Ed25519") => ExpectedAlgorithms {
            jose: "EdDSA",
            cose: Some(SigningAlgorithm::EdDSA),
        },
        ("EC", "P-256") => ExpectedAlgorithms {
            jose: "ES256",
            cose: Some(SigningAlgorithm::ES256),
        },
        ("EC", "P-384") => ExpectedAlgorithms {
            jose: "ES384",
            cose: Some(SigningAlgorithm::ES384),
        },
        (other, curve) => {
            return Err(JwkError::Unsupported(format!(
                "`kty` `{other}` with `crv` `{curve}`"
            )));
        }
    };

    if let Some(declared) = member(jwk, "alg")
        && declared != expected.jose
    {
        return Err(JwkError::AlgorithmDisagreement {
            declared: declared.to_owned(),
            actual: expected.jose,
        });
    }

    Ok(expected)
}

/// A verifier over one published key.
///
/// Deliberately opaque: it prints what it is, never the key material it holds.
pub struct JwkVerifier {
    inner: Key,
}

impl std::fmt::Debug for JwkVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JwkVerifier")
    }
}

/// The key material, in whichever form the enabled features can verify with.
enum Key {
    #[cfg(feature = "ed25519")]
    Ed25519(Box<ed25519_dalek::VerifyingKey>),
    #[cfg(feature = "p256")]
    P256(Box<p256::ecdsa::VerifyingKey>),
    #[cfg(feature = "p384")]
    P384(Box<p384::ecdsa::VerifyingKey>),
}

impl ArtifactVerifier for JwkVerifier {
    #[cfg_attr(
        not(any(feature = "ed25519", feature = "p256", feature = "p384")),
        allow(unused_variables)
    )]
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        match &self.inner {
            #[cfg(feature = "ed25519")]
            Key::Ed25519(key) => {
                use ed25519_dalek::Verifier;

                ed25519_dalek::Signature::from_slice(signature)
                    .is_ok_and(|signature| key.verify(data, &signature).is_ok())
            }
            #[cfg(feature = "p256")]
            Key::P256(key) => {
                use p256::ecdsa::signature::Verifier;

                p256::ecdsa::Signature::from_slice(signature)
                    .is_ok_and(|signature| key.verify(data, &signature).is_ok())
            }
            #[cfg(feature = "p384")]
            Key::P384(key) => {
                use p384::ecdsa::signature::Verifier;

                p384::ecdsa::Signature::from_slice(signature)
                    .is_ok_and(|signature| key.verify(data, &signature).is_ok())
            }
            // With no curve feature enabled the enum has no variants and nothing reaches here.
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }
}

/// Builds a verifier from a published JWK.
///
/// A JWK carrying a private component is refused outright: a verification key is public, and one
/// that arrived with `d` is either a mistake or an attempt to have this build hold a secret it was
/// never given.
pub fn public_key_from_jwk(jwk: &Value) -> Result<JwkVerifier, JwkError> {
    if jwk.get("d").is_some() {
        return Err(JwkError::NotPublic);
    }

    // The algorithms are agreed first, so a JWK whose `alg` contradicts its material never reaches
    // the key readers below.
    let expected = expected_algorithms_for_jwk(jwk)?;
    let x = coordinate(jwk, "x")?;

    match expected.jose {
        "EdDSA" => ed25519_from_x(x),
        "ES256" => p256_from_coordinates(x, coordinate(jwk, "y")?),
        "ES384" => p384_from_coordinates(x, coordinate(jwk, "y")?),
        other => Err(JwkError::Unsupported(other.to_owned())),
    }
}

// Each reader exists in two forms — one when its curve is compiled in, one that says so when it is
// not — rather than one function branching on `cfg`. The build then carries only the code it can
// actually run.

#[cfg(feature = "ed25519")]
fn ed25519_from_x(x: Vec<u8>) -> Result<JwkVerifier, JwkError> {
    let bytes: [u8; 32] = x
        .try_into()
        .map_err(|_| JwkError::WrongLength("an Ed25519 `x` is not 32 bytes".to_owned()))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|error| JwkError::WrongLength(error.to_string()))?;

    Ok(JwkVerifier {
        inner: Key::Ed25519(Box::new(key)),
    })
}

#[cfg(not(feature = "ed25519"))]
fn ed25519_from_x(_x: Vec<u8>) -> Result<JwkVerifier, JwkError> {
    Err(JwkError::Unsupported(
        "Ed25519: enable the `ed25519` feature".to_owned(),
    ))
}

#[cfg(feature = "p256")]
fn p256_from_coordinates(x: Vec<u8>, y: Vec<u8>) -> Result<JwkVerifier, JwkError> {
    let point = sec1_point(&x, &y, 32, "P-256")?;
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
        .map_err(|error| JwkError::WrongLength(error.to_string()))?;

    Ok(JwkVerifier {
        inner: Key::P256(Box::new(key)),
    })
}

#[cfg(not(feature = "p256"))]
fn p256_from_coordinates(_x: Vec<u8>, _y: Vec<u8>) -> Result<JwkVerifier, JwkError> {
    Err(JwkError::Unsupported(
        "P-256: enable the `p256` feature".to_owned(),
    ))
}

#[cfg(feature = "p384")]
fn p384_from_coordinates(x: Vec<u8>, y: Vec<u8>) -> Result<JwkVerifier, JwkError> {
    let point = sec1_point(&x, &y, 48, "P-384")?;
    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
        .map_err(|error| JwkError::WrongLength(error.to_string()))?;

    Ok(JwkVerifier {
        inner: Key::P384(Box::new(key)),
    })
}

#[cfg(not(feature = "p384"))]
fn p384_from_coordinates(_x: Vec<u8>, _y: Vec<u8>) -> Result<JwkVerifier, JwkError> {
    Err(JwkError::Unsupported(
        "P-384: enable the `p384` feature".to_owned(),
    ))
}

/// `0x04 || x || y`, the uncompressed point the curve libraries read.
#[cfg_attr(
    not(any(feature = "p256", feature = "p384")),
    allow(dead_code, unused_variables)
)]
fn sec1_point(x: &[u8], y: &[u8], width: usize, curve: &str) -> Result<Vec<u8>, JwkError> {
    if x.len() != width || y.len() != width {
        return Err(JwkError::WrongLength(format!(
            "a {curve} coordinate is not {width} bytes"
        )));
    }

    let mut point = Vec::with_capacity(1 + width * 2);
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);

    Ok(point)
}

fn member<'a>(jwk: &'a Value, name: &str) -> Option<&'a str> {
    jwk.get(name)?.as_str()
}

fn coordinate(jwk: &Value, name: &'static str) -> Result<Vec<u8>, JwkError> {
    use base64::Engine;

    let encoded = member(jwk, name).ok_or(JwkError::Missing(name))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| JwkError::NotBase64Url(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn algorithms_come_from_key_material_not_from_what_the_jwk_claims() {
        let ed25519 = json!({"kty": "OKP", "crv": "Ed25519", "x": "AA"});
        assert_eq!(
            expected_algorithms_for_jwk(&ed25519).unwrap(),
            ExpectedAlgorithms {
                jose: "EdDSA",
                cose: Some(SigningAlgorithm::EdDSA),
            }
        );

        let p256 = json!({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"});
        assert_eq!(expected_algorithms_for_jwk(&p256).unwrap().jose, "ES256");

        let p384 = json!({"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"});
        assert_eq!(expected_algorithms_for_jwk(&p384).unwrap().jose, "ES384");

        // An `alg` the material cannot produce is an error, not a preference: honouring it would
        // let an artifact pick how it is verified.
        let lying = json!({"kty": "OKP", "crv": "Ed25519", "alg": "ES256", "x": "AA"});
        assert_eq!(
            expected_algorithms_for_jwk(&lying).unwrap_err(),
            JwkError::AlgorithmDisagreement {
                declared: "ES256".to_owned(),
                actual: "EdDSA",
            }
        );

        // RSA belongs to the OAuth side, not to PIC artifacts.
        let rsa = json!({"kty": "RSA", "n": "AA", "e": "AQAB"});
        assert!(matches!(
            expected_algorithms_for_jwk(&rsa).unwrap_err(),
            JwkError::Unsupported(_)
        ));
    }

    #[test]
    fn a_jwk_carrying_private_material_is_refused() {
        let private = json!({"kty": "OKP", "crv": "Ed25519", "x": "AA", "d": "secret"});
        assert_eq!(
            public_key_from_jwk(&private).unwrap_err(),
            JwkError::NotPublic
        );
    }

    #[test]
    fn a_malformed_key_is_refused_rather_than_truncated() {
        let short = json!({"kty": "OKP", "crv": "Ed25519", "x": "AAAA"});
        assert!(matches!(
            public_key_from_jwk(&short).unwrap_err(),
            JwkError::WrongLength(_)
        ));

        let not_base64 = json!({"kty": "OKP", "crv": "Ed25519", "x": "not base64!"});
        assert_eq!(
            public_key_from_jwk(&not_base64).unwrap_err(),
            JwkError::NotBase64Url("x")
        );

        let no_y = json!({"kty": "EC", "crv": "P-256", "x": "AA"});
        assert_eq!(
            public_key_from_jwk(&no_y).unwrap_err(),
            JwkError::Missing("y")
        );
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn an_ed25519_jwk_verifies_what_its_key_signed() {
        use base64::Engine;
        use ed25519_dalek::Signer;

        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signing.verifying_key().as_bytes()),
        });

        let verifier = public_key_from_jwk(&jwk).expect("the JWK reads");
        let signature = signing.sign(b"artifact bytes");
        assert!(verifier.verify(b"artifact bytes", &signature.to_bytes()));
        assert!(!verifier.verify(b"other bytes", &signature.to_bytes()));
    }

    #[cfg(feature = "p256")]
    #[test]
    fn a_p256_jwk_verifies_what_its_key_signed() {
        use base64::Engine;
        use p256::ecdsa::signature::Signer;

        let signing = p256::ecdsa::SigningKey::from_slice(&[0x11; 32]).expect("a signing key");
        let point = signing.verifying_key().to_encoded_point(false);
        let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": encode(point.x().expect("x")),
            "y": encode(point.y().expect("y")),
        });

        let verifier = public_key_from_jwk(&jwk).expect("the JWK reads");
        let signature: p256::ecdsa::Signature = signing.sign(b"artifact bytes");
        assert!(verifier.verify(b"artifact bytes", &signature.to_bytes()));
        assert!(!verifier.verify(b"other bytes", &signature.to_bytes()));
    }
}
