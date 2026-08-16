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

//! PIC Token JWT (`pic+jwt`): the external envelope.
//!
//! `pic.root` carries the unpadded Base64url encoding of the **exact binary
//! PIC Continuity COSE bytes**. Candidate tokens are workload-signed (`iss`
//! optional — identity metadata, not the source of trust); settled tokens are
//! signed by the trusted settlement authority.
//!
//! Signing is delegated to [`crate::trust::ArtifactSigner`], so any JOSE
//! stack can plug in; an Ed25519 implementation ships behind the `ed25519`
//! feature.

use crate::error::ContinuityError;
use crate::trust::{ArtifactSigner, ArtifactVerifier};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

/// The `pic` claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PicClaim {
    /// Unpadded Base64url of the exact PIC Continuity COSE bytes.
    pub root: String,
    /// Reserved for future composition: additional PIC Continuity COSE
    /// values, each unpadded Base64url of exact bytes. Not defined by
    /// Profile 0.2 processing; carried for representation fidelity only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compositions: Option<Vec<String>>,
}

/// PIC Token JWT claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PicTokenClaims {
    /// Issuer: the realm settlement-authority identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Issued-at (seconds since the Unix epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Expiry (seconds since the Unix epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Token identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// PIC profile identifier; must equal [`crate::PROFILE_0_2`].
    pub profile: String,
    /// The PIC claim carrying the continuity state.
    pub pic: PicClaim,
}

impl PicTokenClaims {
    /// Builds claims around exact PIC Continuity COSE bytes.
    pub fn for_continuity(continuity_bytes: &[u8]) -> Self {
        Self {
            iss: None,
            sub: None,
            aud: None,
            iat: None,
            exp: None,
            jti: None,
            profile: crate::PROFILE_0_2.to_string(),
            pic: PicClaim {
                root: URL_SAFE_NO_PAD.encode(continuity_bytes),
                compositions: None,
            },
        }
    }

    /// Decodes `pic.root` back into the exact PIC Continuity COSE bytes.
    pub fn root_bytes(&self) -> Result<Vec<u8>, ContinuityError> {
        URL_SAFE_NO_PAD
            .decode(&self.pic.root)
            .map_err(|e| ContinuityError::Jws(format!("pic.root is not valid base64url: {e}")))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwsHeader {
    alg: String,
    typ: String,
}

/// A decoded (not yet verified) PIC Token JWT.
#[derive(Debug, Clone)]
pub struct DecodedToken {
    /// JOSE `alg` header value.
    pub alg: String,
    /// JOSE `typ` header value; `"pic+jwt"` for a PIC Token.
    pub typ: String,
    /// The decoded claim set. Untrusted until the signature is verified.
    pub claims: PicTokenClaims,
    /// The JWS signing input (`b64(header) . b64(payload)`).
    pub signing_input: Vec<u8>,
    /// The raw JWS signature bytes.
    pub signature: Vec<u8>,
}

/// Signs claims into a compact JWS with `typ = "pic+jwt"`.
pub fn sign_token(
    claims: &PicTokenClaims,
    signer: &dyn ArtifactSigner,
) -> Result<String, ContinuityError> {
    let header = JwsHeader {
        alg: signer.jws_algorithm().to_string(),
        typ: crate::FORMAT_PIC_TOKEN_JWT.to_string(),
    };
    let header_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|e| ContinuityError::Jws(e.to_string()))?);
    let payload_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(claims).map_err(|e| ContinuityError::Jws(e.to_string()))?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signer.sign(signing_input.as_bytes())?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

/// Decodes a compact JWS without verifying the signature.
///
/// Use only where the specification treats the token as untrusted input to
/// be parsed before validation.
pub fn decode_token(token: &str) -> Result<DecodedToken, ContinuityError> {
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => {
            return Err(ContinuityError::Jws(
                "token is not a compact JWS with three segments".into(),
            ));
        }
    };

    let header_bytes = URL_SAFE_NO_PAD
        .decode(h)
        .map_err(|e| ContinuityError::Jws(format!("header: {e}")))?;
    let header: JwsHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| ContinuityError::Jws(format!("header: {e}")))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(p)
        .map_err(|e| ContinuityError::Jws(format!("payload: {e}")))?;
    let claims: PicTokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| ContinuityError::Jws(format!("payload: {e}")))?;

    let signature = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| ContinuityError::Jws(format!("signature: {e}")))?;

    Ok(DecodedToken {
        alg: header.alg,
        typ: header.typ,
        claims,
        signing_input: format!("{h}.{p}").into_bytes(),
        signature,
    })
}

/// Decodes and verifies a PIC Token JWT signature.
pub fn verify_token(
    token: &str,
    verifier: &dyn ArtifactVerifier,
) -> Result<PicTokenClaims, ContinuityError> {
    let decoded = decode_token(token)?;
    if decoded.typ != crate::FORMAT_PIC_TOKEN_JWT {
        return Err(ContinuityError::Jws(format!(
            "typ must be {}, got {}",
            crate::FORMAT_PIC_TOKEN_JWT,
            decoded.typ
        )));
    }
    if !verifier.verify(&decoded.signing_input, &decoded.signature) {
        return Err(ContinuityError::Jws("signature verification failed".into()));
    }
    Ok(decoded.claims)
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use crate::trust::{Ed25519Signer, Ed25519Verifier};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn sign_decode_verify_roundtrip() {
        let key = SigningKey::generate(&mut OsRng);
        let signer = Ed25519Signer::new(key.clone(), "https://realm.example.com/keys/1");
        let verifier = Ed25519Verifier::new(key.verifying_key());

        let mut claims = PicTokenClaims::for_continuity(b"exact-continuity-bytes");
        claims.iss = Some("https://pic-x.example.com/realms/acme".into());
        claims.iat = Some(1786700400);

        let token = sign_token(&claims, &signer).unwrap();
        let decoded = decode_token(&token).unwrap();
        assert_eq!(decoded.typ, crate::FORMAT_PIC_TOKEN_JWT);
        assert_eq!(decoded.alg, "EdDSA");

        let verified = verify_token(&token, &verifier).unwrap();
        assert_eq!(verified, claims);
        assert_eq!(verified.root_bytes().unwrap(), b"exact-continuity-bytes");
    }

    #[test]
    fn wrong_key_fails() {
        let key = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let signer = Ed25519Signer::new(key, "kid");
        let claims = PicTokenClaims::for_continuity(b"bytes");
        let token = sign_token(&claims, &signer).unwrap();

        let verifier = Ed25519Verifier::new(other.verifying_key());
        assert!(verify_token(&token, &verifier).is_err());
    }

    #[test]
    fn tampered_payload_fails() {
        let key = SigningKey::generate(&mut OsRng);
        let signer = Ed25519Signer::new(key.clone(), "kid");
        let claims = PicTokenClaims::for_continuity(b"bytes");
        let token = sign_token(&claims, &signer).unwrap();

        // Swap the payload segment with another encoded payload.
        let other = PicTokenClaims::for_continuity(b"different");
        let fake_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&other).unwrap());
        let mut parts: Vec<&str> = token.split('.').collect();
        parts[1] = &fake_payload;
        let tampered = parts.join(".");

        let verifier = Ed25519Verifier::new(key.verifying_key());
        assert!(verify_token(&tampered, &verifier).is_err());
    }

    #[test]
    fn wrong_typ_fails_even_with_valid_signature() {
        let key = SigningKey::generate(&mut OsRng);
        let signer = Ed25519Signer::new(key.clone(), "kid");
        let verifier = Ed25519Verifier::new(key.verifying_key());
        let claims = PicTokenClaims::for_continuity(b"bytes");

        let header = JwsHeader {
            alg: "EdDSA".into(),
            typ: "at+jwt".into(),
        };
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = signer.sign(signing_input.as_bytes()).unwrap();
        let token = format!(
            "{signing_input}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
        );

        assert!(verify_token(&token, &verifier).is_err());
    }
}
