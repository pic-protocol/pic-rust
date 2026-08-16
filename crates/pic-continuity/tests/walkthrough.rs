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

//! Golden end-to-end test: the "Centralized Token Exchange End to End"
//! walkthrough.
//!
//! PCA 0 { documents:read:document-42, storage:save }
//!   → Worker 1 reads document-42, removes the read invariant (h'01')
//! PCA 1 { storage:save }
//!   → Worker 2 stores the result, removes the save invariant (h'01' again:
//!     every checkpoint re-materializes its section-local indexes)
//! PCA 2 { } — attenuation to zero executable authority, not revocation.

#![cfg(feature = "ed25519")]

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use pic_continuity::artifacts::token::PicTokenClaims;
use pic_continuity::artifacts::{PcaChallenge, PicPcaPayload, ProofOfRelationship};
use pic_continuity::authority::attenuation::{Attenuations, ReferenceProfile};
use pic_continuity::authority::bitmap::RemoveBitmap;
use pic_continuity::authority::indexed::IndexedAuthorityMap;
use pic_continuity::authority::{AuthorityValue, Invariant, LogicalAuthority};
use pic_continuity::error::{ContinuityError, RejectReason};
use pic_continuity::por::PorValidator;
use pic_continuity::prover::{CandidateRequest, build_candidate};
use pic_continuity::trust::{
    ArtifactSigner, ArtifactVerifier, DefaultPolicy, Ed25519Signer, Ed25519Verifier,
    InMemoryCheckpoints, NoRevocation,
};
use pic_continuity::verifier::{
    SettlementAuthority, SettlementContext, issue_settled, verify_settled,
};
use rand::rngs::OsRng;

/// Test-only PoR validator: accepts `type = "sd-jwt"` and treats the
/// evidence as a raw Ed25519 public key. A real deployment plugs an
/// RFC 9901 SD-JWT validator here; the trait boundary is the point under
/// test, not the SD-JWT parsing itself.
struct StubPor;

impl PorValidator for StubPor {
    fn validate(
        &self,
        por: &ProofOfRelationship,
    ) -> Result<Box<dyn ArtifactVerifier>, RejectReason> {
        let bytes: [u8; 32] = por
            .evidence
            .as_slice()
            .try_into()
            .map_err(|_| RejectReason::PorRejected("bad evidence".into()))?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|_| RejectReason::PorRejected("bad key".into()))?;
        Ok(Box::new(Ed25519Verifier::new(key)))
    }
}

fn walkthrough_logical() -> LogicalAuthority {
    let mut contract = BTreeMap::new();
    contract.insert("corporation".into(), AuthorityValue::One("ACME".into()));
    contract.insert(
        "department".into(),
        AuthorityValue::One("sensitive-documents".into()),
    );
    LogicalAuthority::new(
        None,
        vec![
            Invariant::new(
                "documents:read:document-42",
                "read",
                "documents",
                "document-42",
            ),
            Invariant::new("storage:save", "save", "storage", "*"),
        ],
        contract,
    )
}

struct Realm {
    signer: Ed25519Signer,
    verifier: Ed25519Verifier,
}

fn realm() -> Realm {
    let key = SigningKey::generate(&mut OsRng);
    Realm {
        signer: Ed25519Signer::new(key.clone(), "https://pic-x.example.com/realms/acme/keys/1"),
        verifier: Ed25519Verifier::new(key.verifying_key()),
    }
}

fn worker(kid: &str) -> (Ed25519Signer, ProofOfRelationship) {
    let key = SigningKey::generate(&mut OsRng);
    let por = ProofOfRelationship {
        por_type: pic_continuity::POR_TYPE_SD_JWT.into(),
        evidence: key.verifying_key().to_bytes().to_vec(),
    };
    (Ed25519Signer::new(key, kid), por)
}

fn sign_claims_with_typ(claims: &PicTokenClaims, typ: &str, signer: &dyn ArtifactSigner) -> String {
    use base64::Engine;

    let header = serde_json::json!({
        "alg": signer.jws_algorithm(),
        "typ": typ,
    });
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signer.sign(signing_input.as_bytes()).unwrap();
    format!(
        "{signing_input}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
    )
}

fn ctx() -> SettlementContext {
    SettlementContext {
        iss: "https://pic-x.example.com/realms/acme".into(),
        sub: Some("pic-execution-123".into()),
        aud: Some("document-pipeline".into()),
        iat: Some(1_786_700_400),
        exp: Some(1_786_704_000),
        jti: None,
    }
}

/// Initializes checkpoint 0 and returns (settled issue, trusted store).
fn initialize(realm: &Realm) -> (pic_continuity::verifier::SettledIssue, InMemoryCheckpoints) {
    let map = IndexedAuthorityMap::from_logical(&walkthrough_logical()).unwrap();
    let pca0 = PicPcaPayload::new(0, map, b"challenge-0".to_vec());
    let issued = issue_settled(pca0, &realm.signer, &ctx()).unwrap();

    let mut store = InMemoryCheckpoints::new();
    store.insert(issued.pca_bytes.clone());
    (issued, store)
}

#[test]
fn end_to_end_two_hops() {
    let realm = realm();
    let (settled0, mut store) = initialize(&realm);

    // The settled token verifies end to end and exposes checkpoint 0.
    let state0 = verify_settled(&settled0.token, &realm.verifier).unwrap();
    assert_eq!(state0.checkpoint.position, 0);
    assert_eq!(state0.checkpoint.context_of_authority.invariants.len(), 2);
    assert_eq!(
        state0.checkpoint.context_of_authority.invariants[&0].0,
        "documents:read:document-42"
    );
    assert_eq!(
        state0.checkpoint.context_of_authority.invariants[&1].0,
        "storage:save"
    );

    // --- Worker 1: reads document-42, drops the read invariant (h'01'). ---
    let (worker1, por1) = worker("spiffe://acme/ns/docs/sa/worker-1");
    let candidate1 = build_candidate(
        &state0.pca_bytes,
        CandidateRequest {
            attenuations: Attenuations {
                invariants: RemoveBitmap::from_indices(&[0]),
                ..Default::default()
            },
            next_challenge: b"challenge-1".to_vec(),
            proof_of_relationship: Some(por1),
            aud: Some("pic-x".into()),
            iat: Some(1_786_700_700),
            ..Default::default()
        },
        &worker1,
        Some(&realm.verifier),
    )
    .unwrap();
    assert_eq!(
        candidate1
            .transition
            .attenuations
            .as_ref()
            .unwrap()
            .invariants
            .as_ref()
            .unwrap()
            .remove_bitmap,
        vec![0x01]
    );

    let authority = SettlementAuthority {
        trusted: &store,
        por: &StubPor,
        revocation: &NoRevocation,
        policy: &DefaultPolicy,
        order: &ReferenceProfile,
        realm: &realm.signer,
    };
    let settled1 = authority.settle(&candidate1.token, &ctx()).unwrap();
    store.replace(&settled0.pca_bytes, settled1.pca_bytes.clone());

    let state1 = verify_settled(&settled1.token, &realm.verifier).unwrap();
    assert_eq!(state1.checkpoint.position, 1);
    assert_eq!(state1.checkpoint.context_of_authority.invariants.len(), 1);
    // storage:save re-materialized at section-local index 0.
    assert_eq!(
        state1.checkpoint.context_of_authority.invariants[&0].0,
        "storage:save"
    );
    assert_eq!(
        state1.checkpoint.challenge.next_challenge,
        b"challenge-1".to_vec()
    );
    // The execution contract is preserved.
    assert_eq!(
        state1.checkpoint.context_of_authority.execution_contract[&0].0,
        "corporation"
    );
    assert_eq!(
        state1.checkpoint.context_of_authority.execution_contract[&1].0,
        "department"
    );

    // --- Worker 2: saves, drops the save invariant — h'01' again. ---
    let (worker2, por2) = worker("spiffe://acme/ns/storage/sa/worker-2");
    let candidate2 = build_candidate(
        &state1.pca_bytes,
        CandidateRequest {
            attenuations: Attenuations {
                invariants: RemoveBitmap::from_indices(&[0]),
                ..Default::default()
            },
            next_challenge: b"challenge-2".to_vec(),
            proof_of_relationship: Some(por2),
            aud: Some("pic-x".into()),
            ..Default::default()
        },
        &worker2,
        Some(&realm.verifier),
    )
    .unwrap();

    let authority = SettlementAuthority {
        trusted: &store,
        por: &StubPor,
        revocation: &NoRevocation,
        policy: &DefaultPolicy,
        order: &ReferenceProfile,
        realm: &realm.signer,
    };
    let settled2 = authority.settle(&candidate2.token, &ctx()).unwrap();

    let state2 = verify_settled(&settled2.token, &realm.verifier).unwrap();
    assert_eq!(state2.checkpoint.position, 2);
    // Zero executable authority; the checkpoint and its contract remain.
    assert!(state2.checkpoint.context_of_authority.invariants.is_empty());
    assert_eq!(
        state2
            .checkpoint
            .context_of_authority
            .execution_contract
            .len(),
        2
    );
}

fn expect_reject(
    result: Result<pic_continuity::verifier::SettledIssue, ContinuityError>,
) -> RejectReason {
    match result {
        Err(ContinuityError::Reject(r)) => r,
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[test]
fn settlement_rejections() {
    let realm = realm();
    let (settled0, store) = initialize(&realm);
    let state0 = verify_settled(&settled0.token, &realm.verifier).unwrap();
    let (worker1, por1) = worker("spiffe://acme/ns/docs/sa/worker-1");

    let base_request = || CandidateRequest {
        attenuations: Attenuations {
            invariants: RemoveBitmap::from_indices(&[0]),
            ..Default::default()
        },
        next_challenge: b"challenge-1".to_vec(),
        proof_of_relationship: Some(por1.clone()),
        ..Default::default()
    };

    let auth = SettlementAuthority {
        trusted: &store,
        por: &StubPor,
        revocation: &NoRevocation,
        policy: &DefaultPolicy,
        order: &ReferenceProfile,
        realm: &realm.signer,
    };

    // Wrong PoR type is rejected before anything else about the evidence.
    let mut req = base_request();
    req.proof_of_relationship = Some(ProofOfRelationship {
        por_type: "x509".into(),
        evidence: vec![0x01],
    });
    let candidate = build_candidate(&state0.pca_bytes, req, &worker1, None).unwrap();
    assert_eq!(
        expect_reject(auth.settle(&candidate.token, &ctx())),
        RejectReason::PorType("x509".into())
    );

    // A key different from the PoR-bound key fails the workload signatures.
    let (other_worker, _) = worker("spiffe://acme/ns/docs/sa/impostor");
    let candidate =
        build_candidate(&state0.pca_bytes, base_request(), &other_worker, None).unwrap();
    assert_eq!(
        expect_reject(auth.settle(&candidate.token, &ctx())),
        RejectReason::WorkloadSignature("PIC Continuity Transition COSE")
    );

    // An untrusted checkpoint (not the current settled bytes) is rejected.
    let empty_store = InMemoryCheckpoints::new();
    let auth_empty = SettlementAuthority {
        trusted: &empty_store,
        por: &StubPor,
        revocation: &NoRevocation,
        policy: &DefaultPolicy,
        order: &ReferenceProfile,
        realm: &realm.signer,
    };
    let candidate = build_candidate(&state0.pca_bytes, base_request(), &worker1, None).unwrap();
    assert_eq!(
        expect_reject(auth_empty.settle(&candidate.token, &ctx())),
        RejectReason::UntrustedCheckpoint
    );

    // A bitmap referencing a nonexistent index is unbuildable by the prover
    // and rejected by settlement when hand-crafted.
    let mut req = base_request();
    req.attenuations = Attenuations {
        invariants: RemoveBitmap::from_indices(&[2]),
        ..Default::default()
    };
    assert!(matches!(
        build_candidate(&state0.pca_bytes, req, &worker1, None),
        Err(ContinuityError::Reject(
            RejectReason::BitmapIndexOutOfRange("invariants")
        ))
    ));

    // Duplicate execution-contract addition keys are rejected.
    let mut req = base_request();
    req.attenuations = Attenuations {
        execution_contract_additions: vec![
            (
                "region".into(),
                pic_continuity::authority::indexed::TupleValue::Text("EU".into()),
            ),
            (
                "region".into(),
                pic_continuity::authority::indexed::TupleValue::Text("US".into()),
            ),
        ],
        ..Default::default()
    };
    assert!(matches!(
        build_candidate(&state0.pca_bytes, req, &worker1, None),
        Err(ContinuityError::Reject(RejectReason::DuplicateAdditionKey(
            _
        )))
    ));

    // Challenge-continuity and position checks: forge a candidate whose
    // predecessor is stale — settle once, keep using the old checkpoint.
    let candidate = build_candidate(&state0.pca_bytes, base_request(), &worker1, None).unwrap();
    let settled1 = auth.settle(&candidate.token, &ctx()).unwrap();
    let mut store2 = InMemoryCheckpoints::new();
    store2.insert(settled1.pca_bytes.clone());
    let auth2 = SettlementAuthority {
        trusted: &store2,
        por: &StubPor,
        revocation: &NoRevocation,
        policy: &DefaultPolicy,
        order: &ReferenceProfile,
        realm: &realm.signer,
    };
    // The same candidate again: its checkpoint is no longer the current one.
    assert_eq!(
        expect_reject(auth2.settle(&candidate.token, &ctx())),
        RejectReason::UntrustedCheckpoint
    );
}

#[test]
fn contract_additions_materialize_in_canonical_order() {
    let realm = realm();
    let (settled0, store) = initialize(&realm);
    let state0 = verify_settled(&settled0.token, &realm.verifier).unwrap();
    let (worker1, por1) = worker("spiffe://acme/ns/docs/sa/worker-1");

    let candidate = build_candidate(
        &state0.pca_bytes,
        CandidateRequest {
            attenuations: Attenuations {
                execution_contract_additions: vec![
                    (
                        "region".into(),
                        pic_continuity::authority::indexed::TupleValue::Text("EU".into()),
                    ),
                    (
                        "audit".into(),
                        pic_continuity::authority::indexed::TupleValue::Text("required".into()),
                    ),
                ],
                ..Default::default()
            },
            next_challenge: b"challenge-1".to_vec(),
            proof_of_relationship: Some(por1),
            ..Default::default()
        },
        &worker1,
        None,
    )
    .unwrap();

    let auth = SettlementAuthority {
        trusted: &store,
        por: &StubPor,
        revocation: &NoRevocation,
        policy: &DefaultPolicy,
        order: &ReferenceProfile,
        realm: &realm.signer,
    };
    let settled1 = auth.settle(&candidate.token, &ctx()).unwrap();
    let state1 = verify_settled(&settled1.token, &realm.verifier).unwrap();

    let contract = &state1.checkpoint.context_of_authority.execution_contract;
    // Existing entries keep their indexes; accepted additions are appended
    // in canonical key order with the next section-local indexes.
    assert_eq!(contract[&0].0, "corporation");
    assert_eq!(contract[&1].0, "department");
    assert_eq!(contract[&2].0, "audit");
    assert_eq!(contract[&3].0, "region");
}

#[test]
fn tampered_candidate_continuity_is_rejected() {
    let realm = realm();
    let (settled0, store) = initialize(&realm);
    let state0 = verify_settled(&settled0.token, &realm.verifier).unwrap();
    let (worker1, por1) = worker("spiffe://acme/ns/docs/sa/worker-1");

    let candidate = build_candidate(
        &state0.pca_bytes,
        CandidateRequest {
            attenuations: Attenuations {
                invariants: RemoveBitmap::from_indices(&[0]),
                ..Default::default()
            },
            next_challenge: b"challenge-1".to_vec(),
            proof_of_relationship: Some(por1),
            ..Default::default()
        },
        &worker1,
        None,
    )
    .unwrap();

    // Re-wrap the candidate continuity bytes into a token signed by a
    // different key: the PoR-bound key no longer verifies the JWT.
    let (impostor, _) = worker("spiffe://acme/ns/docs/sa/impostor");
    let claims = pic_continuity::artifacts::token::PicTokenClaims::for_continuity(
        &candidate.continuity_bytes,
    );
    let forged = pic_continuity::artifacts::token::sign_token(&claims, &impostor).unwrap();

    let auth = SettlementAuthority {
        trusted: &store,
        por: &StubPor,
        revocation: &NoRevocation,
        policy: &DefaultPolicy,
        order: &ReferenceProfile,
        realm: &realm.signer,
    };
    assert_eq!(
        expect_reject(auth.settle(&forged, &ctx())),
        RejectReason::WorkloadSignature("candidate PIC Token JWT")
    );
}

#[test]
fn settlement_rejects_non_pic_jwt_typ() {
    let realm = realm();
    let (settled0, store) = initialize(&realm);
    let state0 = verify_settled(&settled0.token, &realm.verifier).unwrap();
    let (worker1, por1) = worker("spiffe://acme/ns/docs/sa/worker-1");

    let candidate = build_candidate(
        &state0.pca_bytes,
        CandidateRequest {
            attenuations: Attenuations {
                invariants: RemoveBitmap::from_indices(&[0]),
                ..Default::default()
            },
            next_challenge: b"challenge-1".to_vec(),
            proof_of_relationship: Some(por1),
            ..Default::default()
        },
        &worker1,
        None,
    )
    .unwrap();

    let claims = PicTokenClaims::for_continuity(&candidate.continuity_bytes);
    let wrong_typ = sign_claims_with_typ(&claims, "at+jwt", &worker1);

    let auth = SettlementAuthority {
        trusted: &store,
        por: &StubPor,
        revocation: &NoRevocation,
        policy: &DefaultPolicy,
        order: &ReferenceProfile,
        realm: &realm.signer,
    };
    assert!(matches!(
        expect_reject(auth.settle(&wrong_typ, &ctx())),
        RejectReason::Malformed(_)
    ));
}

#[test]
fn issue_settled_rejects_invalid_checkpoint_payloads() {
    let realm = realm();
    let map = IndexedAuthorityMap::from_logical(&walkthrough_logical()).unwrap();

    let empty_challenge = PicPcaPayload::new(0, map.clone(), vec![]);
    assert!(matches!(
        issue_settled(empty_challenge, &realm.signer, &ctx()),
        Err(ContinuityError::Reject(RejectReason::NextChallengeInvalid))
    ));

    let empty_contract = PicPcaPayload {
        profile: pic_continuity::PROFILE_0_2.into(),
        position: 0,
        context_of_authority: IndexedAuthorityMap::default(),
        challenge: PcaChallenge {
            next_challenge: b"challenge-0".to_vec(),
        },
    };
    assert!(matches!(
        issue_settled(empty_contract, &realm.signer, &ctx()),
        Err(ContinuityError::Reject(
            RejectReason::EmptyExecutionContract
        ))
    ));
}
