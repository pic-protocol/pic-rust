# pic-continuity

PIC Profile 0.2 continuity artifacts, Prover, and Verifier for the [PIC Protocol](https://www.pic-protocol.org)
(Provenance Identity Continuity).

This crate implements the artifact family and procedures of the
[PIC Prover and Verifier Specification](https://github.com/pic-protocol/pic-spec) (draft 0.2):

- **Artifacts** — PIC Token JWT (`pic+jwt`), PIC PCA COSE, PIC Continuity COSE, and PIC Continuity Transition COSE.
  Every signed-artifact hash is SHA-256 over the **exact signed bytes**, and the API only accepts raw byte slices,
  so the shape of the code enforces the rule.
- **Authority model** — the Logical Context of Authority, its deterministic canonicalization into the Indexed
  Authority Map, LSB-first removal bitmaps, execution-contract additions, and the non-expansion order
  (invariants and identity are removal-only; the execution contract is additions-only).
- **Prover** — builds the three workload-signed candidate artifacts from the current trusted checkpoint,
  ready to be submitted as an RFC 8693 `subject_token`.
- **Verifier** — ordinary offline verification of settled artifacts, plus the full settlement-authority
  validation procedure (the role a PIC realm such as PIC-X performs): candidate as untrusted input,
  Proof of Relationship, workload signatures, checkpoint binding, challenge continuity, attenuation
  materialization, non-expansion, revocation and policy hooks, and issuance of checkpoint N+1.

The Verifier is pure: no I/O. Trusted checkpoint state, key material, revocation, and policy all enter
through traits (`trust`, `por`), so the crate embeds in any host — a token-exchange service, a sidecar,
a test harness.

## Usage

Most applications should depend on the [`pic-protocol`](https://crates.io/crates/pic-protocol) facade crate
and use it as `pic::continuity::…`. Depend on `pic-continuity` directly when you want only this profile
implementation.

```toml
[dependencies]
pic-continuity = "0.2"
```

See the crate-level documentation on [docs.rs](https://docs.rs/pic-continuity) for a complete
issue-and-verify example and the role map.

## Feature flags

| Feature | Effect |
|---------|--------|
| `ed25519` *(default)* | Ed25519 signers/verifiers via `ed25519-dalek` |
| `p256` | ECDSA P-256 (`ES256`) |
| `p384` | ECDSA P-384 (`ES384`) |
| `full` | All of the above |

With no features enabled the crate still builds: the protocol logic is crypto-agnostic, and
signing/verification enter through closures or the `ArtifactSigner`/`ArtifactVerifier` traits.

## What this crate does not do

- **SD-JWT Proof of Relationship validation** — deployment-specific; supply it through `por::PorValidator`.
- **Revocation state** — supply it through `trust::RevocationCheck`.
- **Transport, storage, OAuth endpoints** — this crate is pure protocol logic.

## License

Licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

The PIC Model is original theoretical work created by Nicola Gallo.
This implementation is developed and maintained by Nitro Agility S.r.l.
