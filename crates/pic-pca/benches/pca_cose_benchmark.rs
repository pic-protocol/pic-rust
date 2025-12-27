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

//! PCA COSE_Sign1 Benchmark
//!
//! Measures signing and verification performance for a single PCA hop.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ed25519_dalek::{Signer, SigningKey};
use pic_pca::{CoseSigned, Executor, ExecutorBinding, PcaPayload, SignedPca};
use rand::rngs::OsRng;
use std::time::Instant;

/// Creates a representative PCA payload for benchmarking.
fn sample_pca() -> PcaPayload {
    let binding = ExecutorBinding::new()
        .with("org", "acme-corp")
        .with("region", "eu-west-1");

    PcaPayload {
        hop: "api-gateway".into(),
        p_0: "https://idp.example.com/users/alice".into(),
        ops: vec!["read:/user/*".into(), "write:/user/*".into()],
        executor: Executor { binding },
        provenance: None,
        constraints: None,
    }
}

/// Prints a summary table with detailed timing breakdown.
fn print_summary() {
    let pca = sample_pca();
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let iterations = 10_000;

    // Creation phase
    let cbor = pca.to_cbor().unwrap();

    let start = Instant::now();
    for _ in 0..iterations {
        black_box(pca.to_cbor().unwrap());
    }
    let serialize_time = start.elapsed().as_nanos() / iterations;

    let start = Instant::now();
    for _ in 0..iterations {
        black_box(signing_key.sign(&cbor));
    }
    let sign_time = start.elapsed().as_nanos() / iterations;

    let start = Instant::now();
    for _ in 0..iterations {
        let signed: SignedPca =
            CoseSigned::sign_ed25519(black_box(&pca), "issuer", &signing_key).unwrap();
        black_box(signed.to_bytes().unwrap());
    }
    let creation_total = start.elapsed().as_nanos() / iterations;

    // Consumption phase
    let signed: SignedPca = CoseSigned::sign_ed25519(&pca, "issuer", &signing_key).unwrap();
    let cose_bytes = signed.to_bytes().unwrap();

    let start = Instant::now();
    for _ in 0..iterations {
        black_box(SignedPca::from_bytes(&cose_bytes).unwrap());
    }
    let deserialize_time = start.elapsed().as_nanos() / iterations;

    let restored: SignedPca = SignedPca::from_bytes(&cose_bytes).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(restored.verify_ed25519(&verifying_key).unwrap());
    }
    let verify_time = start.elapsed().as_nanos() / iterations;

    let start = Instant::now();
    for _ in 0..iterations {
        let restored: SignedPca = SignedPca::from_bytes(black_box(&cose_bytes)).unwrap();
        black_box(restored.verify_ed25519(&verifying_key).unwrap());
    }
    let consumption_total = start.elapsed().as_nanos() / iterations;

    // Output
    println!();
    println!("PCA COSE_Sign1 Benchmark (Ed25519)");
    println!("==================================");
    println!();
    println!(
        "Payload: {} bytes CBOR -> {} bytes COSE signed",
        pca.to_cbor().unwrap().len(),
        cose_bytes.len()
    );
    println!();
    println!("CREATION (sender side)");
    println!("  Serialize (CBOR)     {:>8} ns", serialize_time);
    println!("  Sign (Ed25519)       {:>8} ns", sign_time);
    println!(
        "  TOTAL                {:>8} ns  ({:.2} us)",
        creation_total,
        creation_total as f64 / 1000.0
    );
    println!();
    println!("CONSUMPTION (receiver side)");
    println!("  Deserialize (COSE)   {:>8} ns", deserialize_time);
    println!("  Verify (Ed25519)     {:>8} ns", verify_time);
    println!(
        "  TOTAL                {:>8} ns  ({:.2} us)",
        consumption_total,
        consumption_total as f64 / 1000.0
    );
    println!();
    println!(
        "ROUNDTRIP              {:>8} ns  ({:.2} us)",
        creation_total + consumption_total,
        (creation_total + consumption_total) as f64 / 1000.0
    );
    println!();
}

/// Criterion benchmark for PCA COSE operations.
fn bench_cose_operations(c: &mut Criterion) {
    print_summary();

    let pca = sample_pca();
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let signed: SignedPca = CoseSigned::sign_ed25519(&pca, "issuer", &signing_key).unwrap();
    let cose_bytes = signed.to_bytes().unwrap();

    c.bench_function("pca_creation_total", |b| {
        b.iter(|| {
            let signed: SignedPca =
                CoseSigned::sign_ed25519(black_box(&pca), "issuer", &signing_key).unwrap();
            signed.to_bytes().unwrap()
        })
    });

    c.bench_function("pca_consumption_total", |b| {
        b.iter(|| {
            let restored: SignedPca = SignedPca::from_bytes(black_box(&cose_bytes)).unwrap();
            restored.verify_ed25519(&verifying_key).unwrap()
        })
    });
}

criterion_group!(benches, bench_cose_operations);
criterion_main!(benches);