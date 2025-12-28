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

//! PCA benchmark with structured output.
//!
//! Run with: cargo bench --bench pca_benchmark -- --nocapture

use ed25519_dalek::SigningKey;
use pic_pca::{
    CatProvenance, Constraints, CoseSigned, Executor, ExecutorBinding,
    ExecutorProvenance, PcaPayload, Provenance, SignedPca, TemporalConstraints,
};
use rand::rngs::OsRng;
use std::time::Instant;

const ITERATIONS: u32 = 10000;

fn sample_pca_0() -> PcaPayload {
    let binding = ExecutorBinding::new()
        .with("federation", "https://trust.example.com")
        .with("namespace", "prod")
        .with("service", "api-gateway");

    PcaPayload {
        hop: 0,
        p_0: "https://idp.example.com/users/alice".into(),
        ops: vec!["read:/user/*".into(), "write:/user/*".into()],
        executor: Executor { binding },
        provenance: None,
        constraints: Some(Constraints {
            temporal: Some(TemporalConstraints {
                iat: Some("2025-12-11T10:00:00Z".into()),
                exp: Some("2025-12-11T11:00:00Z".into()),
                nbf: None,
            }),
        }),
    }
}

fn sample_pca_n() -> PcaPayload {
    let binding = ExecutorBinding::new()
        .with("federation", "https://trust.example.com")
        .with("namespace", "prod")
        .with("service", "storage-service");

    PcaPayload {
        hop: 3,
        p_0: "https://idp.example.com/users/alice".into(),
        ops: vec!["read:/user/*".into()],
        executor: Executor { binding },
        provenance: Some(Provenance {
            cat: CatProvenance {
                kid: "https://cat.example.com/keys/1".into(),
                signature: vec![0xAB; 64],
            },
            executor: ExecutorProvenance {
                kid: "spiffe://trust.example.com/ns/prod/sa/archive".into(),
                signature: vec![0xCD; 64],
            },
        }),
        constraints: Some(Constraints {
            temporal: Some(TemporalConstraints {
                iat: Some("2025-12-11T10:00:00Z".into()),
                exp: Some("2025-12-11T10:30:00Z".into()),
                nbf: None,
            }),
        }),
    }
}

fn bench_avg_ns<F>(iterations: u32, mut f: F) -> u64
where
    F: FnMut(),
{
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();
    elapsed.as_nanos() as u64 / iterations as u64
}

fn print_header(title: &str) {
    println!();
    println!("\x1b[33m{}\x1b[0m", "=".repeat(60));
    println!("\x1b[33m  {}\x1b[0m", title);
    println!("\x1b[33m{}\x1b[0m", "=".repeat(60));
}

fn print_section(title: &str) {
    println!();
    println!("\x1b[36m{}\x1b[0m", title);
}

fn print_metric(label: &str, value_ns: u64) {
    let (value, unit) = if value_ns >= 1_000_000 {
        (value_ns as f64 / 1_000_000.0, "ms")
    } else if value_ns >= 1_000 {
        (value_ns as f64 / 1_000.0, "µs")
    } else {
        (value_ns as f64, "ns")
    };
    println!("  {:<30} {:>10.2} {}", label, value, unit);
}

fn print_size(label: &str, bytes: usize) {
    println!("  {:<30} {:>10} bytes", label, bytes);
}

fn print_total(label: &str, value_ns: u64) {
    let (value, unit) = if value_ns >= 1_000_000 {
        (value_ns as f64 / 1_000_000.0, "ms")
    } else if value_ns >= 1_000 {
        (value_ns as f64 / 1_000.0, "µs")
    } else {
        (value_ns as f64, "ns")
    };
    println!("  \x1b[32m{:<30} {:>10.2} {} ({:.2} µs)\x1b[0m", label, value, unit, value_ns as f64 / 1000.0);
}

fn bench_pca(name: &str, pca: &PcaPayload) {
    print_header(&format!("PCA Benchmark: {}", name));

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let kid = "spiffe://trust.example.com/ns/prod/sa/cat";

    // Sizes
    let cbor_bytes = pca.to_cbor().unwrap();
    let json_bytes = pca.to_json().unwrap();
    let signed: SignedPca = CoseSigned::sign_ed25519(pca, kid, &signing_key).unwrap();
    let cose_bytes = signed.to_bytes().unwrap();

    print_section("SIZES");
    print_size("CBOR (payload)", cbor_bytes.len());
    print_size("JSON (payload)", json_bytes.len());
    print_size("COSE_Sign1 (signed)", cose_bytes.len());
    print_size("COSE overhead", cose_bytes.len() - cbor_bytes.len());

    // Serialization formats
    print_section("SERIALIZATION (format comparison)");
    
    let cbor_ser = bench_avg_ns(ITERATIONS, || {
        let _ = pca.to_cbor().unwrap();
    });
    print_metric("to_cbor()", cbor_ser);

    let cbor_de = bench_avg_ns(ITERATIONS, || {
        let _ = PcaPayload::from_cbor(&cbor_bytes).unwrap();
    });
    print_metric("from_cbor()", cbor_de);

    let json_ser = bench_avg_ns(ITERATIONS, || {
        let _ = pca.to_json().unwrap();
    });
    print_metric("to_json()", json_ser);

    let json_de = bench_avg_ns(ITERATIONS, || {
        let _ = PcaPayload::from_json(&json_bytes).unwrap();
    });
    print_metric("from_json()", json_de);

    // COSE operations
    print_section("CREATION (sender side)");

    let serialize_time = bench_avg_ns(ITERATIONS, || {
        let _ = pca.to_cbor().unwrap();
    });
    print_metric("Serialize (CBOR)", serialize_time);

    let sign_time = bench_avg_ns(ITERATIONS, || {
        let _: SignedPca = CoseSigned::sign_ed25519(pca, kid, &signing_key).unwrap();
    });
    let sign_only = sign_time - serialize_time;
    print_metric("Sign (Ed25519)", sign_only);

    print_total("TOTAL", sign_time);

    print_section("CONSUMPTION (receiver side)");

    let deserialize_time = bench_avg_ns(ITERATIONS, || {
        let _: SignedPca = CoseSigned::from_bytes(&cose_bytes).unwrap();
    });
    print_metric("Deserialize (COSE)", deserialize_time);

    let verify_time = bench_avg_ns(ITERATIONS, || {
        let restored: SignedPca = CoseSigned::from_bytes(&cose_bytes).unwrap();
        let _ = restored.verify_ed25519(&verifying_key).unwrap();
    });
    let verify_only = verify_time - deserialize_time;
    print_metric("Verify (Ed25519)", verify_only);

    print_total("TOTAL", verify_time);

    print_section("ROUNDTRIP");
    let roundtrip = sign_time + verify_time;
    print_total("TOTAL (create + consume)", roundtrip);
}

fn main() {
    println!();
    println!("\x1b[1mPCA Benchmark Suite\x1b[0m");
    println!("Iterations per measurement: {}", ITERATIONS);

    bench_pca("PCA_0 (origin, no provenance)", &sample_pca_0());
    bench_pca("PCA_n (hop 3, with provenance)", &sample_pca_n());

    println!();
}