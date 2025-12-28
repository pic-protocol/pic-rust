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

//! PCA serialization benchmarks with structured output.
//!
//! Run with: cargo run --example pca_serialization --release

use pic_pca::{
    CatProvenance, Constraints, Executor, ExecutorBinding, ExecutorProvenance,
    PcaPayload, Provenance, TemporalConstraints,
};
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

fn format_time(ns: u64) -> String {
    if ns >= 1_000_000 {
        format!("{:.2} ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.2} µs", ns as f64 / 1_000.0)
    } else {
        format!("{} ns", ns)
    }
}

fn bench_pca(name: &str, pca: &PcaPayload) {
    let cbor_bytes = pca.to_cbor().unwrap();
    let json_bytes = pca.to_json().unwrap();

    let cbor_ser = bench_avg_ns(ITERATIONS, || { let _ = pca.to_cbor().unwrap(); });
    let json_ser = bench_avg_ns(ITERATIONS, || { let _ = pca.to_json().unwrap(); });

    let cbor_de = bench_avg_ns(ITERATIONS, || { let _ = PcaPayload::from_cbor(&cbor_bytes).unwrap(); });
    let json_de = bench_avg_ns(ITERATIONS, || { let _ = PcaPayload::from_json(&json_bytes).unwrap(); });

    let cbor_rt = cbor_ser + cbor_de;
    let json_rt = json_ser + json_de;

    println!();
    println!("\x1b[33m{}\x1b[0m", "=".repeat(50));
    println!("\x1b[1m{}\x1b[0m", name);
    println!("\x1b[33m{}\x1b[0m", "=".repeat(50));

    println!();
    println!("Payload: {} bytes CBOR -> {} bytes JSON", cbor_bytes.len(), json_bytes.len());

    println!();
    println!("\x1b[36mCBOR\x1b[0m");
    println!("    Serialize               {}", format_time(cbor_ser));
    println!("    Deserialize             {}", format_time(cbor_de));
    println!("    \x1b[32mROUNDTRIP               {} ({:.2} µs)\x1b[0m", format_time(cbor_rt), cbor_rt as f64 / 1000.0);

    println!();
    println!("\x1b[36mJSON\x1b[0m");
    println!("    Serialize               {}", format_time(json_ser));
    println!("    Deserialize             {}", format_time(json_de));
    println!("    \x1b[32mROUNDTRIP               {} ({:.2} µs)\x1b[0m", format_time(json_rt), json_rt as f64 / 1000.0);

    println!();
    println!("\x1b[36mComparison (JSON/CBOR ratio)\x1b[0m");
    println!("    Size                    {:.1}x", json_bytes.len() as f64 / cbor_bytes.len() as f64);
    println!("    Serialize               {:.1}x", json_ser as f64 / cbor_ser as f64);
    println!("    Deserialize             {:.1}x", json_de as f64 / cbor_de as f64);
    println!("    Roundtrip               {:.1}x", json_rt as f64 / cbor_rt as f64);
}

fn main() {
    println!();
    println!("\x1b[1mPCA Serialization Benchmark\x1b[0m");
    println!("Iterations: {}", ITERATIONS);

    bench_pca("PCA_0 (origin, no provenance)", &sample_pca_0());
    bench_pca("PCA_n (hop 3, with provenance)", &sample_pca_n());

    println!();
}
