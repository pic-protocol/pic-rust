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

//! PoC benchmark with structured output.
//!
//! Run with: cargo bench --bench poc_benchmark -- --nocapture

use ed25519_dalek::SigningKey;
use pic_pca::{
    CoseSigned, Executor, ExecutorBinding, PcaPayload, PocBuilder, PocPayload,
    SignedPoc,
};
use rand::rngs::OsRng;
use std::time::Instant;

const ITERATIONS: u32 = 10000;

fn sample_predecessor_bytes() -> Vec<u8> {
    let pca = PcaPayload {
        hop: 1,
        p_0: "https://idp.example.com/users/alice".into(),
        ops: vec!["read:/user/*".into(), "write:/user/*".into()],
        executor: Executor {
            binding: ExecutorBinding::new()
                .with("federation", "https://trust.example.com")
                .with("namespace", "prod")
                .with("service", "gateway"),
        },
        provenance: None,
        constraints: None,
    };
    pca.to_cbor().unwrap()
}

fn sample_poc_minimal() -> PocPayload {
    PocBuilder::new(sample_predecessor_bytes())
        .ops(vec!["read:/user/*".into()])
        .attestation("vp", vec![0x01; 128])
        .build()
        .unwrap()
}

fn sample_poc_full() -> PocPayload {
    PocBuilder::new(sample_predecessor_bytes())
        .ops(vec!["read:/user/*".into()])
        .executor(
            ExecutorBinding::new()
                .with("federation", "https://trust.example.com")
                .with("namespace", "prod"),
        )
        .attestation_with_pop("spiffe_svid", vec![0x01; 512], vec![0x02; 64])
        .attestation("vp", vec![0x03; 256])
        .attestation("tee_quote", vec![0x04; 256])
        .build()
        .unwrap()
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
    println!(
        "  \x1b[32m{:<30} {:>10.2} {} ({:.2} µs)\x1b[0m",
        label,
        value,
        unit,
        value_ns as f64 / 1000.0
    );
}

fn bench_poc(name: &str, poc: &PocPayload) {
    print_header(&format!("PoC Benchmark: {}", name));

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let kid = "spiffe://trust.example.com/ns/prod/sa/service-a";
    let challenge = b"pcc-nonce-12345";

    // Sizes
    let cbor_bytes = poc.to_cbor().unwrap();
    let json_bytes = poc.to_json().unwrap();
    let signed: SignedPoc = CoseSigned::sign_ed25519(poc, kid, &signing_key).unwrap();
    let cose_bytes = signed.to_bytes().unwrap();
    let signed_with_challenge: SignedPoc =
        CoseSigned::sign_ed25519_with_challenge(poc, kid, Some(challenge), &signing_key).unwrap();
    let cose_challenge_bytes = signed_with_challenge.to_bytes().unwrap();

    print_section("SIZES");
    print_size("CBOR (payload)", cbor_bytes.len());
    print_size("JSON (payload)", json_bytes.len());
    print_size("COSE_Sign1 (signed)", cose_bytes.len());
    print_size("COSE_Sign1 (with challenge)", cose_challenge_bytes.len());
    print_size("COSE overhead", cose_bytes.len() - cbor_bytes.len());
    print_size("Challenge overhead", cose_challenge_bytes.len() - cose_bytes.len());

    // Serialization formats
    print_section("SERIALIZATION (format comparison)");

    let cbor_ser = bench_avg_ns(ITERATIONS, || {
        let _ = poc.to_cbor().unwrap();
    });
    print_metric("to_cbor()", cbor_ser);

    let cbor_de = bench_avg_ns(ITERATIONS, || {
        let _ = PocPayload::from_cbor(&cbor_bytes).unwrap();
    });
    print_metric("from_cbor()", cbor_de);

    let json_ser = bench_avg_ns(ITERATIONS, || {
        let _ = poc.to_json().unwrap();
    });
    print_metric("to_json()", json_ser);

    let json_de = bench_avg_ns(ITERATIONS, || {
        let _ = PocPayload::from_json(&json_bytes).unwrap();
    });
    print_metric("from_json()", json_de);

    // COSE operations (without challenge)
    print_section("CREATION (sender side)");

    let serialize_time = bench_avg_ns(ITERATIONS, || {
        let _ = poc.to_cbor().unwrap();
    });
    print_metric("Serialize (CBOR)", serialize_time);

    let sign_time = bench_avg_ns(ITERATIONS, || {
        let _: SignedPoc = CoseSigned::sign_ed25519(poc, kid, &signing_key).unwrap();
    });
    let sign_only = sign_time - serialize_time;
    print_metric("Sign (Ed25519)", sign_only);

    print_total("TOTAL", sign_time);

    // With challenge
    print_section("CREATION with challenge (sender side)");

    let sign_challenge_time = bench_avg_ns(ITERATIONS, || {
        let _: SignedPoc =
            CoseSigned::sign_ed25519_with_challenge(poc, kid, Some(challenge), &signing_key)
                .unwrap();
    });
    print_metric("Serialize + Sign + Challenge", sign_challenge_time);
    print_size("Challenge overhead time", (sign_challenge_time - sign_time) as usize);

    print_total("TOTAL", sign_challenge_time);

    print_section("CONSUMPTION (receiver side)");

    let deserialize_time = bench_avg_ns(ITERATIONS, || {
        let _: SignedPoc = CoseSigned::from_bytes(&cose_bytes).unwrap();
    });
    print_metric("Deserialize (COSE)", deserialize_time);

    let verify_time = bench_avg_ns(ITERATIONS, || {
        let restored: SignedPoc = CoseSigned::from_bytes(&cose_bytes).unwrap();
        let _ = restored.verify_ed25519(&verifying_key).unwrap();
    });
    let verify_only = verify_time - deserialize_time;
    print_metric("Verify (Ed25519)", verify_only);

    print_total("TOTAL", verify_time);

    print_section("ROUNDTRIP");
    let roundtrip = sign_time + verify_time;
    print_total("TOTAL (create + consume)", roundtrip);

    let roundtrip_challenge = sign_challenge_time + verify_time;
    print_total("TOTAL (with challenge)", roundtrip_challenge);
}

fn bench_attestations() {
    print_header("Attestation Building Benchmark");

    let predecessor = sample_predecessor_bytes();

    print_section("BUILD TIME by attestation count");

    let build_1 = bench_avg_ns(ITERATIONS, || {
        let _ = PocBuilder::new(predecessor.clone())
            .ops(vec!["read:/user/*".into()])
            .attestation("vp", vec![0x01; 256])
            .build()
            .unwrap();
    });
    print_metric("1 attestation (VP)", build_1);

    let build_2 = bench_avg_ns(ITERATIONS, || {
        let _ = PocBuilder::new(predecessor.clone())
            .ops(vec!["read:/user/*".into()])
            .attestation_with_pop("spiffe_svid", vec![0x01; 512], vec![0x02; 64])
            .attestation("tee_quote", vec![0x03; 256])
            .build()
            .unwrap();
    });
    print_metric("2 attestations (SVID+TEE)", build_2);

    let build_3 = bench_avg_ns(ITERATIONS, || {
        let _ = PocBuilder::new(predecessor.clone())
            .ops(vec!["read:/user/*".into()])
            .attestation_with_pop("spiffe_svid", vec![0x01; 512], vec![0x02; 64])
            .attestation("vp", vec![0x03; 256])
            .attestation("tee_quote", vec![0x04; 256])
            .build()
            .unwrap();
    });
    print_metric("3 attestations (SVID+VP+TEE)", build_3);
}

fn main() {
    println!();
    println!("\x1b[1mPoC Benchmark Suite\x1b[0m");
    println!("Iterations per measurement: {}", ITERATIONS);

    bench_poc("Minimal (1 attestation)", &sample_poc_minimal());
    bench_poc("Full (3 attestations)", &sample_poc_full());
    bench_attestations();

    println!();
}