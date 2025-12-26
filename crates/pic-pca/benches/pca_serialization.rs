use criterion::{Criterion, criterion_group, criterion_main};
use pic_pca::{
    CatProvenance, Constraints, Executor, ExecutorBinding, ExecutorProvenance, KeyMaterial,
    PcaPayload, Provenance, TemporalConstraints,
};

fn sample_pca_0() -> PcaPayload {
    let binding = ExecutorBinding::new().with("org", "acme-corp");

    PcaPayload {
        hop: "gateway".into(),
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
    let binding = ExecutorBinding::new().with("org", "acme-corp");

    PcaPayload {
        hop: "storage".into(),
        p_0: "https://idp.example.com/users/alice".into(),
        ops: vec!["read:/user/*".into()],
        executor: Executor { binding },
        provenance: Some(Provenance {
            cat: CatProvenance {
                issuer: "https://cat.acme-corp.com".into(),
                signature: vec![0u8; 64],
                key: KeyMaterial {
                    public_key: vec![0u8; 32],
                    alg: "EdDSA".into(),
                },
            },
            executor: ExecutorProvenance {
                issuer: "spiffe://acme-corp/archive".into(),
                signature: vec![0u8; 64],
                key: KeyMaterial {
                    public_key: vec![0u8; 32],
                    alg: "EdDSA".into(),
                },
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

fn bench_pca(c: &mut Criterion) {
    let pca_0 = sample_pca_0();
    let pca_n = sample_pca_n();
    let cbor_0 = pca_0.to_cbor().unwrap();
    let cbor_n = pca_n.to_cbor().unwrap();

    println!();
    println!("PCA Size");
    println!("--------");
    println!("PCA_0: {} bytes", cbor_0.len());
    println!("PCA_n: {} bytes", cbor_n.len());
    println!();

    c.bench_function("pca_0/serialize", |b| b.iter(|| pca_0.to_cbor().unwrap()));

    c.bench_function("pca_0/deserialize", |b| {
        b.iter(|| PcaPayload::from_cbor(&cbor_0).unwrap())
    });

    c.bench_function("pca_n/serialize", |b| b.iter(|| pca_n.to_cbor().unwrap()));

    c.bench_function("pca_n/deserialize", |b| {
        b.iter(|| PcaPayload::from_cbor(&cbor_n).unwrap())
    });
}

fn bench_chain(c: &mut Criterion) {
    c.bench_function("chain/3_hops", |b| {
        b.iter(|| {
            // HOP: Gateway
            let pca_0 = PcaPayload {
                hop: "gateway".into(),
                p_0: "https://idp.example.com/users/alice".into(),
                ops: vec!["read:/user/*".into(), "write:/user/*".into()],
                executor: Executor {
                    binding: ExecutorBinding::new().with("org", "acme-corp"),
                },
                provenance: None,
                constraints: None,
            };
            let b0 = pca_0.to_cbor().unwrap();
            let r0 = PcaPayload::from_cbor(&b0).unwrap();

            // HOP: Archive
            let pca_1 = PcaPayload {
                hop: "archive".into(),
                p_0: r0.p_0.clone(),
                ops: vec!["read:/user/*".into()],
                executor: Executor {
                    binding: ExecutorBinding::new().with("org", "acme-corp"),
                },
                provenance: Some(Provenance {
                    cat: CatProvenance {
                        issuer: "https://cat.acme-corp.com".into(),
                        signature: vec![1u8; 64],
                        key: KeyMaterial {
                            public_key: vec![1u8; 32],
                            alg: "EdDSA".into(),
                        },
                    },
                    executor: ExecutorProvenance {
                        issuer: "spiffe://acme-corp/gateway".into(),
                        signature: vec![1u8; 64],
                        key: KeyMaterial {
                            public_key: vec![1u8; 32],
                            alg: "EdDSA".into(),
                        },
                    },
                }),
                constraints: None,
            };
            let b1 = pca_1.to_cbor().unwrap();
            let r1 = PcaPayload::from_cbor(&b1).unwrap();

            // HOP: Storage
            let pca_2 = PcaPayload {
                hop: "storage".into(),
                p_0: r1.p_0.clone(),
                ops: vec!["read:/user/alice/*".into()],
                executor: Executor {
                    binding: ExecutorBinding::new().with("org", "acme-corp"),
                },
                provenance: Some(Provenance {
                    cat: CatProvenance {
                        issuer: "https://cat.acme-corp.com".into(),
                        signature: vec![2u8; 64],
                        key: KeyMaterial {
                            public_key: vec![2u8; 32],
                            alg: "EdDSA".into(),
                        },
                    },
                    executor: ExecutorProvenance {
                        issuer: "spiffe://acme-corp/archive".into(),
                        signature: vec![2u8; 64],
                        key: KeyMaterial {
                            public_key: vec![2u8; 32],
                            alg: "EdDSA".into(),
                        },
                    },
                }),
                constraints: None,
            };
            let b2 = pca_2.to_cbor().unwrap();
            PcaPayload::from_cbor(&b2).unwrap()
        })
    });
}

criterion_group!(benches, bench_pca, bench_chain);
criterion_main!(benches);
