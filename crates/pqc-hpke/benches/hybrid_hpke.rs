use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pqc_hpke::hybrid_kem::HybridKem;
use pqc_hpke::hybrid_setup::{setup_hybrid_base_receiver, setup_hybrid_base_sender_deterministic};
use pqc_hpke::identifiers::{AeadId, HpkeSuiteId, KdfId};

fn suite(kem: HybridKem) -> HpkeSuiteId {
    match kem {
        HybridKem::MlKem768P256 => HpkeSuiteId {
            kem_id: kem.kem_id(),
            kdf_id: KdfId::HKDF_SHA256,
            aead_id: AeadId::AES_128_GCM,
        },
        HybridKem::MlKem768X25519 => HpkeSuiteId {
            kem_id: kem.kem_id(),
            kdf_id: KdfId::HKDF_SHA256,
            aead_id: AeadId::CHACHA20_POLY1305,
        },
        HybridKem::MlKem1024P384 => HpkeSuiteId {
            kem_id: kem.kem_id(),
            kdf_id: KdfId::HKDF_SHA384,
            aead_id: AeadId::AES_256_GCM,
        },
    }
}

fn bench_hybrid(c: &mut Criterion) {
    let mut group = c.benchmark_group("hpke/hybrid");
    for (name, kem) in [
        ("MLKEM768-P256", HybridKem::MlKem768P256),
        ("MLKEM768-X25519", HybridKem::MlKem768X25519),
        ("MLKEM1024-P384", HybridKem::MlKem1024P384),
    ] {
        let suite = suite(kem);
        let key_pair = kem.derive_key_pair(&[0x33; 64]).unwrap();
        let randomness = vec![0x44; kem.randomness_length()];
        group.bench_with_input(
            BenchmarkId::new("setup_sender", name),
            &randomness,
            |b, coins| {
                b.iter(|| {
                    setup_hybrid_base_sender_deterministic(
                        kem,
                        suite,
                        black_box(&key_pair.public_key),
                        black_box(b"stage8e"),
                        black_box(coins),
                    )
                    .unwrap()
                })
            },
        );
        let sender = setup_hybrid_base_sender_deterministic(
            kem,
            suite,
            &key_pair.public_key,
            b"stage8e",
            &randomness,
        )
        .unwrap();
        group.bench_with_input(
            BenchmarkId::new("setup_receiver", name),
            &sender.encapsulated_key,
            |b, enc| {
                b.iter(|| {
                    setup_hybrid_base_receiver(
                        kem,
                        suite,
                        black_box(key_pair.private_seed.as_bytes()),
                        black_box(enc),
                        black_box(b"stage8e"),
                    )
                    .unwrap()
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_hybrid);
criterion_main!(benches);
