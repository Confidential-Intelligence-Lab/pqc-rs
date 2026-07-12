use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pqc_ml_kem::ml_kem_decaps::decaps_internal;
use pqc_ml_kem::ml_kem_encaps::encaps_internal;
use pqc_ml_kem::ml_kem_keygen::{
    ml_kem_1024_keygen_internal, ml_kem_512_keygen_internal, ml_kem_768_keygen_internal,
};
use pqc_ml_kem::MlKemParameterSet;

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_kem/keygen");
    group.bench_function("ML-KEM-512", |b| {
        b.iter(|| {
            ml_kem_512_keygen_internal(black_box(&[0x11; 32]), black_box(&[0x22; 32])).unwrap()
        })
    });
    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| {
            ml_kem_768_keygen_internal(black_box(&[0x33; 32]), black_box(&[0x44; 32])).unwrap()
        })
    });
    group.bench_function("ML-KEM-1024", |b| {
        b.iter(|| {
            ml_kem_1024_keygen_internal(black_box(&[0x55; 32]), black_box(&[0x66; 32])).unwrap()
        })
    });
    group.finish();
}

fn bench_encaps_decaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_kem/encaps_decaps");
    let cases = [
        {
            let p = ml_kem_512_keygen_internal(&[0x11; 32], &[0x22; 32]).unwrap();
            (
                "ML-KEM-512",
                MlKemParameterSet::MlKem512,
                p.encapsulation_key.to_vec(),
                p.decapsulation_key.to_vec(),
            )
        },
        {
            let p = ml_kem_768_keygen_internal(&[0x33; 32], &[0x44; 32]).unwrap();
            (
                "ML-KEM-768",
                MlKemParameterSet::MlKem768,
                p.encapsulation_key.to_vec(),
                p.decapsulation_key.to_vec(),
            )
        },
        {
            let p = ml_kem_1024_keygen_internal(&[0x55; 32], &[0x66; 32]).unwrap();
            (
                "ML-KEM-1024",
                MlKemParameterSet::MlKem1024,
                p.encapsulation_key.to_vec(),
                p.decapsulation_key.to_vec(),
            )
        },
    ];

    for (name, set, ek, dk) in cases {
        let enc = encaps_internal(set, &ek, &[0x77; 32]).unwrap();
        let ct = enc.ciphertext.clone();
        group.bench_with_input(BenchmarkId::new("encaps", name), &ek, |b, pk| {
            b.iter(|| encaps_internal(set, black_box(pk), black_box(&[0x77; 32])).unwrap())
        });
        group.bench_with_input(BenchmarkId::new("decaps", name), &(dk, ct), |b, input| {
            b.iter(|| decaps_internal(set, black_box(&input.0), black_box(&input.1)).unwrap())
        });
    }
    group.finish();
}

criterion_group!(benches, bench_keygen, bench_encaps_decaps);
criterion_main!(benches);
