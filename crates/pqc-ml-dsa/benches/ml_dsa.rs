use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pqc_ml_dsa::keygen::keygen_internal;
use pqc_ml_dsa::signature::sign_internal;
use pqc_ml_dsa::verification::verify_internal;
use pqc_ml_dsa::MlDsaParameterSet;

const MESSAGE: &[u8] = b"pqc-rfc9958-rs B1.3.5 performance baseline";
const CONTEXT: &[u8] = b"benchmark";
const SIGNING_RANDOMNESS: [u8; 32] = [0_u8; 32];

fn cases() -> [(MlDsaParameterSet, &'static str, [u8; 32]); 3] {
    [
        (MlDsaParameterSet::MlDsa44, "ML-DSA-44", [0x44; 32]),
        (MlDsaParameterSet::MlDsa65, "ML-DSA-65", [0x65; 32]),
        (MlDsaParameterSet::MlDsa87, "ML-DSA-87", [0x87; 32]),
    ]
}

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa/keygen");
    group.sample_size(10);
    for (parameter_set, name, seed) in cases() {
        group.bench_with_input(BenchmarkId::from_parameter(name), &seed, |b, input| {
            b.iter(|| keygen_internal(parameter_set, black_box(input)).unwrap())
        });
    }
    group.finish();
}

fn bench_sign_verify(c: &mut Criterion) {
    let mut sign_group = c.benchmark_group("ml_dsa/sign");
    sign_group.sample_size(10);
    let mut prepared = Vec::new();

    for (parameter_set, name, seed) in cases() {
        let key_pair = keygen_internal(parameter_set, &seed).unwrap();
        let signature = sign_internal(
            parameter_set,
            key_pair.private_key(),
            MESSAGE,
            CONTEXT,
            &SIGNING_RANDOMNESS,
        )
        .unwrap();

        sign_group.bench_with_input(
            BenchmarkId::from_parameter(name),
            key_pair.private_key(),
            |b, private_key| {
                b.iter(|| {
                    sign_internal(
                        parameter_set,
                        black_box(private_key),
                        black_box(MESSAGE),
                        black_box(CONTEXT),
                        black_box(&SIGNING_RANDOMNESS),
                    )
                    .unwrap()
                })
            },
        );

        prepared.push((parameter_set, name, key_pair, signature));
    }
    sign_group.finish();

    let mut verify_group = c.benchmark_group("ml_dsa/verify");
    verify_group.sample_size(10);
    for (parameter_set, name, key_pair, signature) in &prepared {
        verify_group.bench_with_input(BenchmarkId::from_parameter(*name), signature, |b, sig| {
            b.iter(|| {
                verify_internal(
                    *parameter_set,
                    black_box(key_pair.public_key()),
                    black_box(MESSAGE),
                    black_box(CONTEXT),
                    black_box(sig),
                )
                .unwrap()
            })
        });
    }
    verify_group.finish();
}

criterion_group!(benches, bench_keygen, bench_sign_verify);
criterion_main!(benches);
