use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pqc_slh_dsa::{SlhDsa, SlhDsaKeyGenSeed, SlhDsaParameterSet, SlhDsaPreHash};

const MESSAGE: &[u8] = b"pqc-rfc9958-rs SLH-DSA performance baseline";
const CONTEXT: &[u8] = b"benchmark";

const CASES: [(SlhDsaParameterSet, &str, u8); 12] = [
    (SlhDsaParameterSet::Sha2_128s, "SLH-DSA-SHA2-128s", 0x11),
    (SlhDsaParameterSet::Sha2_128f, "SLH-DSA-SHA2-128f", 0x12),
    (SlhDsaParameterSet::Sha2_192s, "SLH-DSA-SHA2-192s", 0x21),
    (SlhDsaParameterSet::Sha2_192f, "SLH-DSA-SHA2-192f", 0x22),
    (SlhDsaParameterSet::Sha2_256s, "SLH-DSA-SHA2-256s", 0x31),
    (SlhDsaParameterSet::Sha2_256f, "SLH-DSA-SHA2-256f", 0x32),
    (SlhDsaParameterSet::Shake128s, "SLH-DSA-SHAKE-128s", 0x41),
    (SlhDsaParameterSet::Shake128f, "SLH-DSA-SHAKE-128f", 0x42),
    (SlhDsaParameterSet::Shake192s, "SLH-DSA-SHAKE-192s", 0x51),
    (SlhDsaParameterSet::Shake192f, "SLH-DSA-SHAKE-192f", 0x52),
    (SlhDsaParameterSet::Shake256s, "SLH-DSA-SHAKE-256s", 0x61),
    (SlhDsaParameterSet::Shake256f, "SLH-DSA-SHAKE-256f", 0x62),
];

fn seed_for(parameter_set: SlhDsaParameterSet, fill: u8) -> SlhDsaKeyGenSeed {
    let slh_dsa = SlhDsa::new(parameter_set);
    let bytes = vec![fill; slh_dsa.keygen_seed_bytes()];
    SlhDsaKeyGenSeed::from_bytes(parameter_set, &bytes)
        .expect("benchmark seed must match parameter set")
}

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa/keygen");
    group.sample_size(10);

    for (parameter_set, name, fill) in CASES {
        let slh_dsa = SlhDsa::new(parameter_set);
        let seed = seed_for(parameter_set, fill);

        group.bench_with_input(BenchmarkId::from_parameter(name), &seed, |b, seed| {
            b.iter(|| {
                slh_dsa
                    .keygen_from_seed(black_box(seed))
                    .expect("SLH-DSA key generation must succeed")
            })
        });
    }

    group.finish();
}

fn bench_pure_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa/pure_sign");
    group.sample_size(10);

    for (parameter_set, name, fill) in CASES {
        let slh_dsa = SlhDsa::new(parameter_set);
        let seed = seed_for(parameter_set, fill);
        let key_pair = slh_dsa
            .keygen_from_seed(&seed)
            .expect("SLH-DSA key generation must succeed");

        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            key_pair.private_key(),
            |b, private_key| {
                b.iter(|| {
                    slh_dsa
                        .sign_deterministic(
                            black_box(private_key),
                            black_box(MESSAGE),
                            black_box(CONTEXT),
                        )
                        .expect("Pure SLH-DSA signing must succeed")
                })
            },
        );
    }

    group.finish();
}

fn bench_pure_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa/pure_verify");
    group.sample_size(10);

    for (parameter_set, name, fill) in CASES {
        let slh_dsa = SlhDsa::new(parameter_set);
        let seed = seed_for(parameter_set, fill);
        let key_pair = slh_dsa
            .keygen_from_seed(&seed)
            .expect("SLH-DSA key generation must succeed");
        let signature = slh_dsa
            .sign_deterministic(key_pair.private_key(), MESSAGE, CONTEXT)
            .expect("Pure SLH-DSA signing must succeed");

        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &signature,
            |b, signature| {
                b.iter(|| {
                    let verified = slh_dsa
                        .verify(
                            black_box(key_pair.public_key()),
                            black_box(MESSAGE),
                            black_box(CONTEXT),
                            black_box(signature),
                        )
                        .expect("Pure SLH-DSA verification must complete");
                    assert!(verified);
                    verified
                })
            },
        );
    }

    group.finish();
}

fn bench_hash_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa/hash_sign");
    group.sample_size(10);

    for (parameter_set, name, fill) in CASES {
        let slh_dsa = SlhDsa::new(parameter_set);
        let seed = seed_for(parameter_set, fill);
        let key_pair = slh_dsa
            .keygen_from_seed(&seed)
            .expect("SLH-DSA key generation must succeed");

        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            key_pair.private_key(),
            |b, private_key| {
                b.iter(|| {
                    slh_dsa
                        .hash_sign_deterministic(
                            black_box(private_key),
                            black_box(MESSAGE),
                            black_box(CONTEXT),
                            SlhDsaPreHash::Sha2_256,
                        )
                        .expect("HashSLH-DSA signing must succeed")
                })
            },
        );
    }

    group.finish();
}

fn bench_hash_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa/hash_verify");
    group.sample_size(10);

    for (parameter_set, name, fill) in CASES {
        let slh_dsa = SlhDsa::new(parameter_set);
        let seed = seed_for(parameter_set, fill);
        let key_pair = slh_dsa
            .keygen_from_seed(&seed)
            .expect("SLH-DSA key generation must succeed");
        let signature = slh_dsa
            .hash_sign_deterministic(
                key_pair.private_key(),
                MESSAGE,
                CONTEXT,
                SlhDsaPreHash::Sha2_256,
            )
            .expect("HashSLH-DSA signing must succeed");

        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &signature,
            |b, signature| {
                b.iter(|| {
                    let verified = slh_dsa
                        .hash_verify(
                            black_box(key_pair.public_key()),
                            black_box(MESSAGE),
                            black_box(CONTEXT),
                            SlhDsaPreHash::Sha2_256,
                            black_box(signature),
                        )
                        .expect("HashSLH-DSA verification must complete");
                    assert!(verified);
                    verified
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_pure_sign,
    bench_pure_verify,
    bench_hash_sign,
    bench_hash_verify
);
criterion_main!(benches);
