use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use pqc_hpke::hybrid_kem::HybridKem;
use pqc_hpke::hybrid_setup::{setup_hybrid_base_receiver, setup_hybrid_base_sender_deterministic};
use pqc_hpke::identifiers::{AeadId, HpkeSuiteId, KdfId};
use pqc_hpke::ml_kem::MlKemHpke;
use pqc_hpke::setup::{setup_base_receiver, setup_base_sender_deterministic};

const INFO: &[u8] = b"pqc-forge-e3-composition";
const AAD: &[u8] = b"pqc-forge-e3-aad";
const PAYLOAD: [u8; 1024] = [0xa5; 1024];

const PURE_LABEL: &str = "MLKEM768";
const HYBRID_LABEL: &str = "MLKEM768-X25519";

fn pure_suite(kem: MlKemHpke) -> HpkeSuiteId {
    HpkeSuiteId {
        kem_id: kem.kem_id(),
        kdf_id: KdfId::HKDF_SHA256,
        aead_id: AeadId::AES_256_GCM,
    }
}

fn hybrid_suite(kem: HybridKem) -> HpkeSuiteId {
    HpkeSuiteId {
        kem_id: kem.kem_id(),
        kdf_id: KdfId::HKDF_SHA256,
        aead_id: AeadId::AES_256_GCM,
    }
}

fn bench_composition(c: &mut Criterion) {
    let pure_kem = MlKemHpke::MlKem768;
    let pure_suite = pure_suite(pure_kem);
    let pure_key_pair = pure_kem.derive_key_pair(&[0x11; 64]).unwrap();
    let pure_randomness = [0x22; 32];

    let hybrid_kem = HybridKem::MlKem768X25519;
    let hybrid_suite = hybrid_suite(hybrid_kem);
    let hybrid_key_pair = hybrid_kem.derive_key_pair(&[0x31; 64]).unwrap();
    let hybrid_randomness = vec![0x42; hybrid_kem.randomness_length()];

    let mut group = c.benchmark_group("hpke/composition");

    /*
     * Sender setup
     *
     * Key generation and deterministic randomness preparation are outside the
     * timed region. The measured operation includes KEM encapsulation and the
     * common HPKE key schedule/context construction.
     */

    group.bench_function(BenchmarkId::new("setup_sender", PURE_LABEL), |b| {
        b.iter(|| {
            black_box(
                setup_base_sender_deterministic(
                    pure_kem,
                    pure_suite,
                    black_box(&pure_key_pair.public_key),
                    black_box(INFO),
                    black_box(&pure_randomness),
                )
                .unwrap(),
            )
        })
    });

    group.bench_function(BenchmarkId::new("setup_sender", HYBRID_LABEL), |b| {
        b.iter(|| {
            black_box(
                setup_hybrid_base_sender_deterministic(
                    hybrid_kem,
                    hybrid_suite,
                    black_box(&hybrid_key_pair.public_key),
                    black_box(INFO),
                    black_box(&hybrid_randomness),
                )
                .unwrap(),
            )
        })
    });

    /*
     * Receiver setup
     *
     * A valid encapsulated key is prepared once outside the timed region.
     * Receiver setup measures decapsulation plus the common HPKE key schedule
     * and context construction.
     */

    let pure_sender = setup_base_sender_deterministic(
        pure_kem,
        pure_suite,
        &pure_key_pair.public_key,
        INFO,
        &pure_randomness,
    )
    .unwrap();

    group.bench_function(BenchmarkId::new("setup_receiver", PURE_LABEL), |b| {
        b.iter(|| {
            black_box(
                setup_base_receiver(
                    pure_kem,
                    pure_suite,
                    black_box(pure_key_pair.private_key_seed.as_bytes()),
                    black_box(&pure_sender.encapsulated_key),
                    black_box(INFO),
                )
                .unwrap(),
            )
        })
    });

    let hybrid_sender = setup_hybrid_base_sender_deterministic(
        hybrid_kem,
        hybrid_suite,
        &hybrid_key_pair.public_key,
        INFO,
        &hybrid_randomness,
    )
    .unwrap();

    group.bench_function(BenchmarkId::new("setup_receiver", HYBRID_LABEL), |b| {
        b.iter(|| {
            black_box(
                setup_hybrid_base_receiver(
                    hybrid_kem,
                    hybrid_suite,
                    black_box(hybrid_key_pair.private_seed.as_bytes()),
                    black_box(&hybrid_sender.encapsulated_key),
                    black_box(INFO),
                )
                .unwrap(),
            )
        })
    });

    /*
     * Protected-message operations
     *
     * Fresh contexts are constructed in Criterion batched setup. The timed
     * closure contains only seal/open so KEM setup cannot contaminate the
     * steady-state message measurements.
     */

    group.bench_function(BenchmarkId::new("seal_1k", PURE_LABEL), |b| {
        b.iter_batched(
            || {
                setup_base_sender_deterministic(
                    pure_kem,
                    pure_suite,
                    &pure_key_pair.public_key,
                    INFO,
                    &pure_randomness,
                )
                .unwrap()
                .context
            },
            |mut sender| black_box(sender.seal(black_box(AAD), black_box(&PAYLOAD)).unwrap()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function(BenchmarkId::new("seal_1k", HYBRID_LABEL), |b| {
        b.iter_batched(
            || {
                setup_hybrid_base_sender_deterministic(
                    hybrid_kem,
                    hybrid_suite,
                    &hybrid_key_pair.public_key,
                    INFO,
                    &hybrid_randomness,
                )
                .unwrap()
                .context
            },
            |mut sender| black_box(sender.seal(black_box(AAD), black_box(&PAYLOAD)).unwrap()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function(BenchmarkId::new("open_1k", PURE_LABEL), |b| {
        b.iter_batched(
            || {
                let mut sender = setup_base_sender_deterministic(
                    pure_kem,
                    pure_suite,
                    &pure_key_pair.public_key,
                    INFO,
                    &pure_randomness,
                )
                .unwrap();

                let ciphertext = sender.context.seal(AAD, &PAYLOAD).unwrap();

                let receiver = setup_base_receiver(
                    pure_kem,
                    pure_suite,
                    pure_key_pair.private_key_seed.as_bytes(),
                    &sender.encapsulated_key,
                    INFO,
                )
                .unwrap();

                (receiver, ciphertext)
            },
            |(mut receiver, ciphertext)| {
                black_box(
                    receiver
                        .open(black_box(AAD), black_box(&ciphertext))
                        .unwrap(),
                )
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function(BenchmarkId::new("open_1k", HYBRID_LABEL), |b| {
        b.iter_batched(
            || {
                let mut sender = setup_hybrid_base_sender_deterministic(
                    hybrid_kem,
                    hybrid_suite,
                    &hybrid_key_pair.public_key,
                    INFO,
                    &hybrid_randomness,
                )
                .unwrap();

                let ciphertext = sender.context.seal(AAD, &PAYLOAD).unwrap();

                let receiver = setup_hybrid_base_receiver(
                    hybrid_kem,
                    hybrid_suite,
                    hybrid_key_pair.private_seed.as_bytes(),
                    &sender.encapsulated_key,
                    INFO,
                )
                .unwrap();

                (receiver, ciphertext)
            },
            |(mut receiver, ciphertext)| {
                black_box(
                    receiver
                        .open(black_box(AAD), black_box(&ciphertext))
                        .unwrap(),
                )
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, bench_composition);
criterion_main!(benches);
