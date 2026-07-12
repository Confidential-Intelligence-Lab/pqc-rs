use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pqc_hpke::identifiers::{AeadId, HpkeSuiteId, KdfId};
use pqc_hpke::ml_kem::MlKemHpke;
use pqc_hpke::setup::{setup_base_receiver, setup_base_sender_deterministic};

fn bench_hpke(c: &mut Criterion) {
    let kem = MlKemHpke::MlKem768;
    let suite = HpkeSuiteId {
        kem_id: kem.kem_id(),
        kdf_id: KdfId::HKDF_SHA256,
        aead_id: AeadId::AES_128_GCM,
    };
    let key_pair = kem.derive_key_pair(&[0x11; 64]).unwrap();

    c.bench_function("hpke/base/setup_sender", |b| {
        b.iter(|| {
            setup_base_sender_deterministic(
                kem,
                suite,
                black_box(&key_pair.public_key),
                black_box(b"stage8e"),
                black_box(&[0x22; 32]),
            )
            .unwrap()
        })
    });

    let sender =
        setup_base_sender_deterministic(kem, suite, &key_pair.public_key, b"stage8e", &[0x22; 32])
            .unwrap();
    c.bench_function("hpke/base/setup_receiver", |b| {
        b.iter(|| {
            setup_base_receiver(
                kem,
                suite,
                black_box(key_pair.private_key_seed.as_bytes()),
                black_box(&sender.encapsulated_key),
                black_box(b"stage8e"),
            )
            .unwrap()
        })
    });

    c.bench_function("hpke/base/seal_1k", |b| {
        b.iter_batched(
            || {
                setup_base_sender_deterministic(
                    kem,
                    suite,
                    &key_pair.public_key,
                    b"stage8e",
                    &[0x22; 32],
                )
                .unwrap()
                .context
            },
            |mut ctx| {
                ctx.seal(black_box(b"aad"), black_box(&[0xA5; 1024]))
                    .unwrap()
            },
            criterion::BatchSize::SmallInput,
        )
    });

    let mut sender_ctx =
        setup_base_sender_deterministic(kem, suite, &key_pair.public_key, b"stage8e", &[0x22; 32])
            .unwrap()
            .context;
    let ciphertext = sender_ctx.seal(b"aad", &[0xA5; 1024]).unwrap();
    c.bench_function("hpke/base/open_1k", |b| {
        b.iter_batched(
            || {
                setup_base_receiver(
                    kem,
                    suite,
                    key_pair.private_key_seed.as_bytes(),
                    &sender.encapsulated_key,
                    b"stage8e",
                )
                .unwrap()
            },
            |mut ctx| ctx.open(black_box(b"aad"), black_box(&ciphertext)).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });

    let export_ctx =
        setup_base_sender_deterministic(kem, suite, &key_pair.public_key, b"stage8e", &[0x22; 32])
            .unwrap()
            .context;
    c.bench_function("hpke/base/export_32", |b| {
        b.iter(|| {
            export_ctx
                .export(black_box(b"export-context"), black_box(32))
                .unwrap()
        })
    });
}

criterion_group!(benches, bench_hpke);
criterion_main!(benches);
