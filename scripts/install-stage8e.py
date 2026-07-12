#!/usr/bin/env python3
from pathlib import Path
import textwrap

root = Path('.')
if not (root/'Cargo.toml').exists():
    raise SystemExit('Run from repository root')

# Root-level benches so they can access workspace crates directly.
(root/'benches').mkdir(exist_ok=True)

(root/'benches/ml_kem.rs').write_text(textwrap.dedent(r'''
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pqc_ml_kem::ml_kem_decaps::decaps_internal;
use pqc_ml_kem::ml_kem_encaps::encaps_internal;
use pqc_ml_kem::ml_kem_keygen::{
    ml_kem_1024_keygen_internal, ml_kem_512_keygen_internal,
    ml_kem_768_keygen_internal,
};
use pqc_ml_kem::MlKemParameterSet;

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_kem/keygen");
    group.bench_function("ML-KEM-512", |b| b.iter(|| ml_kem_512_keygen_internal(black_box(&[0x11; 32]), black_box(&[0x22; 32])).unwrap()));
    group.bench_function("ML-KEM-768", |b| b.iter(|| ml_kem_768_keygen_internal(black_box(&[0x33; 32]), black_box(&[0x44; 32])).unwrap()));
    group.bench_function("ML-KEM-1024", |b| b.iter(|| ml_kem_1024_keygen_internal(black_box(&[0x55; 32]), black_box(&[0x66; 32])).unwrap()));
    group.finish();
}

fn bench_encaps_decaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_kem/encaps_decaps");
    let cases = [
        {
            let p = ml_kem_512_keygen_internal(&[0x11; 32], &[0x22; 32]).unwrap();
            ("ML-KEM-512", MlKemParameterSet::MlKem512, p.encapsulation_key.to_vec(), p.decapsulation_key.to_vec())
        },
        {
            let p = ml_kem_768_keygen_internal(&[0x33; 32], &[0x44; 32]).unwrap();
            ("ML-KEM-768", MlKemParameterSet::MlKem768, p.encapsulation_key.to_vec(), p.decapsulation_key.to_vec())
        },
        {
            let p = ml_kem_1024_keygen_internal(&[0x55; 32], &[0x66; 32]).unwrap();
            ("ML-KEM-1024", MlKemParameterSet::MlKem1024, p.encapsulation_key.to_vec(), p.decapsulation_key.to_vec())
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
''').lstrip())

(root/'benches/hpke.rs').write_text(textwrap.dedent(r'''
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pqc_hpke::identifiers::{AeadId, HpkeSuiteId, KdfId};
use pqc_hpke::ml_kem::MlKemHpke;
use pqc_hpke::setup::{setup_base_receiver, setup_base_sender_deterministic};

fn bench_hpke(c: &mut Criterion) {
    let kem = MlKemHpke::MlKem768;
    let suite = HpkeSuiteId { kem_id: kem.kem_id(), kdf_id: KdfId::HKDF_SHA256, aead_id: AeadId::AES_128_GCM };
    let key_pair = kem.derive_key_pair(&[0x11; 64]).unwrap();

    c.bench_function("hpke/base/setup_sender", |b| b.iter(|| {
        setup_base_sender_deterministic(kem, suite, black_box(&key_pair.public_key), black_box(b"stage8e"), black_box(&[0x22; 32])).unwrap()
    }));

    let sender = setup_base_sender_deterministic(kem, suite, &key_pair.public_key, b"stage8e", &[0x22; 32]).unwrap();
    c.bench_function("hpke/base/setup_receiver", |b| b.iter(|| {
        setup_base_receiver(kem, suite, black_box(key_pair.private_key_seed.as_bytes()), black_box(&sender.encapsulated_key), black_box(b"stage8e")).unwrap()
    }));

    c.bench_function("hpke/base/seal_1k", |b| b.iter_batched(
        || setup_base_sender_deterministic(kem, suite, &key_pair.public_key, b"stage8e", &[0x22; 32]).unwrap().context,
        |mut ctx| ctx.seal(black_box(b"aad"), black_box(&[0xA5; 1024])).unwrap(),
        criterion::BatchSize::SmallInput,
    ));

    let mut sender_ctx = setup_base_sender_deterministic(kem, suite, &key_pair.public_key, b"stage8e", &[0x22; 32]).unwrap().context;
    let ciphertext = sender_ctx.seal(b"aad", &[0xA5; 1024]).unwrap();
    c.bench_function("hpke/base/open_1k", |b| b.iter_batched(
        || setup_base_receiver(kem, suite, key_pair.private_key_seed.as_bytes(), &sender.encapsulated_key, b"stage8e").unwrap(),
        |mut ctx| ctx.open(black_box(b"aad"), black_box(&ciphertext)).unwrap(),
        criterion::BatchSize::SmallInput,
    ));

    let export_ctx = setup_base_sender_deterministic(kem, suite, &key_pair.public_key, b"stage8e", &[0x22; 32]).unwrap().context;
    c.bench_function("hpke/base/export_32", |b| b.iter(|| export_ctx.export(black_box(b"export-context"), black_box(32)).unwrap()));
}

criterion_group!(benches, bench_hpke);
criterion_main!(benches);
''').lstrip())

(root/'benches/hybrid_hpke.rs').write_text(textwrap.dedent(r'''
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pqc_hpke::hybrid_kem::HybridKem;
use pqc_hpke::hybrid_setup::{setup_hybrid_base_receiver, setup_hybrid_base_sender_deterministic};
use pqc_hpke::identifiers::{AeadId, HpkeSuiteId, KdfId};

fn suite(kem: HybridKem) -> HpkeSuiteId {
    match kem {
        HybridKem::MlKem768P256 => HpkeSuiteId { kem_id: kem.kem_id(), kdf_id: KdfId::HKDF_SHA256, aead_id: AeadId::AES_128_GCM },
        HybridKem::MlKem768X25519 => HpkeSuiteId { kem_id: kem.kem_id(), kdf_id: KdfId::HKDF_SHA256, aead_id: AeadId::CHACHA20_POLY1305 },
        HybridKem::MlKem1024P384 => HpkeSuiteId { kem_id: kem.kem_id(), kdf_id: KdfId::HKDF_SHA384, aead_id: AeadId::AES_256_GCM },
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
        group.bench_with_input(BenchmarkId::new("setup_sender", name), &randomness, |b, coins| {
            b.iter(|| setup_hybrid_base_sender_deterministic(kem, suite, black_box(&key_pair.public_key), black_box(b"stage8e"), black_box(coins)).unwrap())
        });
        let sender = setup_hybrid_base_sender_deterministic(kem, suite, &key_pair.public_key, b"stage8e", &randomness).unwrap();
        group.bench_with_input(BenchmarkId::new("setup_receiver", name), &sender.encapsulated_key, |b, enc| {
            b.iter(|| setup_hybrid_base_receiver(kem, suite, black_box(key_pair.private_seed.as_bytes()), black_box(enc), black_box(b"stage8e")).unwrap())
        });
    }
    group.finish();
}

criterion_group!(benches, bench_hybrid);
criterion_main!(benches);
''').lstrip())

# Root manifest dependencies and benches.
manifest = root/'Cargo.toml'
text = manifest.read_text()
if 'criterion =' not in text:
    marker='[workspace.dependencies]'
    i=text.find(marker)
    if i<0: raise SystemExit('Missing [workspace.dependencies]')
    j=text.find('\n[', i+len(marker))
    if j<0: j=len(text)
    text=text[:j].rstrip()+'\ncriterion = { version = "0.5", features = ["html_reports"] }\n\n'+text[j:].lstrip('\n')
for dep in [
    'pqc-ml-kem = { path = "crates/pqc-ml-kem", version = "0.4.0" }',
    'pqc-hpke = { path = "crates/pqc-hpke", version = "0.4.0" }',
]:
    if dep.split('=')[0].strip()+' =' not in text:
        marker='[dev-dependencies]'
        if marker not in text:
            text += '\n[dev-dependencies]\n'
        i=text.find(marker); j=text.find('\n[', i+len(marker)); j=len(text) if j<0 else j
        text=text[:j].rstrip()+'\n'+dep+'\n\n'+text[j:].lstrip('\n')
if 'criterion = { workspace = true }' not in text:
    marker='[dev-dependencies]'; i=text.find(marker); j=text.find('\n[', i+len(marker)); j=len(text) if j<0 else j
    text=text[:j].rstrip()+'\ncriterion = { workspace = true }\n\n'+text[j:].lstrip('\n')
for name in ['ml_kem','hpke','hybrid_hpke']:
    block=f'[[bench]]\nname = "{name}"\nharness = false\n'
    if f'name = "{name}"' not in text:
        text += '\n'+block
manifest.write_text(text)
print('Stage 8E installed.')
