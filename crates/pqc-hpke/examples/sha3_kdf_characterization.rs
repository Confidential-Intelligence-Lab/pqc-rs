#[cfg(not(all(feature = "experimental-hkdf-sha3", feature = "internal-api")))]
fn main() {
    eprintln!("Requires experimental-hkdf-sha3 and internal-api");
}

#[cfg(all(feature = "experimental-hkdf-sha3", feature = "internal-api"))]
mod benchmark {
    use std::hint::black_box;
    use std::time::Instant;

    use pqc_hpke::internal_api::kdf::KdfAlgorithm;

    use pqc_hpke::internal_api::key_schedule::{
        key_schedule, AeadParameters, HpkeMode, KeyScheduleInputs,
    };

    use pqc_hpke::hybrid_kem::HybridKem;

    use pqc_hpke::hybrid_setup::{setup_hybrid_base_receiver, setup_hybrid_base_sender};

    use pqc_hpke::setup::{setup_base_receiver_with_suite, setup_base_sender_with_suite};

    use pqc_hpke::{AeadId, HpkeSuite, HpkeSuiteId, KdfId, KemId, MlKemHpke};

    use rand_core::OsRng;

    const WARMUP: usize = 200;
    const SAMPLES: usize = 10_000;

    const INFO: &[u8] = b"pqc-rs/kdf-characterization/v1";

    const AAD: &[u8] = b"benchmark-associated-data";

    const MESSAGE: &[u8] = &[0x21, 0x43, 0x65, 0x87, 0x09];

    const SHA2: KdfAlgorithm = KdfAlgorithm::HkdfSha256;

    const SHA3: KdfAlgorithm = KdfAlgorithm::HkdfSha3_256;

    const AEAD: AeadId = AeadId::AES_256_GCM;

    type Row = (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        usize,
        u128,
    );

    fn label(kdf: KdfAlgorithm) -> &'static str {
        match kdf {
            KdfAlgorithm::HkdfSha256 => "SHA256",
            KdfAlgorithm::HkdfSha3_256 => "SHA3-256",
            _ => unreachable!(),
        }
    }

    fn order(index: usize) -> [KdfAlgorithm; 2] {
        if index % 2 == 0 {
            [SHA2, SHA3]
        } else {
            [SHA3, SHA2]
        }
    }

    fn suite_id(kem_id: KemId, kdf: KdfAlgorithm) -> HpkeSuiteId {
        HpkeSuiteId {
            kem_id,
            kdf_id: kdf.id(),
            aead_id: AEAD,
        }
    }

    fn kdf_benchmark(rows: &mut Vec<Row>) {
        let salt = [0x31u8; 32];
        let ikm = [0x52u8; 32];

        let context = [0x73u8; 65];

        for index in 0..WARMUP + SAMPLES {
            for kdf in order(index) {
                let suite = suite_id(KemId(0x0041), kdf).to_bytes();

                let start = Instant::now();

                let prk = black_box(kdf.labeled_extract(
                    black_box(&suite),
                    black_box(&salt),
                    b"secret",
                    black_box(&ikm),
                ));

                let extract_ns = start.elapsed().as_nanos();

                let start = Instant::now();

                let output = black_box(
                    kdf.labeled_expand(
                        black_box(&suite),
                        black_box(&prk),
                        b"key",
                        black_box(&context),
                        32,
                    )
                    .unwrap(),
                );

                let expand_ns = start.elapsed().as_nanos();

                assert_eq!(prk.len(), 32);
                assert_eq!(output.len(), 32);

                if index >= WARMUP {
                    let trial = index - WARMUP;

                    rows.push(("KDF", "none", label(kdf), "extract", trial, extract_ns));

                    rows.push(("KDF", "none", label(kdf), "expand", trial, expand_ns));
                }
            }
        }

        eprintln!("KDF_BENCHMARK=PASS");
    }

    fn schedule_benchmark(rows: &mut Vec<Row>) {
        let shared = [0x42u8; 32];

        let parameters = AeadParameters::for_id(AEAD).unwrap();

        for index in 0..WARMUP + SAMPLES {
            for kdf in order(index) {
                let suite = suite_id(KemId(0x0041), kdf);

                let start = Instant::now();

                let output = black_box(
                    key_schedule(
                        black_box(suite),
                        kdf,
                        parameters,
                        KeyScheduleInputs {
                            mode: HpkeMode::Base,
                            shared_secret: black_box(&shared),
                            info: black_box(INFO),
                            psk: b"",
                            psk_id: b"",
                        },
                    )
                    .unwrap(),
                );

                let elapsed = start.elapsed().as_nanos();

                assert_eq!(output.key.as_bytes().len(), 32);

                assert_eq!(output.base_nonce.len(), 12);

                assert_eq!(output.exporter_secret.as_bytes().len(), 32);

                if index >= WARMUP {
                    rows.push((
                        "SCHEDULE",
                        "synthetic-shared-secret",
                        label(kdf),
                        "base_schedule",
                        index - WARMUP,
                        elapsed,
                    ));
                }
            }
        }

        eprintln!("KEY_SCHEDULE_BENCHMARK=PASS");
    }

    fn pure_benchmark(rows: &mut Vec<Row>, kem: MlKemHpke, name: &'static str) {
        // Recipient key generation is outside
        // every measured interval.

        let keys = kem.derive_key_pair(&[0x43u8; 64]).unwrap();

        let sha2_suite = HpkeSuite::new(kem, KdfId::HKDF_SHA256, AEAD).unwrap();

        let sha3_suite = HpkeSuite::new(kem, KdfId::EXPERIMENTAL_HKDF_SHA3_256, AEAD).unwrap();

        let mut rng = OsRng;

        for index in 0..WARMUP + SAMPLES {
            for kdf in order(index) {
                let suite = if kdf == SHA2 { sha2_suite } else { sha3_suite };

                let start = Instant::now();

                let sender = setup_base_sender_with_suite(
                    kem,
                    suite,
                    black_box(&keys.public_key),
                    black_box(INFO),
                    &mut rng,
                )
                .unwrap();

                let sender_setup_ns = start.elapsed().as_nanos();

                let mut context = sender.context;

                let start = Instant::now();

                let ciphertext =
                    black_box(context.seal(black_box(AAD), black_box(MESSAGE)).unwrap());

                let seal_ns = start.elapsed().as_nanos();

                let start = Instant::now();

                let mut receiver = setup_base_receiver_with_suite(
                    kem,
                    suite,
                    keys.private_key_seed.as_bytes(),
                    black_box(&sender.encapsulated_key),
                    black_box(INFO),
                )
                .unwrap();

                let receiver_setup_ns = start.elapsed().as_nanos();

                let start = Instant::now();

                let plaintext = black_box(
                    receiver
                        .open(black_box(AAD), black_box(&ciphertext))
                        .unwrap(),
                );

                let open_ns = start.elapsed().as_nanos();

                assert_eq!(plaintext, MESSAGE);
                assert_eq!(ciphertext.len(), MESSAGE.len() + 16);

                if index >= WARMUP {
                    let trial = index - WARMUP;

                    for (operation, elapsed) in [
                        ("sender_setup", sender_setup_ns),
                        ("seal", seal_ns),
                        ("receiver_setup", receiver_setup_ns),
                        ("open", open_ns),
                        ("sender_total", sender_setup_ns + seal_ns),
                        ("receiver_total", receiver_setup_ns + open_ns),
                        (
                            "combined_total",
                            sender_setup_ns + seal_ns + receiver_setup_ns + open_ns,
                        ),
                    ] {
                        rows.push(("HPKE", name, label(kdf), operation, trial, elapsed));
                    }
                }
            }
        }

        eprintln!("PURE_HPKE_BENCHMARK=PASS {name}");
    }

    fn hybrid_benchmark(rows: &mut Vec<Row>, kem: HybridKem, name: &'static str) {
        let keys = kem.derive_key_pair(&[0x54u8; 32]).unwrap();

        let mut rng = OsRng;

        for index in 0..WARMUP + SAMPLES {
            for kdf in order(index) {
                let suite = suite_id(kem.kem_id(), kdf);

                let start = Instant::now();

                let sender = setup_hybrid_base_sender(
                    kem,
                    suite,
                    black_box(&keys.public_key),
                    black_box(INFO),
                    &mut rng,
                )
                .unwrap();

                let sender_setup_ns = start.elapsed().as_nanos();

                let mut context = sender.context;

                let start = Instant::now();

                let ciphertext =
                    black_box(context.seal(black_box(AAD), black_box(MESSAGE)).unwrap());

                let seal_ns = start.elapsed().as_nanos();

                let start = Instant::now();

                let mut receiver = setup_hybrid_base_receiver(
                    kem,
                    suite,
                    keys.private_seed.as_bytes(),
                    black_box(&sender.encapsulated_key),
                    black_box(INFO),
                )
                .unwrap();

                let receiver_setup_ns = start.elapsed().as_nanos();

                let start = Instant::now();

                let plaintext = black_box(
                    receiver
                        .open(black_box(AAD), black_box(&ciphertext))
                        .unwrap(),
                );

                let open_ns = start.elapsed().as_nanos();

                assert_eq!(plaintext, MESSAGE);

                assert_eq!(sender.encapsulated_key.len(), kem.encapsulation_length());

                assert_eq!(ciphertext.len(), MESSAGE.len() + 16);

                if index >= WARMUP {
                    let trial = index - WARMUP;

                    for (operation, elapsed) in [
                        ("sender_setup", sender_setup_ns),
                        ("seal", seal_ns),
                        ("receiver_setup", receiver_setup_ns),
                        ("open", open_ns),
                        ("sender_total", sender_setup_ns + seal_ns),
                        ("receiver_total", receiver_setup_ns + open_ns),
                        (
                            "combined_total",
                            sender_setup_ns + seal_ns + receiver_setup_ns + open_ns,
                        ),
                    ] {
                        rows.push(("HPKE", name, label(kdf), operation, trial, elapsed));
                    }
                }
            }
        }

        eprintln!("HYBRID_HPKE_BENCHMARK=PASS {name}");
    }

    pub fn run() {
        let mut rows = Vec::with_capacity(900_000);

        kdf_benchmark(&mut rows);
        schedule_benchmark(&mut rows);

        for (kem, name) in [
            (MlKemHpke::MlKem512, "ML-KEM-512"),
            (MlKemHpke::MlKem768, "ML-KEM-768"),
            (MlKemHpke::MlKem1024, "ML-KEM-1024"),
        ] {
            pure_benchmark(&mut rows, kem, name);
        }

        for (kem, name) in [
            (HybridKem::MlKem768X25519, "ML-KEM-768+X25519"),
            (HybridKem::MlKem768P256, "ML-KEM-768+P256"),
            (HybridKem::MlKem1024P384, "ML-KEM-1024+P384"),
        ] {
            hybrid_benchmark(&mut rows, kem, name);
        }

        assert_eq!(rows.len(), 900_000);

        println!("level,kem,kdf,operation,trial,latency_ns");

        for (level, kem, kdf, operation, trial, ns) in rows {
            println!(
                "{level},{kem},{kdf},\
                 {operation},{trial},{ns}"
            );
        }

        eprintln!("MEASUREMENT_ROWS=900000");
        eprintln!("MEASURED_HPKE_ROUNDTRIPS=120000");
        eprintln!("BENCHMARK_STATUS=PASS");
    }
}

#[cfg(all(feature = "experimental-hkdf-sha3", feature = "internal-api"))]
fn main() {
    benchmark::run();
}
