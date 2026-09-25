use pqc_ml_dsa::{
    keygen::keygen_internal as dsa_keygen, signature::sign_internal as dsa_sign,
    verification::verify_internal as dsa_verify, MlDsaParameterSet,
};
use pqc_ml_kem::{
    ml_kem_decaps::decaps_internal, ml_kem_encaps::encaps_internal,
    ml_kem_keygen::ml_kem_768_keygen_internal, MlKemParameterSet,
};
use serde_json::json;
use std::hint::black_box;
use std::time::{Duration, Instant};

const SAMPLE_COUNT: usize = 100;
const TARGET_SAMPLE: Duration = Duration::from_millis(5);
const WARMUP: Duration = Duration::from_secs(3);

const MESSAGE: &[u8] = b"pqc-rfc9958-rs B1.3.5 performance baseline";
const CONTEXT: &[u8] = b"benchmark";

const KEM_D: [u8; 32] = [0x33; 32];
const KEM_Z: [u8; 32] = [0x44; 32];
const KEM_M: [u8; 32] = [0x77; 32];

const DSA_XI: [u8; 32] = [0x65; 32];
const DSA_RANDOMNESS: [u8; 32] = [0x00; 32];

struct Bench {
    kem_public_key: Vec<u8>,
    kem_private_key: Vec<u8>,
    kem_ciphertext: Vec<u8>,

    dsa_public_key: Vec<u8>,
    dsa_private_key: Vec<u8>,
    dsa_signature: Vec<u8>,

    sink: u8,
}

impl Bench {
    fn new() -> Self {
        let kem_keypair =
            ml_kem_768_keygen_internal(&KEM_D, &KEM_Z).expect("ML-KEM setup keygen failed");

        let kem_enc = encaps_internal(
            MlKemParameterSet::MlKem768,
            kem_keypair.encapsulation_key.as_ref(),
            &KEM_M,
        )
        .expect("ML-KEM setup encaps failed");

        let dsa_keypair =
            dsa_keygen(MlDsaParameterSet::MlDsa65, &DSA_XI).expect("ML-DSA setup keygen failed");

        let dsa_signature = dsa_sign(
            MlDsaParameterSet::MlDsa65,
            dsa_keypair.private_key(),
            MESSAGE,
            CONTEXT,
            &DSA_RANDOMNESS,
        )
        .expect("ML-DSA setup signing failed");

        let valid = dsa_verify(
            MlDsaParameterSet::MlDsa65,
            dsa_keypair.public_key(),
            MESSAGE,
            CONTEXT,
            &dsa_signature,
        )
        .expect("ML-DSA setup verify failed");

        assert!(valid);

        Self {
            kem_public_key: kem_keypair.encapsulation_key.to_vec(),
            kem_private_key: kem_keypair.decapsulation_key.to_vec(),
            kem_ciphertext: kem_enc.ciphertext.clone(),

            dsa_public_key: dsa_keypair.public_key().to_vec(),
            dsa_private_key: dsa_keypair.private_key().to_vec(),
            dsa_signature,

            sink: 0,
        }
    }

    fn kem_keygen(&mut self) {
        let out = ml_kem_768_keygen_internal(black_box(&KEM_D), black_box(&KEM_Z))
            .expect("ML-KEM keygen failed");

        self.sink ^= out.encapsulation_key[0];
        self.sink ^= out.decapsulation_key[0];
    }

    fn kem_encaps(&mut self) {
        let out = encaps_internal(
            MlKemParameterSet::MlKem768,
            black_box(&self.kem_public_key),
            black_box(&KEM_M),
        )
        .expect("ML-KEM encaps failed");

        self.sink ^= out.ciphertext[0];
        self.sink ^= out.shared_secret.as_bytes()[0];
    }

    fn kem_decaps(&mut self) {
        let out = decaps_internal(
            MlKemParameterSet::MlKem768,
            black_box(&self.kem_private_key),
            black_box(&self.kem_ciphertext),
        )
        .expect("ML-KEM decaps failed");

        self.sink ^= out.shared_secret.as_bytes()[0];
    }

    fn dsa_keygen(&mut self) {
        let out = dsa_keygen(MlDsaParameterSet::MlDsa65, black_box(&DSA_XI))
            .expect("ML-DSA keygen failed");

        self.sink ^= out.public_key()[0];
        self.sink ^= out.private_key()[0];
    }

    fn dsa_sign(&mut self) {
        let sig = dsa_sign(
            MlDsaParameterSet::MlDsa65,
            black_box(&self.dsa_private_key),
            black_box(MESSAGE),
            black_box(CONTEXT),
            black_box(&DSA_RANDOMNESS),
        )
        .expect("ML-DSA sign failed");

        self.sink ^= sig[0];
    }

    fn dsa_verify(&mut self) {
        let valid = dsa_verify(
            MlDsaParameterSet::MlDsa65,
            black_box(&self.dsa_public_key),
            black_box(MESSAGE),
            black_box(CONTEXT),
            black_box(&self.dsa_signature),
        )
        .expect("ML-DSA verify failed");

        assert!(valid);
        self.sink ^= 1;
    }
}

fn measure_iterations<F>(bench: &mut Bench, iterations: u64, mut op: F) -> Duration
where
    F: FnMut(&mut Bench),
{
    let start = Instant::now();

    for _ in 0..iterations {
        op(bench);
    }

    start.elapsed()
}

fn warm_up<F>(bench: &mut Bench, mut op: F)
where
    F: FnMut(&mut Bench),
{
    let start = Instant::now();

    while start.elapsed() < WARMUP {
        op(bench);
    }
}

fn calibrate<F>(bench: &mut Bench, mut op: F) -> u64
where
    F: FnMut(&mut Bench),
{
    let mut iterations = 1_u64;

    loop {
        let elapsed = measure_iterations(bench, iterations, &mut op);

        if elapsed >= TARGET_SAMPLE {
            return iterations;
        }

        iterations = iterations.checked_mul(2).expect("calibration overflow");
    }
}

fn benchmark<F>(primitive: &str, operation: &str, bench: &mut Bench, mut op: F)
where
    F: FnMut(&mut Bench),
{
    warm_up(bench, &mut op);

    let iterations = calibrate(bench, &mut op);

    let mut samples = Vec::with_capacity(SAMPLE_COUNT);

    for _ in 0..SAMPLE_COUNT {
        let elapsed = measure_iterations(bench, iterations, &mut op);

        let ns_per_op = elapsed.as_nanos() as f64 / iterations as f64;

        samples.push(ns_per_op);
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "provider": "pqc-rs",
            "primitive": primitive,
            "operation": operation,
            "samples": SAMPLE_COUNT,
            "iterations_per_sample": iterations,
            "sample_ns": samples,
            "sink": bench.sink,
        }))
        .unwrap()
    );
}

fn main() {
    let operation = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!(
            "usage: pqc-provider-bench \
                     {{kem-keygen|kem-encaps|kem-decaps|\
                     dsa-keygen|dsa-sign|dsa-verify}}"
        );
        std::process::exit(64);
    });

    let mut bench = Bench::new();

    match operation.as_str() {
        "kem-keygen" => benchmark("ML-KEM-768", "kem-keygen", &mut bench, Bench::kem_keygen),
        "kem-encaps" => benchmark("ML-KEM-768", "kem-encaps", &mut bench, Bench::kem_encaps),
        "kem-decaps" => benchmark("ML-KEM-768", "kem-decaps", &mut bench, Bench::kem_decaps),
        "dsa-keygen" => benchmark("ML-DSA-65", "dsa-keygen", &mut bench, Bench::dsa_keygen),
        "dsa-sign" => benchmark("ML-DSA-65", "dsa-sign", &mut bench, Bench::dsa_sign),
        "dsa-verify" => benchmark("ML-DSA-65", "dsa-verify", &mut bench, Bench::dsa_verify),
        _ => {
            eprintln!("unsupported operation: {operation}");
            std::process::exit(65);
        }
    }
}
