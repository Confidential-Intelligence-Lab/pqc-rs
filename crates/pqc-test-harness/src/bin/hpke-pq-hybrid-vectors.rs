use pqc_hpke::hybrid_kem::HybridKem;
use pqc_hpke::hybrid_setup::{setup_hybrid_base_receiver, setup_hybrid_base_sender_deterministic};
use pqc_hpke::identifiers::{AeadId, HpkeSuiteId, KdfId, KemId};
use pqc_test_harness::hpke_pq_vectors::{decode_hex, load_vectors, HpkePqVector};
use std::path::PathBuf;

#[derive(Default)]
struct Results {
    suites: usize,
    checks: usize,
    passed: usize,
    failed: usize,
    first_failure: Option<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Hybrid HPKE vector execution failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let path = root.join("tests/vectors/hpke-pq/draft-ietf-hpke-pq-05-test-vectors.json");
    let vectors = load_vectors(path)?;
    let mut results = Results::default();

    for vector in vectors.iter().filter(is_supported_hybrid_base) {
        results.suites += 1;
        if let Err(error) = execute_suite(vector, &mut results) {
            if results.first_failure.is_none() {
                results.first_failure = Some(error);
            }
        }
    }

    println!("draft-ietf-hpke-pq-05 PQ/T hybrid Base vectors");
    println!("  suites: {}", results.suites);
    println!("  checks: {}", results.checks);
    println!("  passed: {}", results.passed);
    println!("  failed: {}", results.failed);

    if let Some(failure) = &results.first_failure {
        println!();
        println!("First mismatch:");
        println!("{failure}");
    }

    if results.suites != 3 || results.failed != 0 {
        std::process::exit(2);
    }

    Ok(())
}

fn is_supported_hybrid_base(vector: &&HpkePqVector) -> bool {
    vector.mode == 0
        && matches!(
            (vector.kem_id, vector.kdf_id, vector.aead_id),
            (0x0050, 0x0001, 0x0001) | (0x647a, 0x0001, 0x0003) | (0x0051, 0x0002, 0x0002)
        )
}

fn execute_suite(vector: &HpkePqVector, results: &mut Results) -> Result<(), String> {
    let kem = parse_kem(vector.kem_id)?;
    let suite = HpkeSuiteId {
        kem_id: KemId(vector.kem_id),
        kdf_id: KdfId(vector.kdf_id),
        aead_id: AeadId(vector.aead_id),
    };

    let ikm_r = decode_hex(&vector.ikm_r).map_err(|error| error.to_string())?;
    let ikm_e = decode_hex(&vector.ikm_e).map_err(|error| error.to_string())?;
    let info = decode_hex(&vector.info).map_err(|error| error.to_string())?;
    let expected_sk = decode_hex(&vector.sk_rm).map_err(|error| error.to_string())?;
    let expected_pk = decode_hex(&vector.pk_rm).map_err(|error| error.to_string())?;
    let expected_enc = decode_hex(&vector.enc).map_err(|error| error.to_string())?;
    let expected_shared = decode_hex(&vector.shared_secret).map_err(|error| error.to_string())?;

    let key_pair = kem
        .derive_key_pair(&ikm_r)
        .map_err(|error| error.to_string())?;
    check(
        results,
        vector,
        "recipient private key",
        key_pair.private_seed.as_bytes(),
        &expected_sk,
    )?;
    check(
        results,
        vector,
        "recipient public key",
        &key_pair.public_key,
        &expected_pk,
    )?;

    let kem_output = kem
        .encapsulate_deterministic(&key_pair.public_key, &ikm_e)
        .map_err(|error| error.to_string())?;
    check(
        results,
        vector,
        "enc",
        &kem_output.encapsulated_key,
        &expected_enc,
    )?;
    check(
        results,
        vector,
        "shared_secret",
        kem_output.shared_secret.as_bytes(),
        &expected_shared,
    )?;

    let sender =
        setup_hybrid_base_sender_deterministic(kem, suite, &key_pair.public_key, &info, &ikm_e)
            .map_err(|error| error.to_string())?;
    let mut sender_context = sender.context;
    let mut receiver_context = setup_hybrid_base_receiver(
        kem,
        suite,
        key_pair.private_seed.as_bytes(),
        &expected_enc,
        &info,
    )
    .map_err(|error| error.to_string())?;

    for encryption in &vector.encryptions {
        let aad = decode_hex(&encryption.aad).map_err(|error| error.to_string())?;
        let plaintext = decode_hex(&encryption.pt).map_err(|error| error.to_string())?;
        let expected_ct = decode_hex(&encryption.ct).map_err(|error| error.to_string())?;
        let ciphertext = sender_context
            .seal(&aad, &plaintext)
            .map_err(|error| error.to_string())?;
        check(results, vector, "ciphertext", &ciphertext, &expected_ct)?;
        let recovered = receiver_context
            .open(&aad, &ciphertext)
            .map_err(|error| error.to_string())?;
        check(results, vector, "plaintext", &recovered, &plaintext)?;
    }

    for export in &vector.exports {
        let context = decode_hex(&export.exporter_context).map_err(|error| error.to_string())?;
        let expected = decode_hex(&export.exported_value).map_err(|error| error.to_string())?;
        let sender_export = sender_context
            .export(&context, export.length)
            .map_err(|error| error.to_string())?;
        check(results, vector, "sender export", &sender_export, &expected)?;
        let receiver_export = receiver_context
            .export(&context, export.length)
            .map_err(|error| error.to_string())?;
        check(
            results,
            vector,
            "receiver export",
            &receiver_export,
            &expected,
        )?;
    }

    Ok(())
}

fn parse_kem(id: u16) -> Result<HybridKem, String> {
    match id {
        0x0050 => Ok(HybridKem::MlKem768P256),
        0x647a => Ok(HybridKem::MlKem768X25519),
        0x0051 => Ok(HybridKem::MlKem1024P384),
        other => Err(format!("unsupported hybrid KEM ID: {other:#06x}")),
    }
}

fn check(
    results: &mut Results,
    vector: &HpkePqVector,
    field: &str,
    actual: &[u8],
    expected: &[u8],
) -> Result<(), String> {
    results.checks += 1;
    if actual == expected {
        results.passed += 1;
        return Ok(());
    }

    results.failed += 1;
    let index = actual
        .iter()
        .zip(expected)
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| usize::min(actual.len(), expected.len()));
    Err(format!(
        "kem_id={:#06x}: {} mismatch at byte {} (actual len {}, expected len {})",
        vector.kem_id,
        field,
        index,
        actual.len(),
        expected.len(),
    ))
}
