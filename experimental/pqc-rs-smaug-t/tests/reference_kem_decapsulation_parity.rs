// SPDX-License-Identifier: MIT
//! Independent SMAUG-T 1.1.1 KEM decapsulation parity.
//!
//! Requires SMAUGT_KEM_DECAPSULATION_ORACLE to identify the directory
//! containing the four independently generated C reference vectors.

use pqc_rs_smaug_t::kem;
use pqc_rs_smaug_t::{Parameters, SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER};
use std::fs;
use std::path::Path;

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "odd-length hexadecimal input");

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(text, 16).expect("valid hexadecimal")
        })
        .collect()
}

fn field<'a>(lines: &'a [&str], name: &str) -> &'a str {
    let prefix = format!("{name}=");
    let matches: Vec<_> = lines
        .iter()
        .filter_map(|line| line.strip_prefix(&prefix))
        .collect();

    assert_eq!(matches.len(), 1, "missing or duplicate field {name}");
    matches[0]
}

fn check_mode(
    directory: &Path,
    mode: &str,
    parameters: Parameters,
    expected_ciphertext_bytes: usize,
) -> usize {
    let path = directory.join(format!("kem-decapsulation-{mode}.txt"));
    let content =
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));

    let lines: Vec<_> = content.lines().collect();
    assert_eq!(lines.len(), 4 * 7, "unexpected oracle record count");

    let mut compared_bytes = 0usize;

    for (case_id, record) in lines.chunks_exact(7).enumerate() {
        assert_eq!(
            field(record, "CASE"),
            case_id.to_string(),
            "unexpected case identifier"
        );

        let seed = decode_hex(field(record, "SEED"));
        let d = decode_hex(field(record, "D"));
        let mu = decode_hex(field(record, "MU"));
        let ciphertext = decode_hex(field(record, "CT"));
        let reference_valid = decode_hex(field(record, "SS_VALID"));
        let reference_reject = decode_hex(field(record, "SS_REJECT"));

        assert_eq!(seed.len(), 32);
        assert_eq!(d.len(), 32);
        assert_eq!(mu.len(), if parameters == TIMER { 16 } else { 32 });
        assert_eq!(ciphertext.len(), expected_ciphertext_bytes);
        assert_eq!(reference_valid.len(), 32);
        assert_eq!(reference_reject.len(), 32);

        let seed: [u8; 32] = seed.try_into().expect("seed length");
        let d: [u8; 32] = d.try_into().expect("auxiliary secret length");

        let (public_key, secret_key) =
            kem::keypair(&seed, &d, &parameters).expect("native key generation");

        // Verify that the C reference ciphertext is also produced
        // by native Rust encapsulation.
        let (rust_ciphertext, rust_encapsulated_secret) =
            kem::encapsulate_deterministic(&public_key, &mu, &parameters)
                .expect("native encapsulation");

        assert_eq!(
            rust_ciphertext, ciphertext,
            "encapsulation ciphertext mismatch: {mode} case {case_id}"
        );

        assert_eq!(
            rust_encapsulated_secret.as_slice(),
            reference_valid.as_slice(),
            "encapsulation secret mismatch: {mode} case {case_id}"
        );

        let rust_valid = kem::decapsulate(&ciphertext, &secret_key, &parameters)
            .expect("native valid decapsulation");

        assert_eq!(
            rust_valid.as_slice(),
            reference_valid.as_slice(),
            "valid decapsulation mismatch: {mode} case {case_id}"
        );

        compared_bytes += 32;

        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0x01;

        let rust_reject = kem::decapsulate(&tampered, &secret_key, &parameters)
            .expect("native implicit rejection");

        assert_eq!(
            rust_reject.as_slice(),
            reference_reject.as_slice(),
            "implicit rejection mismatch: {mode} case {case_id}"
        );

        compared_bytes += 32;
    }

    assert_eq!(compared_bytes, 256);

    println!(
        "KEM_DECAPSULATION_PARITY_MODE={mode} \
         CASES=8 COMPARED_BYTES={compared_bytes} \
         MISMATCHES=0 STATUS=PASS"
    );

    compared_bytes
}

#[test]
fn reference_kem_decapsulation_parity_all_modes() {
    let directory = std::env::var("SMAUGT_KEM_DECAPSULATION_ORACLE")
        .expect("SMAUGT_KEM_DECAPSULATION_ORACLE must be set");

    let directory = Path::new(&directory);
    assert!(directory.is_dir(), "reference oracle directory missing");

    let mut compared_bytes = 0usize;

    for (mode, parameters, ciphertext_bytes) in [
        ("mode1", SMAUG_T128, 672),
        ("mode3", SMAUG_T192, 992),
        ("mode5", SMAUG_T256, 1376),
        ("modet", TIMER, 608),
    ] {
        compared_bytes += check_mode(directory, mode, parameters, ciphertext_bytes);
    }

    assert_eq!(compared_bytes, 1024);

    println!(
        "S5_4C_3_KEM_DECAPSULATION_PARITY=PASS \
         CASES=32 COMPARED_BYTES={compared_bytes} MISMATCHES=0"
    );
}
