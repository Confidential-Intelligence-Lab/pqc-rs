// SPDX-License-Identifier: MIT
//! Differential SMAUG-T 1.1.1 KEM encapsulation validation.
//!
//! The C reference supplies independently generated test vectors.
//! The implementation under test is entirely native Rust.

use pqc_rs_smaug_t::kem;
use pqc_rs_smaug_t::{Parameters, SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER};
use std::fs;
use std::path::Path;

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "odd-length hex input");

    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("invalid UTF-8");
            u8::from_str_radix(text, 16).expect("invalid hex")
        })
        .collect()
}

fn fixed_32(input: &[u8], label: &str) -> [u8; 32] {
    input
        .try_into()
        .unwrap_or_else(|_| panic!("{label} must contain exactly 32 bytes"))
}

fn field<'a>(line: &'a str, prefix: &str) -> &'a str {
    line.strip_prefix(prefix)
        .unwrap_or_else(|| panic!("expected field {prefix}"))
}

fn check_mode(
    directory: &Path,
    mode: &str,
    parameters: Parameters,
    expected_ct_len: usize,
    expected_message_len: usize,
) -> (usize, usize) {
    let path = directory.join(format!("kem-encapsulation-{mode}.txt"));

    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

    let lines: Vec<_> = contents.lines().collect();

    assert_eq!(lines.len(), 24, "{mode}: expected four six-line cases");

    let mut cases = 0;
    let mut compared_bytes = 0;

    for chunk in lines.chunks_exact(6) {
        let case_id: usize = field(chunk[0], "CASE=").parse().expect("invalid case ID");

        assert_eq!(case_id, cases, "{mode}: unexpected case order");

        let seed = fixed_32(&decode_hex(field(chunk[1], "SEED=")), "seed");

        let d = fixed_32(&decode_hex(field(chunk[2], "D=")), "d");

        let message = decode_hex(field(chunk[3], "MU="));
        let reference_ct = decode_hex(field(chunk[4], "CT="));
        let reference_ss = decode_hex(field(chunk[5], "SS="));

        assert_eq!(
            message.len(),
            expected_message_len,
            "{mode} case {case_id}: message length"
        );

        assert_eq!(
            reference_ct.len(),
            expected_ct_len,
            "{mode} case {case_id}: ciphertext length"
        );

        assert_eq!(
            reference_ss.len(),
            32,
            "{mode} case {case_id}: shared-secret length"
        );

        let (public_key, _) =
            kem::keypair(&seed, &d, &parameters).expect("native Rust KEM keypair failed");

        let (rust_ct, rust_ss) = kem::encapsulate_deterministic(&public_key, &message, &parameters)
            .expect("native Rust encapsulation failed");

        assert_eq!(
            rust_ct, reference_ct,
            "{mode} case {case_id}: ciphertext mismatch"
        );

        assert_eq!(
            rust_ss.as_slice(),
            reference_ss.as_slice(),
            "{mode} case {case_id}: shared-secret mismatch"
        );

        compared_bytes += reference_ct.len() + reference_ss.len();
        cases += 1;
    }

    assert_eq!(cases, 4);

    println!(
        "KEM_ENCAPSULATION_PARITY_MODE={mode} CASES={cases} \
         COMPARED_BYTES={compared_bytes} MISMATCHES=0 STATUS=PASS"
    );

    (cases, compared_bytes)
}

#[test]
fn reference_kem_encapsulation_parity_all_modes() {
    let directory = std::env::var("SMAUGT_KEM_ENCAPSULATION_ORACLE")
        .expect("SMAUGT_KEM_ENCAPSULATION_ORACLE must be set");

    let directory = Path::new(&directory);
    assert!(directory.is_dir(), "oracle directory does not exist");

    let mut total_cases = 0;
    let mut total_bytes = 0;

    for (mode, parameters, ct_len, message_len) in [
        ("mode1", SMAUG_T128, 672, 32),
        ("mode3", SMAUG_T192, 992, 32),
        ("mode5", SMAUG_T256, 1376, 32),
        ("modet", TIMER, 608, 16),
    ] {
        let (cases, bytes) = check_mode(directory, mode, parameters, ct_len, message_len);

        total_cases += cases;
        total_bytes += bytes;
    }

    assert_eq!(total_cases, 16);
    assert_eq!(total_bytes, 15_104);

    println!(
        "S5_3B_3_KEM_ENCAPSULATION_PARITY=PASS \
         CASES={total_cases} COMPARED_BYTES={total_bytes} \
         MISMATCHES=0"
    );
}
