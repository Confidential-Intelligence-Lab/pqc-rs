// SPDX-License-Identifier: MIT
//! Differential KEM keypair validation against SMAUG-T 1.1.1.
//!
//! The C reference is used only to generate external test vectors.
//! The cryptographic implementation under test is entirely Rust.

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
    expected_pk_len: usize,
    expected_sk_len: usize,
) -> (usize, usize) {
    let path = directory.join(format!("kem-keypair-{mode}.txt"));

    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

    let lines: Vec<_> = contents.lines().collect();

    assert_eq!(lines.len(), 20, "{mode}: expected four five-line cases");

    let mut cases = 0;
    let mut compared_bytes = 0;

    for chunk in lines.chunks_exact(5) {
        let case_id: usize = field(chunk[0], "CASE=").parse().expect("invalid case ID");

        assert_eq!(case_id, cases, "{mode}: unexpected case order");

        let seed = fixed_32(&decode_hex(field(chunk[1], "SEED=")), "seed");

        let d = fixed_32(&decode_hex(field(chunk[2], "D=")), "d");

        let reference_pk = decode_hex(field(chunk[3], "PK="));
        let reference_sk = decode_hex(field(chunk[4], "SK="));

        assert_eq!(
            reference_pk.len(),
            expected_pk_len,
            "{mode} case {case_id}: reference public-key length"
        );

        assert_eq!(
            reference_sk.len(),
            expected_sk_len,
            "{mode} case {case_id}: reference secret-key length"
        );

        let (rust_pk, rust_sk) =
            kem::keypair(&seed, &d, &parameters).expect("Rust KEM key generation failed");

        assert_eq!(
            rust_pk, reference_pk,
            "{mode} case {case_id}: public-key mismatch"
        );

        assert_eq!(
            rust_sk, reference_sk,
            "{mode} case {case_id}: secret-key mismatch"
        );

        compared_bytes += reference_pk.len() + reference_sk.len();
        cases += 1;
    }

    assert_eq!(cases, 4);

    println!(
        "KEM_KEYPAIR_PARITY_MODE={mode} CASES={cases} \
         COMPARED_BYTES={compared_bytes} MISMATCHES=0 STATUS=PASS"
    );

    (cases, compared_bytes)
}

#[test]
fn reference_kem_keypair_parity_all_modes() {
    let directory =
        std::env::var("SMAUGT_KEM_KEYPAIR_ORACLE").expect("SMAUGT_KEM_KEYPAIR_ORACLE must be set");

    let directory = Path::new(&directory);

    assert!(directory.is_dir(), "oracle directory does not exist");

    let mut total_cases = 0;
    let mut total_bytes = 0;

    for (mode, parameters, pk_len, sk_len) in [
        ("mode1", SMAUG_T128, 672, 832),
        ("mode3", SMAUG_T192, 1088, 1312),
        ("mode5", SMAUG_T256, 1440, 1728),
        ("modet", TIMER, 672, 832),
    ] {
        let (cases, bytes) = check_mode(directory, mode, parameters, pk_len, sk_len);

        total_cases += cases;
        total_bytes += bytes;
    }

    assert_eq!(total_cases, 16);
    assert_eq!(total_bytes, 34_304);

    println!(
        "S5_2B_3_KEM_KEYPAIR_PARITY=PASS \
         CASES={total_cases} COMPARED_BYTES={total_bytes} \
         MISMATCHES=0"
    );
}
