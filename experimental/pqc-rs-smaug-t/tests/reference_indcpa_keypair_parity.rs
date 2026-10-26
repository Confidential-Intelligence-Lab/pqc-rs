// SPDX-License-Identifier: MIT
//! Byte-exact deterministic SMAUG-T IND-CPA keypair parity.

use pqc_rs_smaug_t::{indcpa::keypair, Parameters, SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER};
use std::{env, process::Command};

fn seed_for_case(case: usize) -> [u8; 32] {
    let mut seed = [0u8; 32];

    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = match case {
            0 => 0,
            1 => 0xff,
            2 => i as u8,
            3 => {
                if i & 1 == 0 {
                    0xaa
                } else {
                    0x55
                }
            }
            _ => panic!("unsupported case"),
        };
    }

    seed
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "odd hexadecimal length");

    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("invalid UTF-8");
            u8::from_str_radix(pair, 16).expect("invalid hexadecimal")
        })
        .collect()
}

fn compare_bytes(mode: &str, case: usize, kind: &str, expected: &[u8], actual: &[u8]) -> bool {
    let mismatches = expected
        .iter()
        .zip(actual.iter())
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .collect::<Vec<_>>();

    if expected.len() != actual.len() || !mismatches.is_empty() {
        eprintln!(
            "S4_3A_6_MISMATCH MODE={mode} CASE={case} \
             KIND={kind} EXPECTED_LEN={} ACTUAL_LEN={} \
             MISMATCH_COUNT={}",
            expected.len(),
            actual.len(),
            mismatches.len()
        );

        for (index, (reference, rust)) in mismatches.iter().take(16) {
            eprintln!("  OFFSET={index} C={reference:02x} RUST={rust:02x}");
        }

        return false;
    }

    println!(
        "S4_3A_6_MATCH MODE={mode} CASE={case} \
         KIND={kind} BYTES={}",
        expected.len()
    );
    true
}

fn verify_mode(mode: &str, parameters: Parameters) -> bool {
    let prefix = env::var("SMAUGT_KEYPAIR_ORACLE")
        .expect("SMAUGT_KEYPAIR_ORACLE must identify oracle executable prefix");

    let executable = format!("{prefix}-{mode}");

    let output = Command::new(&executable)
        .output()
        .unwrap_or_else(|error| panic!("cannot execute {executable}: {error}"));

    assert!(
        output.status.success(),
        "reference oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("non-UTF8 oracle output");

    let mut lines = stdout.lines();
    let mut all_match = true;

    for case in 0..4 {
        let expected_case = format!("CASE={case}");
        assert_eq!(lines.next(), Some(expected_case.as_str()));

        let pk_line = lines.next().expect("missing PK");
        let sk_line = lines.next().expect("missing SK");

        let reference_pk = decode_hex(pk_line.strip_prefix("PK=").expect("invalid PK record"));
        let reference_sk = decode_hex(sk_line.strip_prefix("SK=").expect("invalid SK record"));

        let (rust_pk, rust_sk) = keypair(&seed_for_case(case), &parameters).unwrap();

        let pk_match = compare_bytes(mode, case, "PK", &reference_pk, &rust_pk);
        let sk_match = compare_bytes(mode, case, "SK", &reference_sk, &rust_sk);

        all_match &= pk_match && sk_match;
    }

    assert!(lines.next().is_none(), "unexpected oracle records");
    all_match
}

#[test]
fn reference_indcpa_keypair_parity() {
    if env::var_os("SMAUGT_KEYPAIR_ORACLE").is_none() {
        eprintln!("S4_3A_6_SKIPPED: SMAUGT_KEYPAIR_ORACLE not configured");
        return;
    }

    let results = [
        ("mode1", verify_mode("mode1", SMAUG_T128)),
        ("mode3", verify_mode("mode3", SMAUG_T192)),
        ("mode5", verify_mode("mode5", SMAUG_T256)),
        ("modet", verify_mode("modet", TIMER)),
    ];

    for (mode, passed) in results {
        println!(
            "S4_3A_7_MODE={mode} STATUS={}",
            if passed { "PASS" } else { "FAIL" }
        );
    }

    assert!(
        results.iter().all(|(_, passed)| *passed),
        "S4_3A_7_KEYPAIR_PARITY=FAIL"
    );

    println!("S4_3A_7_KEYPAIR_PARITY=PASS KEYPAIRS=16");
}
