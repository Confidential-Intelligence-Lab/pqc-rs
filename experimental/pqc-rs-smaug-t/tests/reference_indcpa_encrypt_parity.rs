// SPDX-License-Identifier: MIT
//! Byte-exact SMAUG-T IND-CPA encryption differential tests.
//! Requires the independently compiled C reference oracle.

use pqc_rs_smaug_t::indcpa::{encrypt, keypair};
use pqc_rs_smaug_t::{Parameters, SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER};
use std::fs;
use std::path::Path;

fn pattern(length: usize, case: usize, domain: u8) -> Vec<u8> {
    (0..length)
        .map(|i| {
            let value = match case {
                0 => 0,
                1 => 0xff,
                2 => i as u8,
                3 => {
                    if i & 1 == 1 {
                        0x55
                    } else {
                        0xaa
                    }
                }
                _ => panic!("invalid case"),
            };
            value ^ domain
        })
        .collect()
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "odd hexadecimal length");

    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex UTF-8");
            u8::from_str_radix(text, 16).expect("valid hex")
        })
        .collect()
}

fn assert_exact(label: &str, mode: &str, case: usize, actual: &[u8], expected: &[u8]) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "{mode} case={case} {label} length mismatch"
    );

    if let Some((index, (&found, &wanted))) = actual
        .iter()
        .zip(expected)
        .enumerate()
        .find(|(_, (a, b))| a != b)
    {
        panic!(
            "{mode} case={case} {label} mismatch at byte {index}: \
             Rust={found:02x} C={wanted:02x}; total_bytes={}",
            actual.len()
        );
    }
}

fn check_mode(
    root: &Path,
    mode: &str,
    parameters: &Parameters,
    message_len: usize,
    pk_len: usize,
    ct_len: usize,
) -> usize {
    let file = root.join(format!("encrypt-{mode}.txt"));
    let content =
        fs::read_to_string(&file).unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));

    let lines: Vec<_> = content.lines().collect();
    assert_eq!(lines.len(), 12, "{mode}: unexpected oracle record count");

    let mut compared = 0;

    for case in 0..4 {
        let base = 3 * case;

        assert_eq!(lines[base], format!("CASE={case}"));

        let expected_pk = decode_hex(lines[base + 1].strip_prefix("PK=").expect("PK record"));

        let expected_ct = decode_hex(lines[base + 2].strip_prefix("CT=").expect("CT record"));

        assert_eq!(expected_pk.len(), pk_len);
        assert_eq!(expected_ct.len(), ct_len);

        let key_seed: [u8; 32] = pattern(32, case, 0x11)
            .try_into()
            .expect("32-byte key seed");

        let encryption_seed: [u8; 32] = pattern(32, case, 0x5a)
            .try_into()
            .expect("32-byte encryption seed");

        let message = pattern(message_len, case, 0);

        let (rust_pk, rust_sk) = keypair(&key_seed, parameters).expect("Rust keypair");

        assert_eq!(rust_sk.len(), parameters.k * 64);

        assert_exact("PK", mode, case, &rust_pk, &expected_pk);

        // Use the independently generated C public key as input.
        // This isolates encryption parity from key-generation parity.
        let rust_ct =
            encrypt(&expected_pk, &message, &encryption_seed, parameters).expect("Rust encryption");

        assert_exact("CT", mode, case, &rust_ct, &expected_ct);

        compared += rust_ct.len();

        println!(
            "S4_4C_2_MODE={mode} CASE={case} \
             PK=PASS CT=PASS CT_BYTES={}",
            rust_ct.len()
        );
    }

    println!(
        "S4_4C_2_MODE={mode} CASES=4 \
         CT_BYTES={compared} MISMATCHES=0 STATUS=PASS"
    );

    compared
}

#[test]
fn reference_indcpa_encrypt_parity_all_modes() {
    let root = match std::env::var("SMAUGT_ENCRYPT_ORACLE") {
        Ok(value) => value,
        Err(_) => {
            eprintln!(
                "S4_4C_2_SKIPPED: set SMAUGT_ENCRYPT_ORACLE \
                 to execute reference parity"
            );
            return;
        }
    };

    let root = Path::new(&root);
    assert!(root.is_dir(), "oracle directory does not exist");

    let total = [
        ("mode1", SMAUG_T128, 32, 672, 672),
        ("mode3", SMAUG_T192, 32, 1088, 992),
        ("mode5", SMAUG_T256, 32, 1440, 1376),
        ("modet", TIMER, 16, 672, 608),
    ]
    .iter()
    .map(|(mode, parameters, message_len, pk_len, ct_len)| {
        check_mode(root, mode, parameters, *message_len, *pk_len, *ct_len)
    })
    .sum::<usize>();

    assert_eq!(total, 14_592);

    println!(
        "S4_4C_2_ENCRYPT_PARITY=PASS \
         CASES=16 CIPHERTEXT_BYTES={total} MISMATCHES=0"
    );
}
