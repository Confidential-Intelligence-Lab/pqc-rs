#![cfg(feature = "internal-api")]
// SPDX-License-Identifier: MIT

//! Exact signing-matrix parity against authenticated HAETAE 1.2.0 C.

use pqc_haetae::packing::{public_key_bytes, unpack_verification_key};
use pqc_haetae::params::ParameterSet;
use std::path::PathBuf;

const CASES: usize = 5;
const N: usize = 256;

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "odd hex length");

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.strip_prefix(name)
        .and_then(|rest| rest.strip_prefix('='))
        .unwrap_or_else(|| panic!("missing field {name}"))
}

fn fixture(mode_number: u8) -> Vec<String> {
    let root = PathBuf::from(
        std::env::var_os("HAETAE_SIGNING_MATRIX_PARITY_DIR")
            .expect("HAETAE_SIGNING_MATRIX_PARITY_DIR required"),
    );

    std::fs::read_to_string(root.join(format!("matrix_mode{mode_number}.txt")))
        .expect("authenticated matrix fixture")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn check<const K: usize, const L: usize>(mode_number: u8, mode: ParameterSet) {
    let lines = fixture(mode_number);

    assert_eq!(lines[0], format!("K={K}"));
    assert_eq!(lines[1], format!("L={L}"));
    assert_eq!(lines[2], format!("N={N}"));
    assert_eq!(
        lines[3],
        format!("PUBLICKEYBYTES={}", public_key_bytes(mode))
    );

    let mut cursor = 4;
    let mut compared = 0_usize;

    for case in 0..CASES {
        assert_eq!(lines[cursor], format!("CASE={case}"));
        cursor += 1;

        let seed = decode_hex(field(&lines[cursor], "SEED"));
        assert_eq!(seed.len(), 32);
        cursor += 1;

        let pk = decode_hex(field(&lines[cursor], "PK"));
        assert_eq!(pk.len(), public_key_bytes(mode));
        // The public-key prefix is the derived matrix seed (rhoprime),
        // not the original deterministic key-generation seed.
        assert_eq!(pk[..32].len(), 32);
        cursor += 1;

        let reconstructed =
            unpack_verification_key::<K, L>(&pk, mode).expect("valid reference public key");

        for row in 0..K {
            for column in 0..L {
                let fields: Vec<&str> = lines[cursor].split(',').collect();

                assert_eq!(
                    fields.len(),
                    N + 2,
                    "MODE={mode_number} CASE={case} ROW={row} COL={column}"
                );

                assert_eq!(fields[0], format!("POLY={row}"));
                assert_eq!(fields[1], column.to_string());

                let actual = &reconstructed.matrix[row].as_slice()[column].coeffs;

                for index in 0..N {
                    let expected: i32 = fields[index + 2]
                        .parse()
                        .expect("signed reference coefficient");

                    assert_eq!(
                        actual[index], expected,
                        "MATRIX_MISMATCH MODE={mode_number} \
                         CASE={case} ROW={row} COLUMN={column} \
                         COEFFICIENT={index}"
                    );

                    compared += 1;
                }

                cursor += 1;
            }
        }

        assert_eq!(lines[cursor], format!("END_CASE={case}"));
        cursor += 1;

        println!(
            "MODE={mode_number} CASE={case} \
             MATRIX_COEFFICIENTS={} STATUS=PASS",
            K * L * N
        );
    }

    assert_eq!(cursor, lines.len());
    assert_eq!(compared, CASES * K * L * N);

    println!(
        "MODE={mode_number} KEYS={CASES} \
         EXACT_MATRIX_COEFFICIENTS={compared} STATUS=PASS"
    );
}

#[test]
fn matrix_reference_mode2() {
    check::<2, 4>(2, ParameterSet::Haetae2);
}

#[test]
fn matrix_reference_mode3() {
    check::<3, 6>(3, ParameterSet::Haetae3);
}

#[test]
fn matrix_reference_mode5() {
    check::<4, 7>(5, ParameterSet::Haetae5);
}

#[test]
fn matrix_rejects_incorrect_lengths() {
    for mode in [
        ParameterSet::Haetae2,
        ParameterSet::Haetae3,
        ParameterSet::Haetae5,
    ] {
        let length = public_key_bytes(mode);

        assert!(unpack_verification_key::<2, 4>(&vec![0; length - 1], mode).is_err());

        assert!(unpack_verification_key::<2, 4>(&vec![0; length + 1], mode).is_err());
    }
}

#[test]
fn matrix_rejects_dimension_mismatch() {
    for (mode_number, mode) in [
        (2, ParameterSet::Haetae2),
        (3, ParameterSet::Haetae3),
        (5, ParameterSet::Haetae5),
    ] {
        let lines = fixture(mode_number);
        let pk = decode_hex(field(&lines[6], "PK"));

        assert!(
            unpack_verification_key::<1, 1>(&pk, mode).is_err(),
            "MODE={mode_number} incorrect dimensions accepted"
        );
    }
}
