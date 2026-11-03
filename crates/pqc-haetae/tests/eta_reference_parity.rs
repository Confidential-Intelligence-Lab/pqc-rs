#![cfg(feature = "internal-api")]
//! Byte-exact ETA packing parity against HAETAE 1.2.0 C fixtures.

use pqc_haetae::packing::{
    pack_poly2_eta, pack_poly_eta, unpack_poly2_eta, unpack_poly_eta, POLY2_ETA_PACKED_BYTES,
    POLY_ETA_PACKED_BYTES,
};
use pqc_haetae::params::N;
use pqc_haetae::poly::Poly;

use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn parse_fixture(path: &Path, mode: usize, kind: &str, case: usize) -> (Poly, Vec<u8>) {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("Cannot read {}: {error}", path.display()));

    let mut fields = HashMap::new();

    for line in contents.lines() {
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("Malformed fixture: {line}"));

        assert!(
            fields.insert(key, value).is_none(),
            "Duplicate fixture field: {key}"
        );
    }

    assert_eq!(fields.len(), 5, "Unexpected fixture fields");
    assert_eq!(fields["MODE"].parse::<usize>().unwrap(), mode);
    assert_eq!(fields["KIND"], kind);
    assert_eq!(fields["CASE"].parse::<usize>().unwrap(), case);

    let coefficients: Vec<i32> = fields["COEFFS"]
        .split(',')
        .map(|value| value.parse::<i32>().unwrap())
        .collect();

    assert_eq!(coefficients.len(), N);

    let array: [i32; N] = coefficients.try_into().unwrap();

    let hex = fields["ENCODED"];
    assert_eq!(hex.len() % 2, 0);

    let encoded: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();

    (Poly::new(array), encoded)
}

fn check_reference(mode: usize, kind: &str) {
    let directory = std::env::var("HAETAE_ETA_PACKING_PARITY_DIR")
        .expect("HAETAE_ETA_PACKING_PARITY_DIR is required");

    let root = Path::new(&directory);
    assert!(root.is_dir());

    let expected_length = match kind {
        "eta" => POLY_ETA_PACKED_BYTES,
        "two_eta" => POLY2_ETA_PACKED_BYTES,
        _ => panic!("Unsupported fixture kind: {kind}"),
    };

    let mut checked_bytes = 0_usize;
    let mut checked_coefficients = 0_usize;

    for case in 0..12 {
        let path = root.join(format!("mode{mode}_{kind}_case{case:02}.txt"));

        let (original, expected) = parse_fixture(&path, mode, kind, case);

        assert_eq!(expected.len(), expected_length);

        let actual = match kind {
            "eta" => pack_poly_eta(&original),
            "two_eta" => pack_poly2_eta(&original),
            _ => unreachable!(),
        }
        .unwrap_or_else(|error| {
            panic!(
                "Packing failed: mode={mode} kind={kind} \
                 case={case}: {error:?}"
            )
        });

        assert_eq!(
            actual, expected,
            "C/Rust byte mismatch: mode={mode} \
             kind={kind} case={case}"
        );

        let decoded = match kind {
            "eta" => unpack_poly_eta(&expected),
            "two_eta" => unpack_poly2_eta(&expected),
            _ => unreachable!(),
        }
        .unwrap_or_else(|error| {
            panic!(
                "Decoding failed: mode={mode} kind={kind} \
                 case={case}: {error:?}"
            )
        });

        assert_eq!(
            decoded, original,
            "C/Rust coefficient mismatch: mode={mode} \
             kind={kind} case={case}"
        );

        checked_bytes += expected.len();
        checked_coefficients += N;
    }

    assert_eq!(checked_bytes, 12 * expected_length);
    assert_eq!(checked_coefficients, 12 * N);

    println!(
        "MODE={mode} KIND={kind} CASES=12 \
         COEFFICIENTS={checked_coefficients} \
         BYTES={checked_bytes} STATUS=PASS"
    );
}

#[test]
fn haetae2_eta_parity() {
    check_reference(2, "eta");
}

#[test]
fn haetae2_two_eta_parity() {
    check_reference(2, "two_eta");
}

#[test]
fn haetae3_eta_parity() {
    check_reference(3, "eta");
}

#[test]
fn haetae3_two_eta_parity() {
    check_reference(3, "two_eta");
}

#[test]
fn haetae5_eta_parity() {
    check_reference(5, "eta");
}

#[test]
fn haetae5_two_eta_primitive_parity() {
    // Standalone C primitive only.
    // HAETAE-5 secret keys use poly_eta for s1.
    check_reference(5, "two_eta");
}
