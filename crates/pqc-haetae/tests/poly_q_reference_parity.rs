//! Byte-exact parity with HAETAE 1.2.0 reference C poly_q packing.
//!
//! Fixtures are generated independently by the authenticated C reference.

use pqc_haetae::packing::{pack_poly_q, poly_q_packed_bytes, unpack_poly_q};
use pqc_haetae::params::{ParameterSet, N};
use pqc_haetae::poly::Poly;

use std::fs;
use std::path::Path;

fn parse_fixture(path: &Path, expected_mode: usize, expected_case: usize) -> (Poly, Vec<u8>) {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

    let mut mode = None;
    let mut case = None;
    let mut coefficients = None;
    let mut encoded = None;

    for line in contents.lines() {
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("malformed fixture line: {line}"));

        match key {
            "MODE" => {
                mode = Some(value.parse::<usize>().unwrap());
            }
            "CASE" => {
                case = Some(value.parse::<usize>().unwrap());
            }
            "COEFFS" => {
                let values: Vec<i32> = value
                    .split(',')
                    .map(|part| part.parse::<i32>().unwrap())
                    .collect();

                assert_eq!(values.len(), N);

                let array: [i32; N] = values.try_into().unwrap();
                coefficients = Some(Poly::new(array));
            }
            "ENCODED" => {
                assert_eq!(value.len() % 2, 0);

                let bytes: Vec<u8> = value
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| {
                        let text = std::str::from_utf8(pair).unwrap();
                        u8::from_str_radix(text, 16).unwrap()
                    })
                    .collect();

                encoded = Some(bytes);
            }
            _ => panic!("unknown fixture field: {key}"),
        }
    }

    assert_eq!(mode, Some(expected_mode));
    assert_eq!(case, Some(expected_case));

    (
        coefficients.expect("missing COEFFS"),
        encoded.expect("missing ENCODED"),
    )
}

fn check_mode(mode_number: usize, mode: ParameterSet) {
    let directory = std::env::var("HAETAE_POLY_Q_PARITY_DIR")
        .expect("HAETAE_POLY_Q_PARITY_DIR must identify C fixtures");

    let root = Path::new(&directory);
    assert!(root.is_dir());

    let mut checked_coefficients = 0_usize;
    let mut checked_bytes = 0_usize;

    for case in 0..12 {
        let path = root.join(format!("mode{mode_number}_case{case:02}.txt"));

        let (original, expected) = parse_fixture(&path, mode_number, case);

        assert_eq!(expected.len(), poly_q_packed_bytes(mode));

        let actual = pack_poly_q(&original, mode).unwrap_or_else(|error| {
            panic!(
                "Rust packing failed for mode {mode_number}, \
                     case {case}: {error:?}"
            )
        });

        assert_eq!(
            actual, expected,
            "C/Rust encoding mismatch: mode {mode_number}, case {case}"
        );

        let decoded = unpack_poly_q(&expected, mode).unwrap_or_else(|error| {
            panic!(
                "Rust decoding failed for mode {mode_number}, \
                     case {case}: {error:?}"
            )
        });

        assert_eq!(
            decoded, original,
            "C/Rust decoding mismatch: mode {mode_number}, case {case}"
        );

        checked_coefficients += N;
        checked_bytes += expected.len();
    }

    assert_eq!(checked_coefficients, 12 * N);

    println!(
        "MODE={mode_number} CASES=12 COEFFICIENTS={} BYTES={} STATUS=PASS",
        checked_coefficients, checked_bytes
    );
}

#[test]
fn haetae2_poly_q_reference_parity() {
    check_mode(2, ParameterSet::Haetae2);
}

#[test]
fn haetae3_poly_q_reference_parity() {
    check_mode(3, ParameterSet::Haetae3);
}

#[test]
fn haetae5_poly_q_reference_parity() {
    check_mode(5, ParameterSet::Haetae5);
}
