// SPDX-License-Identifier: MIT
//! Authenticated C/Rust complete-loop key-generation parity.

use pqc_haetae::keygen_loop::{generate_accepted_state, KeygenLoopError};
use pqc_haetae::params::ParameterSet;
use std::collections::BTreeMap;
use std::path::PathBuf;

const N: usize = 256;

struct Case {
    fields: BTreeMap<String, String>,
    polys: BTreeMap<(String, usize), Vec<i32>>,
}

fn fixture_path(mode: u8) -> PathBuf {
    let root = std::env::var_os("HAETAE_KEYGEN_COMPLETE_LOOP_PARITY_DIR")
        .expect("HAETAE_KEYGEN_COMPLETE_LOOP_PARITY_DIR must be set");
    PathBuf::from(root).join(format!("complete_loop_mode{mode}.txt"))
}

fn parse_fixture(mode: u8, k: usize, m: usize) -> Vec<Case> {
    let text = std::fs::read_to_string(fixture_path(mode))
        .expect("authenticated C fixture must be readable");

    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some(format!("HEADER K={k} M={m} N={N}").as_str())
    );

    let mut cases = Vec::new();

    while let Some(line) = lines.next() {
        assert!(line.starts_with("CASE="), "unexpected fixture line: {line}");

        let mut fields = BTreeMap::new();
        fields.insert("CASE".to_owned(), line[5..].to_owned());

        let mut polys = BTreeMap::new();
        let mut ended = false;

        for line in lines.by_ref() {
            if line == "END_CASE" {
                ended = true;
                break;
            }

            if let Some(rest) = line.strip_prefix("POLY=") {
                let parts: Vec<_> = rest.split_whitespace().collect();

                assert_eq!(parts.len(), N + 3);

                let kind = parts[0].to_owned();
                let row = parts[1]
                    .strip_prefix("ROW=")
                    .expect("ROW field")
                    .parse::<usize>()
                    .expect("row integer");

                assert_eq!(parts[2], "COL=0");

                let coefficients = parts[3..]
                    .iter()
                    .map(|value| value.parse::<i32>().expect("coefficient"))
                    .collect::<Vec<_>>();

                assert_eq!(coefficients.len(), N);
                assert!(
                    polys.insert((kind, row), coefficients).is_none(),
                    "duplicate polynomial"
                );
            } else {
                let (key, value) = line.split_once('=').expect("fixture scalar field");

                assert!(
                    fields.insert(key.to_owned(), value.to_owned()).is_none(),
                    "duplicate scalar field"
                );
            }
        }

        assert!(ended, "fixture case missing END_CASE");
        assert_eq!(polys.len(), m + 2 * k);

        cases.push(Case { fields, polys });
    }

    assert_eq!(cases.len(), 5);
    cases
}

fn field<'a>(case: &'a Case, name: &str) -> &'a str {
    case.fields
        .get(name)
        .unwrap_or_else(|| panic!("missing field {name}"))
}

fn number<T: std::str::FromStr>(case: &Case, name: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    field(case, name).parse().expect("numeric fixture field")
}

fn seed_bytes(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex byte"))
}

fn assert_vector(case: &Case, kind: &str, coefficients: &[pqc_haetae::poly::Poly]) -> usize {
    for (row, polynomial) in coefficients.iter().enumerate() {
        let expected = case
            .polys
            .get(&(kind.to_owned(), row))
            .unwrap_or_else(|| panic!("missing {kind} row {row}"));

        assert_eq!(
            polynomial.coeffs.as_slice(),
            expected.as_slice(),
            "{kind} row {row} differs"
        );
    }

    coefficients.len() * N
}

fn check<const K: usize, const M: usize>(mode_number: u8, mode: ParameterSet) {
    let cases = parse_fixture(mode_number, K, M);
    let mut total_coefficients = 0;

    for (index, case) in cases.iter().enumerate() {
        assert_eq!(number::<usize>(case, "CASE"), index);
        assert_eq!(number::<u8>(case, "REJECTED"), 0);

        let seed = seed_bytes(field(case, "SEED"));
        let attempts = number::<usize>(case, "ATTEMPTS");
        let nonce = number::<u16>(case, "NONCE");
        let squared = number::<i64>(case, "SQUARED_SINGULAR_VALUE");

        assert!(attempts > 0);

        let result = generate_accepted_state::<K, M>(&seed, mode, attempts)
            .expect("Rust must accept at authenticated reference attempt");

        assert_eq!(result.attempts, attempts);
        assert_eq!(result.sampling_nonce, nonce);
        assert_eq!(result.squared_singular_value, squared);

        assert_eq!(result.rhoprime, seed_bytes(field(case, "RHOPRIME")));
        assert_eq!(result.key, seed_bytes(field(case, "KEY")));

        total_coefficients += assert_vector(case, "S1", result.s1.as_slice());
        total_coefficients += assert_vector(case, "S2", result.s2.as_slice());
        total_coefficients += assert_vector(case, "B_PUBLIC", result.public_b.as_slice());

        if attempts > 1 {
            assert!(matches!(
                generate_accepted_state::<K, M>(&seed, mode, attempts - 1,),
                Err(KeygenLoopError::AttemptLimitReached)
            ));
        }

        println!(
            "MODE={mode_number} CASE={index} ATTEMPTS={attempts} \
             NONCE={nonce} SQUARED={squared} STATUS=PASS"
        );
    }

    assert_eq!(total_coefficients, 5 * (M + 2 * K) * N);

    println!(
        "MODE={mode_number} EXACT_COEFFICIENTS={total_coefficients} \
         STATUS=PASS"
    );
}

#[test]
fn authenticated_complete_loop_mode2() {
    check::<2, 3>(2, ParameterSet::Haetae2);
}

#[test]
fn authenticated_complete_loop_mode3() {
    check::<3, 5>(3, ParameterSet::Haetae3);
}

#[test]
fn authenticated_complete_loop_mode5() {
    check::<4, 6>(5, ParameterSet::Haetae5);
}
