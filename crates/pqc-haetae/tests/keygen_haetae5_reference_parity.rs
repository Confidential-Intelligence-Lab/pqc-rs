// SPDX-License-Identifier: MIT
//! Exact HAETAE-5 differential tests against authenticated C fixtures.

use pqc_haetae::keygen_arithmetic::unrounded_first_attempt;
use pqc_haetae::keygen_prepare::prepare_first_attempt;
use pqc_haetae::params::ParameterSet;
use pqc_haetae::polymat::pointwise_montgomery;
use pqc_haetae::polyvec::PolyVecM;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

const MODE: ParameterSet = ParameterSet::Haetae5;
const K: usize = 4;
const M: usize = 6;

fn fixture(name: &str) -> String {
    let root = std::env::var_os("HAETAE_KEYGEN_ARITHMETIC_PARITY_DIR")
        .expect("HAETAE_KEYGEN_ARITHMETIC_PARITY_DIR must be set");

    let path = PathBuf::from(root).join(name);

    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn decode_seed(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);

    std::array::from_fn(|index| {
        u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("invalid seed hex")
    })
}

fn scalar<'a>(line: &'a str, prefix: &str) -> &'a str {
    line.strip_prefix(prefix)
        .unwrap_or_else(|| panic!("expected {prefix}, got {line}"))
}

fn parse_cases(input: &str) -> Vec<BTreeMap<String, String>> {
    let mut lines = input.lines();

    assert_eq!(lines.next(), Some("HEADER K=4 M=6 N=256"));

    let mut cases = Vec::new();

    while let Some(first) = lines.next() {
        let mut fields: BTreeMap<String, String> = BTreeMap::new();

        let case_number = scalar(first, "CASE=")
            .parse::<usize>()
            .expect("invalid case index");

        assert_eq!(case_number, cases.len());

        fields.insert("CASE".into(), case_number.to_string());

        loop {
            let line = lines.next().expect("unterminated case");

            if line == "END_CASE" {
                break;
            }

            if line.starts_with("POLY=") {
                let count = fields.keys().filter(|key| key.starts_with("POLY_")).count();

                fields.insert(format!("POLY_{count:02}"), line.to_owned());
            } else {
                let (key, value) = line.split_once('=').expect("invalid fixture field");

                assert!(
                    fields.insert(key.to_owned(), value.to_owned()).is_none(),
                    "duplicate fixture field"
                );
            }
        }

        cases.push(fields);
    }

    assert_eq!(cases.len(), 5);
    cases
}

fn field<'a>(case: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    case.get(key)
        .unwrap_or_else(|| panic!("missing fixture field {key}"))
}

fn compare_polynomials(
    case: &BTreeMap<String, String>,
    kind: &str,
    polynomials: &[pqc_haetae::poly::Poly],
    offset: &mut usize,
) -> usize {
    let mut compared = 0;

    for (row, poly) in polynomials.iter().enumerate() {
        let key = format!("POLY_{:02}", *offset);
        let line = field(case, &key);
        *offset += 1;

        let mut words = line.split_whitespace();

        assert_eq!(words.next(), Some(format!("POLY={kind}").as_str()));
        assert_eq!(words.next(), Some(format!("ROW={row}").as_str()));
        assert_eq!(words.next(), Some("COL=0"));

        for (index, actual) in poly.coeffs.iter().enumerate() {
            let expected = words
                .next()
                .expect("missing reference coefficient")
                .parse::<i32>()
                .expect("invalid reference coefficient");

            assert_eq!(
                *actual,
                expected,
                "C/Rust mismatch: case={} kind={kind} row={row} coefficient={index}",
                field(case, "CASE")
            );

            compared += 1;
        }

        assert!(words.next().is_none(), "extra reference coefficients");
    }

    compared
}

#[test]
fn authenticated_haetae5_rejected_first_attempts() {
    let cases = parse_cases(&fixture("arithmetic_mode5.txt"));

    for case in &cases {
        let seed = decode_seed(field(case, "SEED"));
        let prepared = prepare_first_attempt::<K, M>(&seed, MODE);
        let result = unrounded_first_attempt(&prepared, MODE);

        let expected_squared = field(case, "SQUARED_SINGULAR_VALUE")
            .parse::<i64>()
            .expect("invalid singular-value estimate");

        assert_eq!(result.squared_singular_value, expected_squared);
        assert_eq!(field(case, "REJECTED"), "1");
        assert!(result.rejected);
        assert!(result.public_b.is_none());

        assert!(
            !case.keys().any(|key| key.starts_with("POLY_")),
            "rejected C attempt must not produce arithmetic checkpoints"
        );

        println!(
            "HAETAE5_REJECTED_CASE={} SQUARED={} STATUS=PASS",
            field(case, "CASE"),
            expected_squared
        );
    }
}

#[test]
fn authenticated_haetae5_accepted_arithmetic() {
    let cases = parse_cases(&fixture("arithmetic_mode5_accepted.txt"));
    let expected_nonces = [100_u16, 200, 50, 90, 110];

    let mut total_compared = 0_usize;

    for (index, case) in cases.iter().enumerate() {
        let seed = decode_seed(field(case, "SEED"));
        let nonce = field(case, "NONCE").parse::<u16>().expect("invalid nonce");

        let attempts = field(case, "ATTEMPTS")
            .parse::<usize>()
            .expect("invalid attempt count");

        assert_eq!(nonce, expected_nonces[index]);
        assert_eq!(usize::from(nonce), (attempts - 1) * (M + K));
        assert_eq!(field(case, "REJECTED"), "0");

        let mut prepared = prepare_first_attempt::<K, M>(&seed, MODE);

        let (s1, s2) = PolyVecM::<M>::expand_s_with_k::<K>(&prepared.sigma, nonce, MODE);

        prepared.s1 = s1;
        prepared.s2 = s2;

        let result = unrounded_first_attempt(&prepared, MODE);

        let expected_squared = field(case, "SQUARED_SINGULAR_VALUE")
            .parse::<i64>()
            .expect("invalid singular-value estimate");

        assert_eq!(result.squared_singular_value, expected_squared);
        assert!(!result.rejected);

        let public_b = result
            .public_b
            .expect("accepted HAETAE-5 attempt must produce public B");

        let mut s1hat = prepared.s1.clone();
        let mut s2hat = prepared.s2.clone();

        s1hat.ntt();
        s2hat.ntt();

        let mut offset = 0_usize;
        let mut compared = 0_usize;

        compared += compare_polynomials(case, "S1HAT", s1hat.as_slice(), &mut offset);

        compared += compare_polynomials(case, "S2HAT", s2hat.as_slice(), &mut offset);

        let mut intermediate = pointwise_montgomery(&prepared.matrix, &s1hat, MODE);

        compared += compare_polynomials(case, "B_PRODUCT", intermediate.as_slice(), &mut offset);

        intermediate.frommont();
        intermediate = intermediate.add(&s2hat);

        compared +=
            compare_polynomials(case, "B_INTERMEDIATE", intermediate.as_slice(), &mut offset);

        compared += compare_polynomials(case, "B_PUBLIC", public_b.as_slice(), &mut offset);

        assert_eq!(offset, 22);
        assert_eq!(compared, 5632);

        total_compared += compared;

        println!(
            "HAETAE5_ACCEPTED_CASE={} NONCE={} COEFFICIENTS={} STATUS=PASS",
            index, nonce, compared
        );
    }

    assert_eq!(total_compared, 28_160);

    println!("HAETAE5_EXACT_REFERENCE_COEFFICIENTS={total_compared}");
}
