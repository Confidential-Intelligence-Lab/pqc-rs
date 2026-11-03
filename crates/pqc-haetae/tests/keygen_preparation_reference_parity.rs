// SPDX-License-Identifier: MIT

//! Differential verification against authenticated HAETAE 1.2.0 C fixtures.

use pqc_haetae::keygen_prepare::prepare_first_attempt;
use pqc_haetae::params::{ParameterSet, N};
use std::{fs, path::PathBuf};

fn decode_hex<const LEN: usize>(text: &str) -> [u8; LEN] {
    assert_eq!(text.len(), LEN * 2, "unexpected hexadecimal length");

    let mut output = [0_u8; LEN];

    for (index, byte) in output.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&text[start..start + 2], 16)
            .expect("invalid reference hexadecimal byte");
    }

    output
}

struct FixtureReader<'a> {
    lines: std::str::Lines<'a>,
    mode: ParameterSet,
    pattern: usize,
    compared_coefficients: usize,
    compared_seed_bytes: usize,
}

impl<'a> FixtureReader<'a> {
    fn new(contents: &'a str, mode: ParameterSet) -> Self {
        Self {
            lines: contents.lines(),
            mode,
            pattern: 0,
            compared_coefficients: 0,
            compared_seed_bytes: 0,
        }
    }

    fn next(&mut self) -> &'a str {
        self.lines.next().expect("truncated authenticated fixture")
    }

    fn expect(&mut self, expected: &str) {
        assert_eq!(
            self.next(),
            expected,
            "fixture structure mismatch: {:?}, pattern {}",
            self.mode,
            self.pattern
        );
    }

    fn bytes<const LEN: usize>(&mut self, name: &str) -> [u8; LEN] {
        let line = self.next();
        let value = line
            .strip_prefix(name)
            .and_then(|value| value.strip_prefix('='))
            .expect("invalid fixture byte field");
        decode_hex::<LEN>(value)
    }

    fn poly(&mut self, kind: &str, row: usize, col: usize, actual: &[i32; N]) {
        let line = self.next();
        let mut fields = line.split_whitespace();

        assert_eq!(fields.next(), Some(format!("POLY={kind}").as_str()));
        assert_eq!(fields.next(), Some(format!("ROW={row}").as_str()));
        assert_eq!(fields.next(), Some(format!("COL={col}").as_str()));

        for (index, value) in actual.iter().enumerate() {
            let expected: i32 = fields
                .next()
                .expect("missing authenticated polynomial coefficient")
                .parse()
                .expect("invalid authenticated polynomial coefficient");

            assert_eq!(
                *value, expected,
                "coefficient mismatch: {:?}, pattern {}, \
                 {kind}[{row}][{col}], coefficient {index}",
                self.mode, self.pattern
            );

            self.compared_coefficients += 1;
        }

        assert!(
            fields.next().is_none(),
            "extra authenticated polynomial coefficients"
        );
    }
}

fn check_mode<const K: usize, const M: usize>(
    mode: ParameterSet,
    mode_number: usize,
) -> (usize, usize) {
    let directory = std::env::var_os("HAETAE_KEYGEN_PREPARATION_PARITY_DIR")
        .expect("HAETAE_KEYGEN_PREPARATION_PARITY_DIR must be set");

    let path = PathBuf::from(directory).join(format!("preparation_mode{mode_number}.txt"));

    let contents =
        fs::read_to_string(path).expect("cannot read authenticated C preparation fixture");

    let mut fixture = FixtureReader::new(&contents, mode);
    fixture.expect(&format!("HEADER K={K} M={M} N={N}"));

    for pattern in 0..5 {
        fixture.pattern = pattern;
        fixture.expect(&format!("CASE={pattern}"));

        let seed = fixture.bytes::<32>("SEED");
        let expected_rhoprime = fixture.bytes::<32>("RHOPRIME");
        let expected_sigma = fixture.bytes::<64>("SIGMA");
        let expected_key = fixture.bytes::<32>("KEY");

        let prepared = prepare_first_attempt::<K, M>(&seed, mode);

        assert_eq!(
            prepared.rhoprime, expected_rhoprime,
            "rhoprime mismatch: {mode:?}, pattern {pattern}"
        );
        assert_eq!(
            prepared.sigma, expected_sigma,
            "sigma mismatch: {mode:?}, pattern {pattern}"
        );
        assert_eq!(
            prepared.key, expected_key,
            "key mismatch: {mode:?}, pattern {pattern}"
        );

        fixture.compared_seed_bytes += 128;

        for row in 0..K {
            for col in 0..M {
                fixture.poly("A", row, col, &prepared.matrix[row].as_slice()[col].coeffs);
            }
        }

        match mode {
            ParameterSet::Haetae2 | ParameterSet::Haetae3 => {
                let public = prepared
                    .public_vector
                    .as_ref()
                    .expect("missing public vector");

                for row in 0..K {
                    fixture.poly("PUBLIC", row, 0, &public.as_slice()[row].coeffs);
                }
            }
            ParameterSet::Haetae5 => {
                assert!(
                    prepared.public_vector.is_none(),
                    "HAETAE-5 must not expand the public vector"
                );
            }
        }

        for col in 0..M {
            fixture.poly("S1", 0, col, &prepared.s1.as_slice()[col].coeffs);
        }

        for row in 0..K {
            fixture.poly("S2", row, 0, &prepared.s2.as_slice()[row].coeffs);
        }

        fixture.expect(&format!("INITIAL_NONCE=0 NEXT_NONCE={}", K + M));
        fixture.expect("END_CASE");
    }

    assert!(
        fixture.lines.next().is_none(),
        "unexpected trailing authenticated fixture data"
    );

    let expected_coefficients = 5 * (K * M + M + K + if mode_number == 5 { 0 } else { K }) * N;

    assert_eq!(fixture.compared_coefficients, expected_coefficients);
    assert_eq!(fixture.compared_seed_bytes, 5 * 128);

    println!(
        "MODE={mode_number} CASES=5 EXACT_COEFFICIENTS={} \
         EXACT_DERIVED_SEED_BYTES={} STATUS=PASS",
        fixture.compared_coefficients, fixture.compared_seed_bytes
    );

    (fixture.compared_coefficients, fixture.compared_seed_bytes)
}

#[test]
fn authenticated_keygen_preparation_reference_parity() {
    let results = [
        check_mode::<2, 3>(ParameterSet::Haetae2, 2),
        check_mode::<3, 5>(ParameterSet::Haetae3, 3),
        check_mode::<4, 6>(ParameterSet::Haetae5, 5),
    ];

    let coefficients: usize = results.iter().map(|result| result.0).sum();
    let seed_bytes: usize = results.iter().map(|result| result.1).sum();

    assert_eq!(coefficients, 93_440);
    assert_eq!(seed_bytes, 1_920);

    println!(
        "HAETAE_KEYGEN_PREPARATION_DIFFERENTIAL=PASS \
         TOTAL_EXACT_COEFFICIENTS={coefficients} \
         TOTAL_EXACT_DERIVED_SEED_BYTES={seed_bytes}"
    );
}
