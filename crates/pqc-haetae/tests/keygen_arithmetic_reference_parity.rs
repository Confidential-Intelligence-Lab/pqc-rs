#![cfg(feature = "internal-api")]
// SPDX-License-Identifier: MIT

//! Authenticated HAETAE-2/3 first-attempt arithmetic differential tests.

use pqc_haetae::keygen_arithmetic::rounded_first_attempt;
use pqc_haetae::keygen_prepare::prepare_first_attempt;
use pqc_haetae::params::{ParameterSet, N};
use pqc_haetae::polymat::pointwise_montgomery;
use std::{fs, path::PathBuf};

fn decode_seed(text: &str) -> [u8; 32] {
    let hex = text.strip_prefix("SEED=").expect("missing seed field");
    assert_eq!(hex.len(), 64);

    let mut seed = [0_u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("invalid seed hexadecimal");
    }
    seed
}

struct Reader<'a> {
    lines: std::str::Lines<'a>,
    mode: usize,
    pattern: usize,
    compared: usize,
}

impl<'a> Reader<'a> {
    fn new(text: &'a str, mode: usize) -> Self {
        Self {
            lines: text.lines(),
            mode,
            pattern: 0,
            compared: 0,
        }
    }

    fn next(&mut self) -> &'a str {
        self.lines.next().expect("truncated C arithmetic fixture")
    }

    fn expect(&mut self, value: &str) {
        assert_eq!(
            self.next(),
            value,
            "fixture structure mismatch: mode {}, pattern {}",
            self.mode,
            self.pattern
        );
    }

    fn poly(&mut self, kind: &str, row: usize, actual: &[i32; N]) {
        let line = self.next();
        let mut fields = line.split_whitespace();

        assert_eq!(fields.next(), Some(format!("POLY={kind}").as_str()));
        assert_eq!(fields.next(), Some(format!("ROW={row}").as_str()));
        assert_eq!(fields.next(), Some("COL=0"));

        for (index, coefficient) in actual.iter().enumerate() {
            let expected: i32 = fields
                .next()
                .expect("missing C reference coefficient")
                .parse()
                .expect("invalid C reference coefficient");

            assert_eq!(
                *coefficient, expected,
                "arithmetic mismatch: mode {}, pattern {}, \
                 {kind}[{row}], coefficient {index}",
                self.mode, self.pattern
            );

            self.compared += 1;
        }

        assert!(
            fields.next().is_none(),
            "unexpected extra C reference coefficients"
        );
    }

    fn scalar_i64(&mut self, name: &str) -> i64 {
        let line = self.next();
        line.strip_prefix(name)
            .and_then(|s| s.strip_prefix('='))
            .expect("missing scalar fixture field")
            .parse()
            .expect("invalid scalar fixture value")
    }
}

fn check_mode<const K: usize, const M: usize>(
    mode: ParameterSet,
    mode_number: usize,
) -> (usize, usize, usize) {
    let directory = std::env::var_os("HAETAE_KEYGEN_ARITHMETIC_PARITY_DIR")
        .expect("HAETAE_KEYGEN_ARITHMETIC_PARITY_DIR must be set");

    let path = PathBuf::from(directory).join(format!("arithmetic_mode{mode_number}.txt"));

    let contents = fs::read_to_string(path).expect("cannot read authenticated arithmetic fixture");

    let mut reader = Reader::new(&contents, mode_number);
    reader.expect(&format!("HEADER K={K} M={M} N={N}"));

    let mut compared_estimates = 0;
    let mut compared_decisions = 0;

    for pattern in 0..5 {
        reader.pattern = pattern;
        reader.expect(&format!("CASE={pattern}"));

        let seed = decode_seed(reader.next());
        let prepared = prepare_first_attempt::<K, M>(&seed, mode);

        let mut s1hat = prepared.s1.clone();
        s1hat.ntt();

        for col in 0..M {
            reader.poly("S1HAT", col, &s1hat.as_slice()[col].coeffs);
        }

        let mut product = pointwise_montgomery(&prepared.matrix, &s1hat, mode);

        for row in 0..K {
            reader.poly("B_PRODUCT", row, &product.as_slice()[row].coeffs);
        }

        product.invntt_tomont();
        product = product.add(&prepared.s2);
        product = product.add(
            prepared
                .public_vector
                .as_ref()
                .expect("missing HAETAE-2/3 public vector"),
        );
        product.freeze();

        for row in 0..K {
            reader.poly("B_PREDECOMPOSE", row, &product.as_slice()[row].coeffs);
        }

        let result = rounded_first_attempt(&prepared, mode);

        for row in 0..K {
            reader.poly("B_PUBLIC", row, &result.public_b.as_slice()[row].coeffs);
        }

        for row in 0..K {
            reader.poly("S2_UPDATED", row, &result.updated_s2.as_slice()[row].coeffs);
        }

        let expected_squared = reader.scalar_i64("SQUARED_SINGULAR_VALUE");

        assert_eq!(
            result.squared_singular_value, expected_squared,
            "singular-value mismatch: mode {mode_number}, pattern {pattern}"
        );
        compared_estimates += 1;

        let expected_rejected = reader.scalar_i64("REJECTED");
        assert!(expected_rejected == 0 || expected_rejected == 1);

        assert_eq!(
            result.rejected,
            expected_rejected == 1,
            "rejection mismatch: mode {mode_number}, pattern {pattern}"
        );
        compared_decisions += 1;

        reader.expect("END_CASE");
    }

    assert!(
        reader.lines.next().is_none(),
        "unexpected trailing arithmetic fixture data"
    );

    let expected_coefficients = 5 * (M + 4 * K) * N;
    assert_eq!(reader.compared, expected_coefficients);
    assert_eq!(compared_estimates, 5);
    assert_eq!(compared_decisions, 5);

    println!(
        "MODE={mode_number} CASES=5 EXACT_COEFFICIENTS={} \
         EXACT_ESTIMATES={compared_estimates} \
         EXACT_REJECTION_DECISIONS={compared_decisions} STATUS=PASS",
        reader.compared
    );

    (reader.compared, compared_estimates, compared_decisions)
}

#[test]
fn authenticated_keygen_arithmetic_reference_parity() {
    let results = [
        check_mode::<2, 3>(ParameterSet::Haetae2, 2),
        check_mode::<3, 5>(ParameterSet::Haetae3, 3),
    ];

    let coefficients: usize = results.iter().map(|r| r.0).sum();
    let estimates: usize = results.iter().map(|r| r.1).sum();
    let decisions: usize = results.iter().map(|r| r.2).sum();

    assert_eq!(coefficients, 35_840);
    assert_eq!(estimates, 10);
    assert_eq!(decisions, 10);

    println!(
        "HAETAE_KEYGEN_ARITHMETIC_DIFFERENTIAL=PASS \
         TOTAL_EXACT_COEFFICIENTS={coefficients} \
         TOTAL_EXACT_ESTIMATES={estimates} \
         TOTAL_EXACT_REJECTION_DECISIONS={decisions}"
    );
}
