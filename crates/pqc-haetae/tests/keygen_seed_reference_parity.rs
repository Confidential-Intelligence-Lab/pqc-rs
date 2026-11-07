#![cfg(feature = "internal-api")]
// SPDX-License-Identifier: MIT

use pqc_haetae::keygen_seed::expand_keygen_seed;
use std::{fs, path::PathBuf};

fn decode_hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2, "unexpected hexadecimal length");

    let mut output = [0_u8; N];

    for (index, byte) in output.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&text[start..start + 2], 16)
            .expect("invalid reference hexadecimal byte");
    }

    output
}

#[test]
fn authenticated_keygen_seed_reference_parity() {
    let fixture_dir = std::env::var_os("HAETAE_KEYGEN_SEED_PARITY_DIR")
        .expect("HAETAE_KEYGEN_SEED_PARITY_DIR must be set");

    let path = PathBuf::from(fixture_dir).join("seed_vectors.txt");
    let contents = fs::read_to_string(&path).expect("cannot read authenticated C seed fixtures");

    let lines: Vec<_> = contents.lines().collect();
    assert_eq!(lines.len(), 5, "expected exactly five reference vectors");

    let mut compared = 0_usize;

    for (expected_pattern, line) in lines.iter().enumerate() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "invalid reference fixture");

        assert_eq!(
            fields[0],
            format!("PATTERN={expected_pattern}"),
            "unexpected fixture pattern"
        );

        let seed_hex = fields[1].strip_prefix("SEED=").expect("missing SEED field");

        let output_hex = fields[2]
            .strip_prefix("OUTPUT=")
            .expect("missing OUTPUT field");

        let seed = decode_hex::<32>(seed_hex);
        let reference = decode_hex::<128>(output_hex);

        let derived = expand_keygen_seed(&seed);

        assert_eq!(
            derived.rhoprime.as_slice(),
            &reference[..32],
            "rhoprime mismatch for pattern {expected_pattern}"
        );

        assert_eq!(
            derived.sigma.as_slice(),
            &reference[32..96],
            "sigma mismatch for pattern {expected_pattern}"
        );

        assert_eq!(
            derived.key.as_slice(),
            &reference[96..128],
            "key mismatch for pattern {expected_pattern}"
        );

        compared += reference.len();

        println!(
            "PATTERN={expected_pattern} EXACT_BYTES={} STATUS=PASS",
            reference.len()
        );
    }

    assert_eq!(compared, 640);

    println!("HAETAE_KEYGEN_SEED_DIFFERENTIAL=PASS TOTAL_EXACT_BYTES={compared}");
}
