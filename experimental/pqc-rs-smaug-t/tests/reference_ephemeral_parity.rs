//! Differential validation of SMAUG-T ExpandR against the pinned C reference.

use pqc_rs_smaug_t::{ephemeral::expand_r, Parameters, SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn seed_for(case: usize) -> [u8; 32] {
    let mut seed = [0u8; 32];

    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = match case {
            0 => 0,
            1 => 0xff,
            2 => i as u8,
            3 => {
                if i % 2 == 0 {
                    0xaa
                } else {
                    0x55
                }
            }
            _ => panic!("unsupported test case"),
        };
    }

    seed
}

fn validate_mode(mode: &str, parameters: Parameters, root: &Path) -> (usize, usize) {
    let path = root.join(format!("ephemeral-{mode}.txt"));
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

    let mut lines = content.lines();
    let mut compared = 0usize;
    let mut mismatches = 0usize;

    for case in 0..4 {
        let expected_header = format!("CASE={case}");
        let header = lines.next().expect("missing case header");
        assert_eq!(header, expected_header);

        let actual = expand_r(&seed_for(case), &parameters).expect("Rust ExpandR failed");

        assert_eq!(actual.len(), parameters.k);

        for (poly_index, actual_poly) in actual.iter().enumerate() {
            let line = lines.next().expect("missing polynomial record");
            let mut fields = line.split_whitespace();

            let expected_label = format!("POLY={poly_index}");
            assert_eq!(fields.next(), Some(expected_label.as_str()));

            let reference: Vec<i16> = fields
                .map(|value| value.parse::<i16>().expect("invalid C coefficient"))
                .collect();

            assert_eq!(reference.len(), 256);
            assert_eq!(actual_poly.len(), 256);

            for (index, (&expected, &observed)) in
                reference.iter().zip(actual_poly.iter()).enumerate()
            {
                compared += 1;

                if expected != observed {
                    mismatches += 1;

                    if mismatches <= 12 {
                        println!(
                            "S4_3B_5_MISMATCH MODE={mode} CASE={case} \
                             POLY={poly_index} INDEX={index} \
                             C={expected} RUST={observed}"
                        );
                    }
                }
            }
        }
    }

    assert!(lines.next().is_none(), "unexpected trailing oracle records");

    println!(
        "S4_3B_5_MODE={mode} COMPARED={compared} MISMATCHES={mismatches} \
         STATUS={}",
        if mismatches == 0 { "PASS" } else { "FAIL" }
    );

    (compared, mismatches)
}

#[test]
fn reference_expand_r_parity_all_modes() {
    let root = PathBuf::from(
        env::var("SMAUGT_EPHEMERAL_ORACLE")
            .expect("set SMAUGT_EPHEMERAL_ORACLE to the oracle output directory"),
    );

    let modes = [
        ("mode1", SMAUG_T128),
        ("mode3", SMAUG_T192),
        ("mode5", SMAUG_T256),
        ("modet", TIMER),
    ];

    let mut total_compared = 0usize;
    let mut total_mismatches = 0usize;

    for (mode, parameters) in modes {
        let (compared, mismatches) = validate_mode(mode, parameters, &root);
        total_compared += compared;
        total_mismatches += mismatches;
    }

    assert_eq!(total_compared, 11_264);

    println!(
        "S4_3B_5_EPHEMERAL_PARITY={} COEFFICIENTS={} MISMATCHES={}",
        if total_mismatches == 0 {
            "PASS"
        } else {
            "FAIL"
        },
        total_compared,
        total_mismatches
    );

    assert_eq!(
        total_mismatches, 0,
        "Rust ExpandR differs from the C reference"
    );
}
