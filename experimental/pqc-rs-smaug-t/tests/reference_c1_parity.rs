//! Differential validation of SMAUG-T computeC1 against the pinned C reference.

use pqc_rs_smaug_t::{
    ciphertext::compute_c1, ephemeral::expand_r, matrix::expand_matrix, Parameters, SMAUG_T128,
    SMAUG_T192, SMAUG_T256, TIMER,
};
use std::{env, fs, path::Path};

fn seed_for(case: usize, domain: u8) -> [u8; 32] {
    assert!(case < 4);

    let mut seed = [0u8; 32];

    for (index, byte) in seed.iter_mut().enumerate() {
        let value = match case {
            0 => 0,
            1 => 0xff,
            2 => index as u8,
            3 => {
                if index % 2 == 0 {
                    0xaa
                } else {
                    0x55
                }
            }
            _ => unreachable!(),
        };

        *byte = value ^ domain;
    }

    seed
}

fn validate_mode(mode: &str, parameters: Parameters, root: &Path) -> (usize, usize) {
    let path = root.join(format!("c1-{mode}.txt"));

    let content = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

    let mut lines = content.lines();
    let mut compared = 0usize;
    let mut mismatches = 0usize;

    for case in 0..4 {
        let header = lines.next().expect("missing C1 case header");
        assert_eq!(header, format!("CASE={case}"));

        let matrix_seed = seed_for(case, 0x00);
        let ephemeral_seed = seed_for(case, 0x5a);

        let matrix = expand_matrix(&matrix_seed, &parameters);

        let ephemeral = expand_r(&ephemeral_seed, &parameters).expect("Rust ExpandR failed");

        let actual = compute_c1(&matrix, &ephemeral, &parameters).expect("Rust computeC1 failed");

        assert_eq!(actual.len(), parameters.k);

        for (poly_index, actual_poly) in actual.iter().enumerate() {
            let line = lines.next().expect("missing C1 polynomial record");
            let mut fields = line.split_whitespace();

            let expected_label = format!("POLY={poly_index}");
            assert_eq!(fields.next(), Some(expected_label.as_str()));

            let reference: Vec<u16> = fields
                .map(|value| value.parse::<u16>().expect("invalid C1 coefficient"))
                .collect();

            assert_eq!(reference.len(), 256);

            for (index, (&expected, &observed)) in reference
                .iter()
                .zip(actual_poly.coefficients.iter())
                .enumerate()
            {
                assert!(
                    expected < parameters.p,
                    "noncanonical C coefficient: mode={mode} \
                     case={case} poly={poly_index} index={index} \
                     value={expected}"
                );

                assert!(
                    observed < parameters.p,
                    "noncanonical Rust coefficient: mode={mode} \
                     case={case} poly={poly_index} index={index} \
                     value={observed}"
                );

                compared += 1;

                if expected != observed {
                    mismatches += 1;

                    if mismatches <= 12 {
                        println!(
                            "S4_3C_4_MISMATCH MODE={mode} CASE={case} \
                             POLY={poly_index} INDEX={index} \
                             C={expected} RUST={observed}"
                        );
                    }
                }
            }
        }
    }

    assert!(
        lines.next().is_none(),
        "unexpected trailing C1 oracle records"
    );

    println!(
        "S4_3C_4_MODE={mode} COMPARED={compared} \
         MISMATCHES={mismatches} STATUS={}",
        if mismatches == 0 { "PASS" } else { "FAIL" }
    );

    (compared, mismatches)
}

#[test]
fn reference_compute_c1_parity_all_modes() {
    let root = env::var("SMAUGT_C1_ORACLE")
        .expect("set SMAUGT_C1_ORACLE to the C1 oracle output directory");

    let root = Path::new(&root);

    let modes = [
        ("mode1", SMAUG_T128),
        ("mode3", SMAUG_T192),
        ("mode5", SMAUG_T256),
        ("modet", TIMER),
    ];

    let mut total_compared = 0usize;
    let mut total_mismatches = 0usize;

    for (mode, parameters) in modes {
        let (compared, mismatches) = validate_mode(mode, parameters, root);

        total_compared += compared;
        total_mismatches += mismatches;
    }

    println!(
        "S4_3C_4_C1_PARITY={} COEFFICIENTS={} MISMATCHES={}",
        if total_mismatches == 0 {
            "PASS"
        } else {
            "FAIL"
        },
        total_compared,
        total_mismatches
    );

    assert_eq!(total_compared, 11264);
    assert_eq!(total_mismatches, 0);
}
