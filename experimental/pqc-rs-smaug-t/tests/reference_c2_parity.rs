//! Differential validation of SMAUG-T computeC2 against the pinned C reference.

use pqc_rs_smaug_t::{
    ciphertext::compute_c2, ephemeral::expand_r, Parameters, Polynomial, N, SMAUG_T128, SMAUG_T192,
    SMAUG_T256, TIMER,
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

fn message_for(case: usize, len: usize) -> Vec<u8> {
    assert!(case < 4);

    (0..len)
        .map(|index| match case {
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
        })
        .collect()
}

fn public_vector_for(case: usize, parameters: &Parameters) -> Vec<Polynomial> {
    (0..parameters.k)
        .map(|poly_index| Polynomial {
            coefficients: std::array::from_fn(|index| {
                ((index * 17 + poly_index * 31 + case * 13) as u16) & (parameters.q - 1)
            }),
        })
        .collect()
}

fn validate_mode(mode: &str, parameters: Parameters, root: &Path) -> (usize, usize) {
    let path = root.join(format!("c2-{mode}.txt"));

    let content = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

    let mut lines = content.lines();
    let mut compared = 0usize;
    let mut mismatches = 0usize;

    for case in 0..4 {
        let header = lines.next().expect("missing C2 case header");
        assert_eq!(header, format!("CASE={case}"));

        let public_vector = public_vector_for(case, &parameters);
        let ephemeral_seed = seed_for(case, 0x5a);
        let ephemeral = expand_r(&ephemeral_seed, &parameters).expect("Rust expand_r failed");

        let message_len = if mode == "modet" { 16 } else { 32 };
        let message = message_for(case, message_len);

        let actual = compute_c2(&public_vector, &ephemeral, &message, &parameters)
            .expect("Rust compute_c2 failed");

        let line = lines.next().expect("missing C2 polynomial record");
        let mut fields = line.split_whitespace();

        let first = fields.next().expect("missing C2 first coefficient");
        let first = first.strip_prefix("C2=").expect("invalid C2 record prefix");

        let reference: Vec<u16> = std::iter::once(first)
            .chain(fields)
            .map(|value| value.parse::<u16>().expect("invalid C2 coefficient"))
            .collect();

        assert_eq!(reference.len(), N);

        for (index, (&expected, &observed)) in
            reference.iter().zip(actual.coefficients.iter()).enumerate()
        {
            assert!(
                expected < parameters.p_prime,
                "noncanonical C coefficient: mode={mode} \
                 case={case} index={index} value={expected}"
            );

            assert!(
                observed < parameters.p_prime,
                "noncanonical Rust coefficient: mode={mode} \
                 case={case} index={index} value={observed}"
            );

            compared += 1;

            if expected != observed {
                mismatches += 1;

                if mismatches <= 12 {
                    println!(
                        "S4_3D_6_MISMATCH MODE={mode} CASE={case} \
                         INDEX={index} C={expected} RUST={observed}"
                    );
                }
            }
        }
    }

    assert!(
        lines.next().is_none(),
        "unexpected trailing C2 oracle records"
    );

    println!(
        "S4_3D_6_MODE={mode} COMPARED={compared} \
         MISMATCHES={mismatches} STATUS={}",
        if mismatches == 0 { "PASS" } else { "FAIL" }
    );

    (compared, mismatches)
}

#[test]
fn reference_compute_c2_parity_all_modes() {
    let root = env::var("SMAUGT_C2_ORACLE")
        .expect("set SMAUGT_C2_ORACLE to the C2 oracle output directory");

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
        "S4_3D_6_C2_PARITY={} COEFFICIENTS={} MISMATCHES={}",
        if total_mismatches == 0 {
            "PASS"
        } else {
            "FAIL"
        },
        total_compared,
        total_mismatches
    );

    assert_eq!(total_compared, 4096);
    assert_eq!(total_mismatches, 0);
}
