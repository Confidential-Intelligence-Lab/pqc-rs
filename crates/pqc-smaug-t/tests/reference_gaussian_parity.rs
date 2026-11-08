use std::process::Command;

use pqc_rs_smaug_t::gaussian::{gaussian_poly, gaussian_vector, GaussianError};
use pqc_rs_smaug_t::N;

fn seed_for_pattern(pattern: u8) -> [u8; 32] {
    let mut seed = [0u8; 32];

    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = match pattern {
            0 => 0,
            1 => 255,
            2 => i as u8,
            _ => unreachable!(),
        };
    }

    seed
}

fn reference_coefficients(prefix: &str, mode: &str, pattern: u8, operation: &str) -> Vec<i16> {
    let output = Command::new(format!("{prefix}-{mode}"))
        .arg(pattern.to_string())
        .arg(operation)
        .output()
        .expect("failed to execute Gaussian C oracle");

    assert!(
        output.status.success(),
        "{mode} pattern={pattern} operation={operation}: C oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout)
        .expect("C oracle emitted invalid UTF-8")
        .trim()
        .split(',')
        .map(|value| value.parse().expect("invalid reference coefficient"))
        .collect()
}

#[test]
fn reference_gaussian_polynomial_parity() {
    let prefix =
        std::env::var("SMAUGT_GAUSSIAN_ORACLE").expect("SMAUGT_GAUSSIAN_ORACLE must be set");

    let configurations = [
        ("mode1", 10u32),
        ("mode3", 11),
        ("mode5", 11),
        ("modet", 10),
    ];

    let mut compared = 0usize;

    for (mode, log_q) in configurations {
        for pattern in 0..3u8 {
            let seed = seed_for_pattern(pattern);
            let mut extended = [0u8; 33];
            extended[..32].copy_from_slice(&seed);

            let reference = reference_coefficients(&prefix, mode, pattern, "p");

            assert_eq!(reference.len(), N);

            let rust =
                gaussian_poly(&extended, log_q).expect("Rust Gaussian polynomial sampling failed");

            assert_eq!(
                rust.as_slice(),
                reference.as_slice(),
                "{mode} pattern={pattern}: Gaussian polynomial mismatch"
            );

            compared += N;
        }
    }

    assert_eq!(compared, 3072);
    println!("GAUSSIAN_POLYNOMIAL_PARITY=PASS coefficients={compared}");
}

#[test]
fn reference_gaussian_vector_parity() {
    let prefix =
        std::env::var("SMAUGT_GAUSSIAN_ORACLE").expect("SMAUGT_GAUSSIAN_ORACLE must be set");

    let configurations = [
        ("mode1", 2usize, 10u32),
        ("mode3", 3, 11),
        ("mode5", 4, 11),
        ("modet", 2, 10),
    ];

    let mut compared = 0usize;

    for (mode, k, log_q) in configurations {
        for pattern in 0..3u8 {
            let seed = seed_for_pattern(pattern);

            let reference = reference_coefficients(&prefix, mode, pattern, "v");

            assert_eq!(reference.len(), k * N);

            let rust =
                gaussian_vector(&seed, k, log_q).expect("Rust Gaussian vector expansion failed");

            assert_eq!(rust.len(), k);

            for (i, polynomial) in rust.iter().enumerate() {
                let start = i * N;
                let end = start + N;

                assert_eq!(
                    polynomial.as_slice(),
                    &reference[start..end],
                    "{mode} pattern={pattern} polynomial={i}: Gaussian mismatch"
                );

                compared += N;
            }
        }
    }

    assert_eq!(compared, 8448);
    println!("GAUSSIAN_VECTOR_PARITY=PASS coefficients={compared}");
}

#[test]
fn gaussian_vector_rejects_invalid_parameters() {
    let seed = [0u8; 32];

    for k in [0, 1, 5, usize::MAX] {
        assert_eq!(
            gaussian_vector(&seed, k, 10),
            Err(GaussianError::InvalidParameters)
        );
    }

    for log_q in [0, 9, 12, u32::MAX] {
        assert_eq!(
            gaussian_vector(&seed, 2, log_q),
            Err(GaussianError::InvalidLogQ)
        );
    }
}

#[test]
#[ignore = "run separately against the pinned original Gaussian oracle"]
fn pinned_reference_gaussian_overwrite_regression() {
    let prefix =
        std::env::var("SMAUGT_GAUSSIAN_ORACLE").expect("SMAUGT_GAUSSIAN_ORACLE must be set");

    for mode in ["mode1", "mode3", "mode5", "modet"] {
        for pattern in 0..3u8 {
            let reference = reference_coefficients(&prefix, mode, pattern, "p");

            assert_eq!(reference.len(), N);

            assert!(
                reference[..64].iter().any(|&coefficient| coefficient != 0),
                "{mode} pattern={pattern}: expected nonzero first group"
            );

            assert!(
                reference[64..].iter().all(|&coefficient| coefficient == 0),
                "{mode} pattern={pattern}: unexpected nonzero tail"
            );
        }
    }

    println!("PINNED_GAUSSIAN_OVERWRITE_REGRESSION=PASS");
}
