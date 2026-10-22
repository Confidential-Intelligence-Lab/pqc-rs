use std::process::Command;

use pqc_rs_smaug_t::sampling::{
    fixed_weight_ternary, hwt_randomness, rejection_sample_indices, SMAUG_T128_SECRET_WEIGHT,
    SMAUG_T192_SECRET_WEIGHT, SMAUG_T256_SECRET_WEIGHT, TIMER_SECRET_WEIGHT,
};
use pqc_rs_smaug_t::N;

#[test]
fn reference_sampling_indices_parity() {
    let prefix =
        std::env::var("SMAUGT_SAMPLING_ORACLE").expect("SMAUGT_SAMPLING_ORACLE must be set");

    let mut compared = 0usize;

    for mode in ["mode1", "mode3", "mode5", "modet"] {
        for pattern in 0..3u8 {
            let output = Command::new(format!("{prefix}-{mode}"))
                .arg(pattern.to_string())
                .output()
                .expect("failed to execute C sampling oracle");

            assert!(
                output.status.success(),
                "C oracle failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let mut seed = [0u8; 34];
            for (i, byte) in seed[..32].iter_mut().enumerate() {
                *byte = match pattern {
                    0 => 0,
                    1 => 255,
                    _ => i as u8,
                };
            }

            let (randomness, _) = hwt_randomness(&seed);
            let rust = rejection_sample_indices(&randomness);

            let text = String::from_utf8(output.stdout).expect("C oracle emitted invalid UTF-8");

            if text.trim() == "EXHAUSTED" {
                assert!(rust.is_err(), "{mode} pattern={pattern}");
                continue;
            }

            let reference: Vec<u16> = text
                .trim()
                .split(',')
                .map(|s| s.parse().expect("invalid C index"))
                .collect();

            assert_eq!(reference.len(), N);
            let rust = rust.expect("Rust exhausted but C succeeded");

            assert_eq!(
                rust.as_slice(),
                reference.as_slice(),
                "{mode} pattern={pattern}"
            );

            compared += N;
        }
    }

    println!("SAMPLING_INDEX_PARITY=PASS coefficients={compared}");
    assert_eq!(compared, 4 * 3 * N);
}

#[test]
fn reference_ternary_polynomial_parity() {
    let prefix =
        std::env::var("SMAUGT_SAMPLING_ORACLE").expect("SMAUGT_SAMPLING_ORACLE must be set");

    let configurations = [
        ("mode1", SMAUG_T128_SECRET_WEIGHT),
        ("mode3", SMAUG_T192_SECRET_WEIGHT),
        ("mode5", SMAUG_T256_SECRET_WEIGHT),
        ("modet", TIMER_SECRET_WEIGHT),
    ];

    let mut compared = 0usize;

    for (mode, weight) in configurations {
        for pattern in 0..3u8 {
            let output = std::process::Command::new(format!("{prefix}-{mode}"))
                .arg(pattern.to_string())
                .arg("t")
                .output()
                .expect("failed to execute reference HWT oracle");

            assert!(
                output.status.success(),
                "C HWT oracle failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let mut seed = [0u8; 34];

            for (i, byte) in seed[..32].iter_mut().enumerate() {
                *byte = match pattern {
                    0 => 0,
                    1 => 255,
                    _ => i as u8,
                };
            }

            let (randomness, signs) = hwt_randomness(&seed);
            let indices = rejection_sample_indices(&randomness);

            let text =
                String::from_utf8(output.stdout).expect("C HWT oracle emitted invalid UTF-8");

            if text.trim() == "EXHAUSTED" {
                assert!(
                    indices.is_err(),
                    "{mode} pattern={pattern}: C exhausted but Rust succeeded"
                );
                continue;
            }

            let indices = indices.expect("Rust sampler exhausted but C HWT succeeded");

            let reference: Vec<i16> = text
                .trim()
                .split(',')
                .map(|value| value.parse().expect("invalid C coefficient"))
                .collect();

            assert_eq!(reference.len(), N);

            let rust = fixed_weight_ternary(&indices, &signs, weight);

            assert_eq!(
                rust.as_slice(),
                reference.as_slice(),
                "{mode} pattern={pattern}: ternary mismatch"
            );

            assert!(
                rust.iter()
                    .all(|&coefficient| (-1..=1).contains(&coefficient)),
                "{mode} pattern={pattern}: nonternary coefficient"
            );

            let actual_weight = rust.iter().filter(|&&x| x != 0).count();

            assert_eq!(
                actual_weight, weight,
                "{mode} pattern={pattern}: incorrect Hamming weight"
            );

            compared += N;
        }
    }

    assert_eq!(compared, 4 * 3 * N);

    println!("TERNARY_POLYNOMIAL_PARITY=PASS coefficients={compared}");
}
