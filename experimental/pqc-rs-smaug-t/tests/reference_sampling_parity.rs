use std::process::Command;

use pqc_rs_smaug_t::sampling::{hwt_randomness, rejection_sample_indices};
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
