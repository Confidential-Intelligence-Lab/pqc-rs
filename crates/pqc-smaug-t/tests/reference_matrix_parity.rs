// SPDX-License-Identifier: MIT

use std::process::Command;

use pqc_rs_smaug_t::matrix::expand_matrix;
use pqc_rs_smaug_t::{Parameters, N, SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER};

#[test]
fn reference_matrix_parity() {
    let prefix = std::env::var("SMAUGT_MATRIX_ORACLE").expect("SMAUGT_MATRIX_ORACLE must be set");

    let configurations: [(&str, Parameters); 4] = [
        ("modet", TIMER),
        ("mode1", SMAUG_T128),
        ("mode3", SMAUG_T192),
        ("mode5", SMAUG_T256),
    ];

    let mut matrices_checked = 0usize;
    let mut coefficients_checked = 0usize;

    for (mode, parameters) in configurations {
        let executable = format!("{prefix}-{mode}");

        for pattern in 0..3u8 {
            let mut seed = [0u8; 32];

            for (index, byte) in seed.iter_mut().enumerate() {
                *byte = match pattern {
                    0 => 0,
                    1 => 0xff,
                    _ => index as u8,
                };
            }

            let rust_matrix = expand_matrix(&seed, &parameters);

            let output = Command::new(&executable)
                .arg(pattern.to_string())
                .output()
                .expect("failed to execute matrix oracle");

            assert!(
                output.status.success(),
                "oracle failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let stdout = String::from_utf8(output.stdout).expect("oracle output is not UTF-8");

            let lines: Vec<&str> = stdout.lines().collect();

            assert_eq!(
                lines.len(),
                parameters.k * parameters.k,
                "matrix dimensions mismatch: {mode}"
            );

            for row in 0..parameters.k {
                for column in 0..parameters.k {
                    let line = lines[row * parameters.k + column];

                    let coefficients: Vec<u16> = line
                        .split(',')
                        .map(|value| value.parse::<u16>().expect("invalid oracle coefficient"))
                        .collect();

                    assert_eq!(coefficients.len(), N);

                    assert_eq!(
                        coefficients.as_slice(),
                        rust_matrix[row][column].coefficients.as_slice(),
                        "matrix mismatch: mode={mode}, pattern={pattern}, \
                         row={row}, column={column}"
                    );

                    coefficients_checked += N;
                }
            }

            matrices_checked += 1;
        }
    }

    assert_eq!(matrices_checked, 12);
    assert_eq!(coefficients_checked, 25_344);

    println!(
        "MATRIX_PARITY=PASS matrices={} coefficients={}",
        matrices_checked, coefficients_checked
    );
}
