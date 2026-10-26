// SPDX-License-Identifier: MIT
use std::process::Command;

use pqc_rs_smaug_t::arithmetic::{
    matrix_vec_mult_add_scaled, matrix_vec_mult_sub_scaled, vec_vec_mult_add_scaled,
};

const N: usize = 256;

fn coefficient(pattern: usize, role: usize, i: usize, j: usize, k: usize) -> u16 {
    let v: i32 = match pattern {
        0 => 0,
        1 => {
            if k != 0 && k != 255 {
                0
            } else {
                match role {
                    0 => (i * 3 + j + 1) as i32,
                    1 => (i + 2) as i32,
                    _ => (i * 7 + k % 5 + 11) as i32,
                }
            }
        }
        2 => ((i * 29 + j * 17 + k * 7 + role * 13) % 31) as i32 - 15,
        _ => unreachable!(),
    };
    (v as i16) as u16
}

fn polynomial(pattern: usize, role: usize, i: usize, j: usize, shift: u32) -> [u16; N] {
    std::array::from_fn(|k| {
        let v = coefficient(pattern, role, i, j, k);
        if role == 0 {
            v.wrapping_shl(shift)
        } else {
            v
        }
    })
}

fn run<const K: usize>(prefix: &str, mode: &str, qshift: u32, pshift: u32) -> usize {
    let mut compared = 0;

    for pattern in 0..3 {
        let secret: [[u16; N]; K] = std::array::from_fn(|i| polynomial(pattern, 1, i, 0, 0));

        for op in 0..3 {
            let shifts: &[u32] = if op == 0 {
                &[qshift, pshift]
            } else {
                &[qshift]
            };

            for &shift in shifts {
                let actual: Vec<u16> = if op == 0 {
                    let vector: [[u16; N]; K] =
                        std::array::from_fn(|j| polynomial(pattern, 0, 0, j, shift));
                    let mut out = polynomial(pattern, 2, 0, 0, 0);
                    vec_vec_mult_add_scaled(&mut out, &vector, &secret, shift);
                    out.to_vec()
                } else {
                    let matrix: [[[u16; N]; K]; K] = std::array::from_fn(|i| {
                        std::array::from_fn(|j| polynomial(pattern, 0, i, j, qshift))
                    });
                    let mut out: [[u16; N]; K] = std::array::from_fn(|i| {
                        if op == 2 {
                            polynomial(pattern, 2, i, 0, 0)
                        } else {
                            [0u16; N]
                        }
                    });
                    if op == 1 {
                        matrix_vec_mult_add_scaled(&mut out, &matrix, &secret, qshift);
                    } else {
                        matrix_vec_mult_sub_scaled(&mut out, &matrix, &secret, qshift);
                    }
                    out.into_iter().flatten().collect()
                };

                let output = Command::new(format!("{prefix}-{mode}"))
                    .arg(op.to_string())
                    .arg(pattern.to_string())
                    .arg(shift.to_string())
                    .output()
                    .expect("failed to execute C arithmetic oracle");

                assert!(
                    output.status.success(),
                    "{mode} op={op} pattern={pattern} shift={shift}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );

                let stdout =
                    String::from_utf8(output.stdout).expect("C oracle emitted invalid UTF-8");
                let expected: Vec<u16> = stdout
                    .trim()
                    .split(',')
                    .map(|s| s.parse().expect("invalid C coefficient"))
                    .collect();

                assert_eq!(expected.len(), actual.len());
                for (index, (&c, &rust)) in expected.iter().zip(&actual).enumerate() {
                    assert_eq!(
                        rust, c,
                        "mode={mode} op={op} pattern={pattern} \
                         shift={shift} coefficient={index}"
                    );
                }

                compared += actual.len();
                println!(
                    "MODE={mode} OP={op} SHIFT={shift} \
                     PATTERN={pattern} MISMATCHES=0"
                );
            }
        }
    }
    compared
}

#[test]
fn reference_arithmetic_parity() {
    let prefix =
        std::env::var("SMAUGT_ARITHMETIC_ORACLE").expect("SMAUGT_ARITHMETIC_ORACLE must be set");

    let total = run::<2>(&prefix, "mode1", 6, 8)
        + run::<3>(&prefix, "mode3", 5, 7)
        + run::<4>(&prefix, "mode5", 5, 7)
        + run::<2>(&prefix, "modet", 6, 8);

    assert_eq!(total, 23040);
    println!("S4_2B_2_ARITHMETIC_PARITY=PASS COEFFICIENTS={total}");
}
