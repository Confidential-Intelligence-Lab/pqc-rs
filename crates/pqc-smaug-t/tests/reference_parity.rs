// SPDX-License-Identifier: MIT

use pqc_rs_smaug_t::encoding::{pack_unsigned, POLY_N};
use std::process::Command;

#[test]
fn reference_packing_parity() {
    let oracle = std::env::var("SMAUGT_PACK_ORACLE")
        .expect("SMAUGT_PACK_ORACLE must be set for reference parity tests");

    let cases: &[(u8, u32)] = &[
        (3, 1),
        (4, 2),
        (5, 3),
        (7, 4),
        (8, 5),
        (9, 6),
        (10, 7),
        (11, 8),
    ];

    for &(width, seed) in cases {
        let mode = match width {
            3 => "modet",
            4 => "mode3",
            5 => "mode1",
            7 => "mode5",
            8 => "mode1",
            9 => "mode3",
            10 => "mode1",
            11 => "mode3",
            _ => unreachable!(),
        };

        let executable = format!("{oracle}-{mode}");

        let output = Command::new(&executable)
            .arg(width.to_string())
            .arg(seed.to_string())
            .output()
            .expect("failed to execute reference oracle");

        assert!(
            output.status.success(),
            "C oracle failed for width {width}: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let expected = String::from_utf8(output.stdout).expect("reference output was not UTF-8");

        let mut coefficients = [0u16; POLY_N];
        let mask = (1u16 << width) - 1;

        for (i, coefficient) in coefficients.iter_mut().enumerate() {
            *coefficient = ((i as u32 * 73 + seed * 19) as u16) & mask;
        }

        let actual = pack_unsigned(&coefficients, width).expect("Rust packing failed");

        let actual_hex: String = actual.iter().map(|b| format!("{b:02x}")).collect();

        assert_eq!(
            actual_hex,
            expected.trim(),
            "reference mismatch at width {width}"
        );
    }
}

#[test]
fn reference_decoding_parity() {
    use pqc_rs_smaug_t::encoding::{pack_unsigned, POLY_N};
    use std::process::Command;

    let oracle = std::env::var("SMAUGT_DECODE_ORACLE").expect("SMAUGT_DECODE_ORACLE must be set");

    let cases: &[(&str, &[u8])] = &[
        ("mode1", &[5, 8, 10]),
        ("mode3", &[4, 9, 11]),
        ("mode5", &[7, 9, 11]),
        ("modet", &[3, 8, 10]),
    ];

    for &(mode, widths) in cases {
        for &width in widths {
            let limit = 1u16 << width;

            for pattern in 0..5u32 {
                let mut coefficients = [0u16; POLY_N];

                for (i, coefficient) in coefficients.iter_mut().enumerate() {
                    *coefficient = match pattern {
                        0 => 0,
                        1 => limit - 1,
                        2 => {
                            if i % 2 == 0 {
                                0
                            } else {
                                limit - 1
                            }
                        }
                        3 => {
                            if i == 0 || i == POLY_N - 1 {
                                limit - 1
                            } else {
                                0
                            }
                        }
                        _ => {
                            let x = (i as u32)
                                .wrapping_mul(73)
                                .wrapping_add(19)
                                .wrapping_mul(2654435761);
                            (x as u16) & (limit - 1)
                        }
                    };
                }

                let packed = pack_unsigned(&coefficients, width).expect("Rust packing failed");

                let hex: String = packed.iter().map(|b| format!("{b:02x}")).collect();

                let executable = format!("{oracle}-{mode}");

                let output = Command::new(&executable)
                    .arg(width.to_string())
                    .arg(&hex)
                    .output()
                    .expect("failed to execute C decode oracle");

                assert!(
                    output.status.success(),
                    "C decode failed: mode={mode}, width={width}, \
                     pattern={pattern}, stderr={}",
                    String::from_utf8_lossy(&output.stderr)
                );

                let decoded: Vec<u16> = String::from_utf8(output.stdout)
                    .expect("invalid C oracle UTF-8")
                    .trim()
                    .split(',')
                    .map(|s| s.parse::<u16>().expect("invalid decoded coefficient"))
                    .collect();

                assert_eq!(decoded.len(), POLY_N, "incorrect decoded length");

                assert_eq!(
                    decoded.as_slice(),
                    coefficients.as_slice(),
                    "C/Rust decode mismatch: \
                     mode={mode}, width={width}, pattern={pattern}"
                );
            }
        }
    }
}
