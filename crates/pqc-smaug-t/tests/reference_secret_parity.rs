// SPDX-License-Identifier: MIT

use pqc_rs_smaug_t::encoding::{pack_secret, unpack_secret, POLY_N};
use std::process::Command;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn canonical_secret_reference_parity() {
    let oracle = std::env::var("SMAUGT_SECRET_ORACLE").expect("SMAUGT_SECRET_ORACLE must be set");

    for mode in ["mode1", "mode3", "mode5", "modet"] {
        for pattern in 0..5usize {
            let mut coefficients = [0i16; POLY_N];

            for (i, coefficient) in coefficients.iter_mut().enumerate() {
                *coefficient = match pattern {
                    0 => 0,
                    1 => 1,
                    2 => -1,
                    3 => [-1, 0, 1][i % 3],
                    _ => {
                        if i == 0 || i == POLY_N - 1 {
                            -1
                        } else {
                            0
                        }
                    }
                };
            }

            let rust_bytes = pack_secret(&coefficients).unwrap();

            let input: Vec<u8> = coefficients.iter().map(|&x| (x + 1) as u8).collect();

            let executable = format!("{oracle}-{mode}");

            let packed = Command::new(&executable)
                .arg("pack")
                .arg(to_hex(&input))
                .output()
                .expect("C secret pack oracle unavailable");

            assert!(
                packed.status.success(),
                "C secret pack failed: {}",
                String::from_utf8_lossy(&packed.stderr)
            );

            assert_eq!(
                String::from_utf8(packed.stdout).unwrap().trim(),
                to_hex(&rust_bytes),
                "secret pack mismatch: mode={mode}, pattern={pattern}"
            );

            let decoded = Command::new(&executable)
                .arg("unpack")
                .arg(to_hex(&rust_bytes))
                .output()
                .expect("C secret unpack oracle unavailable");

            assert!(
                decoded.status.success(),
                "C secret unpack failed: {}",
                String::from_utf8_lossy(&decoded.stderr)
            );

            let values: Vec<i16> = String::from_utf8(decoded.stdout)
                .unwrap()
                .trim()
                .split(',')
                .map(|s| s.parse().unwrap())
                .collect();

            assert_eq!(values.as_slice(), coefficients.as_slice());

            assert_eq!(unpack_secret(&rust_bytes).unwrap(), coefficients);
        }
    }
}
