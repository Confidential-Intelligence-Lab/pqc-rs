//! Native HAETAE 1.2.0 hyperball sampler.
//!
//! H1_3_D_3D_2B_NATIVE_HYPERBALL
//!
//! Internal implementation; not yet a public signing API.

use crate::gaussian::{sample_gauss_n, Fp96_76};
use crate::hyperball_fixed::{half_rounded, mul_high, mul_rnd13, newton_invsqrt};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const N: usize = 256;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct HyperballOutput {
    pub(crate) y1: Vec<[i32; N]>,
    pub(crate) y2: Vec<[i32; N]>,
    pub(crate) b: u8,
    pub(crate) next_nonce: u16,
    pub(crate) attempts: usize,
    pub(crate) norm2: u64,
}

// HAETAE_10K_7D_4C_3_HYPERBALL_LIFECYCLE
impl HyperballOutput {
    fn zeroize_secret_material(&mut self) {
        use zeroize::Zeroize;
        for coefficients in &mut self.y1 {
            coefficients.zeroize();
        }
        for coefficients in &mut self.y2 {
            coefficients.zeroize();
        }
    }
}

impl Drop for HyperballOutput {
    fn drop(&mut self) {
        self.zeroize_secret_material();
    }
}

#[cfg(test)]
mod hyperball_lifecycle_tests {
    use super::*;

    #[test]
    fn cleanup_is_idempotent_all_modes() {
        for mode in [2, 3, 5] {
            let (l, k, _, _) = constants(mode);
            let mut output = HyperballOutput {
                y1: vec![[123; N]; l],
                y2: vec![[456; N]; k],
                b: 1,
                next_nonce: 9,
                attempts: 2,
                norm2: 777,
            };

            output.zeroize_secret_material();
            assert!(output.y1.iter().flatten().all(|&x| x == 0));
            assert!(output.y2.iter().flatten().all(|&x| x == 0));

            assert_eq!(output.y1.len(), l);
            assert_eq!(output.y2.len(), k);
            assert_eq!(output.b, 1);
            assert_eq!(output.next_nonce, 9);
            assert_eq!(output.attempts, 2);
            assert_eq!(output.norm2, 777);

            output.zeroize_secret_material();
            assert!(output.y1.iter().flatten().all(|&x| x == 0));
            assert!(output.y2.iter().flatten().all(|&x| x == 0));
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HyperballError {
    NonceExhausted,
}

fn constants(mode: u8) -> (usize, usize, u64, u64) {
    match mode {
        2 => (4, 2, 2_643_021_496_320, 6_505_809_026_482_176),
        3 => (6, 3, 4_916_390_789_120, 22_510_896_139_993_088),
        5 => (7, 4, 5_997_831_421_952, 33_503_371_683_954_688),
        _ => panic!("unsupported HAETAE parameter set"),
    }
}

/// Samples until the hyperball norm condition is satisfied.
///
/// This implementation deliberately reports nonce exhaustion instead
/// of wrapping. Reference parity across the nonce boundary is not
/// claimed.
pub(crate) fn sample_hyperball(
    mode: u8,
    seed: &[u8; 64],
    initial_nonce: u16,
) -> Result<HyperballOutput, HyperballError> {
    let (l, k, scale, threshold) = constants(mode);

    let mut cursor = u32::from(initial_nonce);
    let mut attempts = 0_usize;

    loop {
        let mut sqsum = Fp96_76::default();
        let mut gaussian = Vec::with_capacity(l + k);

        for poly in 0..(l + k) {
            if cursor > u32::from(u16::MAX) {
                return Err(HyperballError::NonceExhausted);
            }

            let nonce = cursor as u16;
            let len = if poly < 2 { 257 } else { 256 };

            let output = sample_gauss_n(seed, nonce, len, sqsum);

            sqsum = output.sqsum;
            gaussian.push(output);
            cursor += 1;
        }

        let half = half_rounded(sqsum);
        let invsqrt = newton_invsqrt(half, mode);
        let normalized = mul_high(invsqrt, scale);

        // HAETAE_10K_7D_4C_6_NORMALIZED_VECTOR_LIFECYCLE
        let mut y1 = zeroize::Zeroizing::new(Vec::with_capacity(l));
        let mut y2 = zeroize::Zeroizing::new(Vec::with_capacity(k));
        let mut norm2 = 0_u64;

        for (poly, output) in gaussian.iter().enumerate() {
            let mut coefficients = zeroize::Zeroizing::new([0_i32; N]);

            for (index, coefficient) in coefficients.iter_mut().enumerate() {
                let sign = (output.signs[index / 8] >> (index % 8)) & 1;

                let value = mul_rnd13(output.samples[index], normalized, sign);

                *coefficient = value;

                let signed = i64::from(value);

                norm2 = norm2
                    .checked_add((signed * signed) as u64)
                    .expect("hyperball norm overflow");
            }

            if poly < l {
                y1.push(*coefficients);
            } else {
                y2.push(*coefficients);
            }
        }

        attempts += 1;

        if norm2 <= threshold {
            if cursor > u32::from(u16::MAX) {
                return Err(HyperballError::NonceExhausted);
            }

            let next_nonce = cursor as u16;

            let mut shake = Shake256::default();
            shake.update(seed);
            shake.update(&next_nonce.to_le_bytes());

            let mut b = [0_u8; 1];
            shake.finalize_xof().read(&mut b);

            return Ok(HyperballOutput {
                y1: std::mem::take(&mut *y1),
                y2: std::mem::take(&mut *y2),
                b: b[0],
                next_nonce,
                attempts,
                norm2,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_all_modes() {
        let seed = std::array::from_fn(|i| (i * 17) as u8);

        for mode in [2, 3, 5] {
            let first = sample_hyperball(mode, &seed, 7).unwrap();
            let second = sample_hyperball(mode, &seed, 7).unwrap();

            assert_eq!(first, second);
            assert!(first.attempts >= 1);
            assert!(first.norm2 <= constants(mode).3);
            assert_eq!(
                first.y1.len() + first.y2.len(),
                constants(mode).0 + constants(mode).1,
            );
        }
    }

    #[test]
    fn nonce_exhaustion_is_explicit() {
        let seed = [0_u8; 64];

        for mode in [2, 3, 5] {
            assert_eq!(
                sample_hyperball(mode, &seed, u16::MAX),
                Err(HyperballError::NonceExhausted),
            );
        }
    }
}

#[cfg(test)]
mod authenticated_complete_hyperball_tests {
    use super::*;

    // H1_3_D_3D_3C_AUTHENTICATED_COMPLETE_PARITY

    fn parse_case(case: &str) -> std::collections::HashMap<&str, &str> {
        case.lines()
            .filter_map(|line| line.split_once('='))
            .collect()
    }

    fn decode_seed(hex: &str) -> [u8; 64] {
        assert_eq!(hex.len(), 128);

        let mut seed = [0_u8; 64];

        for (index, byte) in seed.iter_mut().enumerate() {
            let start = index * 2;
            *byte = u8::from_str_radix(&hex[start..start + 2], 16).unwrap();
        }

        seed
    }

    fn verify(mode: u8, fixture: &str) {
        let mut lines = fixture.lines();

        assert_eq!(lines.next(), Some("FORMAT=HAETAE_COMPLETE_HYPERBALL_V1"));

        let expected_config = match mode {
            2 => 0,
            3 => 1,
            5 => 2,
            _ => panic!("unsupported mode"),
        };

        assert!(fixture.contains(&format!("MODE={expected_config}\n")));

        let cases: Vec<_> = fixture.split("BEGIN_CASE\n").skip(1).collect();

        assert_eq!(cases.len(), 64);

        let (l, k, _, threshold) = constants(mode);

        let mut compared_coefficients = 0_usize;

        for (case_id, case) in cases.iter().enumerate() {
            let fields = parse_case(case);

            assert_eq!(fields["CASE"].parse::<usize>().unwrap(), case_id);

            let seed = decode_seed(fields["SEED"]);
            let nonce = fields["NONCE"].parse::<u16>().unwrap();

            let result = sample_hyperball(mode, &seed, nonce)
                .unwrap_or_else(|error| panic!("mode={mode} case={case_id} error={error:?}"));

            let expected_nonce = fields["NEXT_NONCE"].parse::<u16>().unwrap();

            let expected_attempts = fields["ATTEMPTS"].parse::<usize>().unwrap();

            let expected_b = fields["B"].parse::<u8>().unwrap();

            let expected_norm = fields["NORM2"].parse::<u64>().unwrap();

            assert_eq!(
                result.next_nonce, expected_nonce,
                "mode={mode} case={case_id} next_nonce"
            );

            assert_eq!(
                result.attempts, expected_attempts,
                "mode={mode} case={case_id} attempts"
            );

            assert_eq!(result.b, expected_b, "mode={mode} case={case_id} b");

            assert_eq!(
                result.norm2, expected_norm,
                "mode={mode} case={case_id} norm2"
            );

            assert!(
                result.norm2 <= threshold,
                "mode={mode} case={case_id} threshold"
            );

            assert_eq!(result.y1.len(), l);
            assert_eq!(result.y2.len(), k);

            let expected: Vec<i32> = fields["COEFFICIENTS"]
                .split(',')
                .map(|value| value.parse::<i32>().unwrap())
                .collect();

            assert_eq!(expected.len(), (l + k) * N);

            for (poly_index, poly) in result.y1.iter().chain(result.y2.iter()).enumerate() {
                for (coefficient_index, actual) in poly.iter().enumerate() {
                    let flat_index = poly_index * N + coefficient_index;

                    assert_eq!(
                        *actual, expected[flat_index],
                        "mode={mode} case={case_id} \
                         poly={poly_index} \
                         coefficient={coefficient_index}"
                    );

                    compared_coefficients += 1;
                }
            }
        }

        assert_eq!(compared_coefficients, 64 * (l + k) * N);

        println!(
            "HAETAE_MODE={mode} CASES=64 \
             COEFFICIENTS={compared_coefficients} \
             COMPLETE_PARITY=PASS"
        );
    }

    #[test]
    fn authenticated_complete_hyperball_mode2() {
        verify(2, include_str!("hyperball_complete_fixtures/mode0.txt"));
    }

    #[test]
    fn authenticated_complete_hyperball_mode3() {
        verify(3, include_str!("hyperball_complete_fixtures/mode1.txt"));
    }

    #[test]
    fn authenticated_complete_hyperball_mode5() {
        verify(5, include_str!("hyperball_complete_fixtures/mode2.txt"));
    }
}

#[cfg(test)]
mod authenticated_hyperball_rejection_tests {
    use super::*;

    // H1_3_D_3D_4C_REJECTION_LOOP_PARITY

    fn verify(mode: u8, fixture: &str, expected_cases: usize) {
        let expected_config = match mode {
            2 => 0,
            3 => 1,
            5 => 2,
            _ => panic!("unsupported mode"),
        };

        assert!(fixture.starts_with("FORMAT=HAETAE_HYPERBALL_REJECTION_FIXTURES_V1\n"));

        let header = fixture.split("BEGIN_CASE\n").next().unwrap();

        let header_fields: std::collections::HashMap<_, _> = header
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();

        assert_eq!(
            header_fields["MODE"].parse::<u8>().unwrap(),
            expected_config
        );

        assert_eq!(
            header_fields["COUNT"].parse::<usize>().unwrap(),
            expected_cases
        );

        let (l, k, _, threshold) = constants(mode);

        let cases: Vec<_> = fixture.split("BEGIN_CASE\n").skip(1).collect();

        assert_eq!(cases.len(), expected_cases);

        let mut coefficient_count = 0_usize;

        for case in cases {
            assert!(case.trim_end().ends_with("END_CASE"));

            let fields: std::collections::HashMap<_, _> = case
                .lines()
                .filter_map(|line| line.split_once('='))
                .collect();

            let case_id = fields["CASE"].parse::<usize>().unwrap();

            let seed_hex = fields["SEED"];
            assert_eq!(seed_hex.len(), 128);

            let mut seed = [0_u8; 64];

            for (index, byte) in seed.iter_mut().enumerate() {
                let offset = index * 2;
                *byte = u8::from_str_radix(&seed_hex[offset..offset + 2], 16).unwrap();
            }

            let nonce = fields["NONCE"].parse::<u16>().unwrap();

            let result = sample_hyperball(mode, &seed, nonce)
                .unwrap_or_else(|error| panic!("mode={mode} case={case_id} error={error:?}"));

            let expected_nonce = fields["NEXT_NONCE"].parse::<u16>().unwrap();

            let expected_attempts = fields["ATTEMPTS"].parse::<usize>().unwrap();

            let expected_b = fields["B"].parse::<u8>().unwrap();

            let expected_norm = fields["NORM2"].parse::<u64>().unwrap();

            assert_eq!(expected_attempts, 2);

            assert_eq!(
                result.attempts, expected_attempts,
                "mode={mode} case={case_id} attempts"
            );

            assert_eq!(
                result.next_nonce, expected_nonce,
                "mode={mode} case={case_id} nonce"
            );

            assert_eq!(result.b, expected_b, "mode={mode} case={case_id} b");

            assert_eq!(
                result.norm2, expected_norm,
                "mode={mode} case={case_id} norm2"
            );

            assert!(result.norm2 <= threshold);

            assert_eq!(result.y1.len(), l);
            assert_eq!(result.y2.len(), k);

            let expected: Vec<i32> = fields["COEFFICIENTS"]
                .split(',')
                .map(|value| value.parse::<i32>().unwrap())
                .collect();

            assert_eq!(expected.len(), (l + k) * N);

            for (poly_index, poly) in result.y1.iter().chain(result.y2.iter()).enumerate() {
                for (index, actual) in poly.iter().enumerate() {
                    let flat_index = poly_index * N + index;

                    assert_eq!(
                        *actual, expected[flat_index],
                        "mode={mode} case={case_id} \
                         poly={poly_index} coefficient={index}"
                    );

                    coefficient_count += 1;
                }
            }
        }

        assert_eq!(coefficient_count, expected_cases * (l + k) * N);

        println!(
            "HAETAE_MODE={mode} \
             REJECTION_CASES={expected_cases} \
             COEFFICIENTS={coefficient_count} \
             REJECTION_PARITY=PASS"
        );
    }

    #[test]
    fn authenticated_rejection_mode2() {
        verify(
            2,
            include_str!("hyperball_complete_fixtures/rejection_mode0.txt"),
            1,
        );
    }

    #[test]
    fn authenticated_rejection_mode3() {
        verify(
            3,
            include_str!("hyperball_complete_fixtures/rejection_mode1.txt"),
            2,
        );
    }

    #[test]
    fn authenticated_rejection_mode5() {
        verify(
            5,
            include_str!("hyperball_complete_fixtures/rejection_mode2.txt"),
            2,
        );
    }
}
