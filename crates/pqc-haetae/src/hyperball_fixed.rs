// SPDX-License-Identifier: MIT

//! Experimental fixed-point arithmetic for HAETAE hyperball sampling.
//! Arithmetic follows the HAETAE 1.2.0 C reference.

use crate::gaussian::{fixpoint_square, Fp96_76};

const MASK48: u64 = (1_u64 << 48) - 1;

fn normalize(mut x: Fp96_76) -> Fp96_76 {
    x.hi = x.hi.wrapping_add(x.lo >> 48);
    x.lo &= MASK48;
    x
}

fn mul48(a: u64, b: u64) -> (u64, u64) {
    let p = u128::from(a) * u128::from(b);
    ((p as u64) & MASK48, (p >> 48) as u64)
}

pub(crate) fn mul(x: Fp96_76, y: Fp96_76) -> Fp96_76 {
    let (low, high) = mul48(x.lo, y.lo);

    let mut lo = high.wrapping_add(((low >> 47) + 1) >> 1);

    let (cross_lo, cross_hi) = mul48(x.lo, y.hi);
    lo = lo.wrapping_add(cross_lo);
    let mut hi = cross_hi;

    let (cross_lo, cross_hi) = mul48(x.hi, y.lo);
    lo = lo.wrapping_add(cross_lo);
    hi = hi.wrapping_add(cross_hi);

    lo = lo.wrapping_add(1_u64 << 27);
    lo >>= 28;
    lo = lo.wrapping_add((hi << 20) & MASK48);
    hi >>= 28;

    let p = u128::from(x.hi) * u128::from(y.hi);
    let p_lo = p as u64;
    let p_hi = (p >> 64) as u64;

    lo = lo.wrapping_add((p_lo << 20) & MASK48);
    hi = hi.wrapping_add((p_lo >> 28).wrapping_add(p_hi << 36));

    normalize(Fp96_76 { lo, hi })
}

fn neg(x: Fp96_76) -> Fp96_76 {
    normalize(Fp96_76 {
        lo: (x.lo ^ MASK48).wrapping_add(1),
        hi: !x.hi,
    })
}

fn sub(x: Fp96_76, y: Fp96_76) -> Fp96_76 {
    let n = neg(y);
    Fp96_76 {
        lo: x.lo.wrapping_add(n.lo),
        hi: x.hi.wrapping_add(n.hi),
    }
}

fn three_halves_minus(x: Fp96_76) -> Fp96_76 {
    let mut n = neg(x);
    n.hi = n.hi.wrapping_add(3_u64 << 27);
    normalize(n)
}

fn unsigned_signed_mul(x: Fp96_76, y: Fp96_76) -> Fp96_76 {
    let negative = (y.hi >> 63) != 0;
    let abs_y = if negative { neg(y) } else { y };
    let result = mul(x, abs_y);
    if negative {
        neg(result)
    } else {
        result
    }
}

fn starting_constants(mode: u8) -> (Fp96_76, Fp96_76) {
    match mode {
        2 => (
            Fp96_76 {
                lo: 0x770077e2e41a,
                hi: 0x1162,
            },
            Fp96_76 {
                lo: 0x693861ad937b,
                hi: 0x9caa56,
            },
        ),
        3 => (
            Fp96_76 {
                lo: 0x1a2935cfae68,
                hi: 0x978,
            },
            Fp96_76 {
                lo: 0x7ad215218533,
                hi: 0x7ff1c9,
            },
        ),
        5 => (
            Fp96_76 {
                lo: 0x700ff3e8890d,
                hi: 0x702,
            },
            Fp96_76 {
                lo: 0x5768588eed31,
                hi: 0x73bd40,
            },
        ),
        _ => panic!("unsupported HAETAE mode"),
    }
}

pub(crate) fn newton_invsqrt(xhalf: Fp96_76, mode: u8) -> Fp96_76 {
    let (cube, three_halves) = starting_constants(mode);

    let mut result = sub(three_halves, mul(xhalf, cube));

    for _ in 0..6 {
        let square = fixpoint_square(result);
        let product = mul(xhalf, square);
        let correction = three_halves_minus(product);
        result = unsigned_signed_mul(result, correction);
    }

    result
}

pub(crate) fn mul_high(x: Fp96_76, y: u64) -> Fp96_76 {
    let (mut lo, mut hi) = mul48(x.lo, y);
    let (cross_lo, cross_hi) = mul48(x.hi, y);

    hi = hi.wrapping_add(cross_lo);

    lo = lo.wrapping_add(1_u64 << 27);
    lo >>= 28;
    lo = lo.wrapping_add((hi << 20) & MASK48);
    hi >>= 28;
    hi = hi.wrapping_add(cross_hi << 20);

    normalize(Fp96_76 { lo, hi })
}

pub(crate) fn mul_rnd13(x: u64, y: Fp96_76, sign: u8) -> i32 {
    assert!(sign <= 1);

    let xx = Fp96_76 {
        lo: (x & 0xffff_ffff) << 16,
        hi: x >> 32,
    };

    let product = mul(xx, y);
    let rounded = product.hi.wrapping_add(1_u64 << 14) >> 15;

    let value = i32::try_from(rounded).expect("HAETAE coefficient out of range");
    if sign == 0 {
        value
    } else {
        -value
    }
}

pub(crate) fn half_rounded(x: Fp96_76) -> Fp96_76 {
    let mut lo = x.lo.wrapping_add(1);
    lo >>= 1;
    lo = lo.wrapping_add((x.hi & 1) << 47);

    normalize(Fp96_76 { lo, hi: x.hi >> 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_multiplication() {
        let zero = Fp96_76::default();
        let x = Fp96_76 {
            lo: 12345,
            hi: 67890,
        };
        assert_eq!(mul(zero, x), zero);
        assert_eq!(mul(x, zero), zero);
    }

    #[test]
    fn one_multiplication() {
        let one = Fp96_76 { lo: 0, hi: 1 << 28 };
        let x = Fp96_76 {
            lo: 0,
            hi: 123 << 28,
        };
        assert_eq!(mul(x, one), x);
    }

    #[test]
    fn negation_roundtrip() {
        let x = Fp96_76 {
            lo: 123456,
            hi: 98765,
        };
        assert_eq!(neg(neg(x)), x);
    }

    #[test]
    fn half_rounding() {
        let x = Fp96_76 { lo: 3, hi: 0 };
        assert_eq!(half_rounded(x), Fp96_76 { lo: 2, hi: 0 });
    }

    #[test]
    fn inverse_sqrt_is_deterministic() {
        let x = Fp96_76 { lo: 0, hi: 1 << 28 };
        for mode in [2, 3, 5] {
            assert_eq!(newton_invsqrt(x, mode), newton_invsqrt(x, mode));
        }
    }

    #[test]
    fn rounding_sign_symmetry() {
        let one = Fp96_76 { lo: 0, hi: 1 << 28 };
        assert_eq!(mul_rnd13(8192, one, 0), -mul_rnd13(8192, one, 1));
    }

    #[test]
    fn high_multiply_zero() {
        assert_eq!(mul_high(Fp96_76::default(), 123456), Fp96_76::default());
    }

    fn parse_fp(value: &str) -> Fp96_76 {
        let (lo, hi) = value.split_once(',').expect("two fixed-point limbs");
        Fp96_76 {
            lo: u64::from_str_radix(lo, 16).expect("hexadecimal low limb"),
            hi: u64::from_str_radix(hi, 16).expect("hexadecimal high limb"),
        }
    }

    fn verify_fixture(content: &str, expected_mode: u8) {
        let mut lines = content.lines();

        assert_eq!(lines.next(), Some("FORMAT=HAETAE_FIXED_ORACLE_V1"));

        let c_mode: u8 = lines
            .next()
            .expect("mode")
            .strip_prefix("MODE=")
            .expect("mode field")
            .parse()
            .expect("numeric mode");

        assert_eq!(c_mode, expected_mode);

        assert_eq!(lines.next(), Some("COUNT=128"));

        let rust_mode = match c_mode {
            0 => 2,
            1 => 3,
            2 => 5,
            _ => panic!("invalid C mode"),
        };

        for case in 0..128 {
            let case_line = lines.next().expect("case identifier");
            assert_eq!(case_line, format!("CASE={case}"));

            let input = parse_fp(
                lines
                    .next()
                    .expect("input")
                    .strip_prefix("INPUT=")
                    .expect("input field"),
            );

            let expected_square = parse_fp(
                lines
                    .next()
                    .expect("square")
                    .strip_prefix("SQUARE=")
                    .expect("square field"),
            );

            let expected_invsqrt = parse_fp(
                lines
                    .next()
                    .expect("inverse square root")
                    .strip_prefix("INVSQRT=")
                    .expect("inverse square root field"),
            );

            let sample: u64 = lines
                .next()
                .expect("sample")
                .strip_prefix("SAMPLE=")
                .expect("sample field")
                .parse()
                .expect("numeric sample");

            let sign: u8 = lines
                .next()
                .expect("sign")
                .strip_prefix("SIGN=")
                .expect("sign field")
                .parse()
                .expect("numeric sign");

            let expected_rounded: i32 = lines
                .next()
                .expect("rounded")
                .strip_prefix("ROUNDED=")
                .expect("rounded field")
                .parse()
                .expect("numeric rounded value");

            assert_eq!(
                fixpoint_square(input),
                expected_square,
                "mode={rust_mode} case={case} square"
            );

            let actual_invsqrt = newton_invsqrt(input, rust_mode);

            assert_eq!(
                actual_invsqrt, expected_invsqrt,
                "mode={rust_mode} case={case} inverse square root"
            );

            assert_eq!(
                mul_rnd13(sample, actual_invsqrt, sign),
                expected_rounded,
                "mode={rust_mode} case={case} signed rounding"
            );
        }

        assert!(lines.next().is_none(), "unexpected trailing fixture data");
    }

    #[test]
    fn authenticated_fixed_point_mode2() {
        verify_fixture(include_str!("hyperball_fixed_fixtures/mode0.txt"), 0);
    }

    #[test]
    fn authenticated_fixed_point_mode3() {
        verify_fixture(include_str!("hyperball_fixed_fixtures/mode1.txt"), 1);
    }

    #[test]
    fn authenticated_fixed_point_mode5() {
        verify_fixture(include_str!("hyperball_fixed_fixtures/mode2.txt"), 2);
    }
}

#[cfg(test)]
mod authenticated_hyperball_attempt_tests {
    use super::{half_rounded, mul_high, mul_rnd13, newton_invsqrt};
    use crate::gaussian::{sample_gauss_n, Fp96_76};
    use std::collections::BTreeMap;

    const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
    const FNV_PRIME: u64 = 1_099_511_628_211;

    fn decode_seed(hex: &str) -> [u8; 64] {
        assert_eq!(hex.len(), 128);
        let mut seed = [0_u8; 64];

        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).unwrap();
        }

        seed
    }

    fn parse_fp(value: &str) -> Fp96_76 {
        let (lo, hi) = value.split_once(',').unwrap();

        Fp96_76 {
            lo: u64::from_str_radix(lo, 16).unwrap(),
            hi: u64::from_str_radix(hi, 16).unwrap(),
        }
    }

    fn number(fields: &BTreeMap<&str, &str>, key: &str) -> u64 {
        fields.get(key).unwrap().parse().unwrap()
    }

    fn fp(fields: &BTreeMap<&str, &str>, key: &str) -> Fp96_76 {
        parse_fp(fields.get(key).unwrap())
    }

    fn check_fixture(
        text: &str,
        reference_mode: u8,
        mode: u8,
        k: usize,
        l: usize,
        scale: u64,
        threshold: u64,
    ) {
        let mut lines = text.lines();

        assert_eq!(lines.next(), Some("FORMAT=HAETAE_HYPERBALL_ATTEMPT_V1"));
        assert_eq!(
            lines.next(),
            Some(format!("MODE={reference_mode}").as_str())
        );
        assert_eq!(lines.next(), Some("COUNT=5"));
        assert_eq!(
            lines.next(),
            Some(format!("POLYNOMIALS={}", k + l).as_str())
        );
        assert_eq!(
            lines.next(),
            Some(format!("COEFFICIENTS={}", (k + l) * 256).as_str())
        );
        assert_eq!(lines.next(), Some(format!("SCALE={scale}").as_str()));
        assert_eq!(
            lines.next(),
            Some(format!("THRESHOLD={threshold}").as_str())
        );

        let mut cases = 0_usize;
        let mut fields = BTreeMap::new();
        let mut inside = false;

        for line in lines {
            if line == "BEGIN_CASE" {
                assert!(!inside);
                assert!(fields.is_empty());
                inside = true;
            } else if line == "END_CASE" {
                assert!(inside);
                inside = false;

                assert_eq!(number(&fields, "CASE") as usize, cases);

                let seed = decode_seed(fields["SEED"]);
                let nonce = u16::try_from(number(&fields, "NONCE")).unwrap();

                let mut next_nonce = nonce;
                let mut sqsum = Fp96_76::default();

                let mut coefficients = Vec::with_capacity((k + l) * 256);

                let mut positive = 0_u64;
                let mut negative = 0_u64;
                let mut zero = 0_u64;

                let mut digest = FNV_OFFSET;

                // Preserve the C reference's two 257-sample calls.
                let mut gaussian_outputs = Vec::with_capacity(k + l);

                for poly in 0..(k + l) {
                    let len = if poly < 2 { 257 } else { 256 };

                    let output = sample_gauss_n(&seed, next_nonce, len, sqsum);

                    sqsum = output.sqsum;
                    gaussian_outputs.push(output);

                    next_nonce = next_nonce.checked_add(1).expect("test nonce overflow");
                }

                assert_eq!(
                    u64::from(next_nonce),
                    number(&fields, "NEXT_NONCE"),
                    "mode={mode} case={cases} nonce"
                );

                assert_eq!(
                    sqsum,
                    fp(&fields, "SQSUM"),
                    "mode={mode} case={cases} sqsum"
                );

                let half = half_rounded(sqsum);

                assert_eq!(half, fp(&fields, "HALF"), "mode={mode} case={cases} half");

                let invsqrt = newton_invsqrt(half, mode);

                assert_eq!(
                    invsqrt,
                    fp(&fields, "INVSQRT"),
                    "mode={mode} case={cases} invsqrt"
                );

                let normalized = mul_high(invsqrt, scale);

                assert_eq!(
                    normalized,
                    fp(&fields, "NORMALIZED"),
                    "mode={mode} case={cases} normalized"
                );

                let mut norm2 = 0_u64;

                for output in &gaussian_outputs {
                    for index in 0..256 {
                        let sign = (output.signs[index / 8] >> (index % 8)) & 1;

                        let value = mul_rnd13(output.samples[index], normalized, sign);

                        coefficients.push(value);

                        let signed = i64::from(value);
                        let square = u64::try_from(signed * signed).unwrap();

                        norm2 = norm2.checked_add(square).expect("squared norm overflow");

                        match value.cmp(&0) {
                            std::cmp::Ordering::Greater => positive += 1,
                            std::cmp::Ordering::Less => negative += 1,
                            std::cmp::Ordering::Equal => zero += 1,
                        }

                        for byte in value.to_le_bytes() {
                            digest ^= u64::from(byte);
                            digest = digest.wrapping_mul(FNV_PRIME);
                        }
                    }
                }

                assert_eq!(coefficients.len(), (k + l) * 256);

                let expected_digest = u64::from_str_radix(fields["DIGEST"], 16).unwrap();

                assert_eq!(
                    digest, expected_digest,
                    "mode={mode} case={cases} coefficient digest"
                );

                assert_eq!(
                    norm2,
                    number(&fields, "NORM2"),
                    "mode={mode} case={cases} squared norm"
                );

                assert_eq!(
                    u64::from(norm2 <= threshold),
                    number(&fields, "ACCEPT"),
                    "mode={mode} case={cases} acceptance"
                );

                assert_eq!(positive, number(&fields, "POSITIVE"));
                assert_eq!(negative, number(&fields, "NEGATIVE"));
                assert_eq!(zero, number(&fields, "ZERO"));

                assert!(positive > 0);
                assert!(negative > 0);

                cases += 1;
                fields.clear();
            } else if inside {
                let (key, value) = line.split_once('=').expect("malformed fixture field");

                assert!(
                    fields.insert(key, value).is_none(),
                    "duplicate fixture field"
                );
            } else {
                assert!(line.is_empty(), "unexpected fixture content");
            }
        }

        assert!(!inside);
        assert!(fields.is_empty());
        assert_eq!(cases, 5);
    }

    #[test]
    fn authenticated_hyperball_attempt_mode2() {
        check_fixture(
            include_str!("hyperball_attempt_fixtures/mode0.txt"),
            0,
            2,
            2,
            4,
            2_643_021_496_320,
            6_505_809_026_482_176,
        );
    }

    #[test]
    fn authenticated_hyperball_attempt_mode3() {
        check_fixture(
            include_str!("hyperball_attempt_fixtures/mode1.txt"),
            1,
            3,
            3,
            6,
            4_916_390_789_120,
            22_510_896_139_993_088,
        );
    }

    #[test]
    fn authenticated_hyperball_attempt_mode5() {
        check_fixture(
            include_str!("hyperball_attempt_fixtures/mode2.txt"),
            2,
            5,
            4,
            7,
            5_997_831_421_952,
            33_503_371_683_954_688,
        );
    }
}
