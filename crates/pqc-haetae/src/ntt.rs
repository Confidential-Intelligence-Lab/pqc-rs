//! HAETAE 1.2.0 number-theoretic transform.
//!
//! The butterfly structure follows the existing PQC-rs ML-DSA NTT.
//! Twiddle factors and normalization follow the authenticated
//! HAETAE 1.2.0 reference implementation.
//!
//! Experimental: not yet independently validated against C outputs.

use crate::montgomery::montgomery_reduce;
use crate::params::N;

const ZETAS: [i32; N] = [
    0, 26964, -16505, 22229, 30746, 20243, 19064, -31218, 9395, -30985, 22859, -8851, 32144, 13744,
    21408, 17599, -16039, -22946, 6241, -19553, 10681, 22935, 22431, -29104, 28147, -27527, -29133,
    -20035, 20143, -11361, 30820, 25252, -22562, -6789, -10049, 9383, 16304, -12296, 16446, 18239,
    -1296, -19725, -32076, 11782, -17941, 29643, -8577, 7893, -21464, -19646, -15130, -2391, 30608,
    -23970, -16608, 19616, -7941, 26533, -19129, 27690, 7597, -11459, 10615, -9430, 11591, 7814,
    12697, 32114, -3761, -9604, 19813, 20353, 17456, -16267, -19555, 598, -29942, 4538, 835, 15546,
    3970, -27685, 1488, 8311, -12442, 31352, -17631, 1806, -5342, 9790, 29068, 16507, -29051,
    22131, 6759, 15510, -14941, 28710, 1160, -31327, 24985, 11261, -10623, -27727, 21502, 18731,
    -16186, -4127, -18832, 12050, -14501, 7929, 29563, -31064, 5913, 5322, -16405, 2844, 29439,
    5876, -9522, -18586, -9874, 23844, 30362, -21442, 9560, 17671, -27989, 3350, 787, -13857, 1657,
    -21224, -7374, -9190, 2464, 25555, -3529, -28772, 16588, -15739, 23475, 13666, 5764, 30980,
    13633, -7401, -30317, 28847, 7682, -11808, -8796, 14864, -24162, -19194, 689, -1311, -31332,
    -16319, 1025, 10971, -23016, -2648, -21900, -12543, -25921, 28254, 28521, -16160, 12380,
    -12882, -30332, -16630, 23439, 7742, 17182, 17494, 5920, 13642, 7382, -18166, 21422, -30274,
    -28190, 13283, -20316, -9939, 10672, 21454, 6080, -17374, -29735, -25912, -10170, 3808, 10639,
    -26985, -10865, 25636, 17261, -26851, -8253, -3304, 18282, -2202, -31368, -22243, 13882, 12069,
    -11242, -7729, -10226, 1761, -27298, -4800, -17737, -22805, -3528, 65, 10770, 8908, -23751,
    26934, 21921, -27010, -21944, 8889, -1035, 23224, -9488, -5823, -994, -20206, 7655, -16251,
    -22820, -27740, 15822, 23078, 13803, -8099, 2931, 9217, -21126, -14203, 25492, -12831, 7947,
    17463, -12979, 29003, 31612, 26554, 8241, -20175,
];

/// Forward, in-place, bit-reversed NTT.
pub fn forward(coefficients: &mut [i32; N]) {
    let mut k = 0_usize;
    let mut length = N / 2;

    while length > 0 {
        let mut start = 0_usize;

        while start < N {
            k += 1;
            let zeta = ZETAS[k];
            let end = start + length;

            for index in start..end {
                let t =
                    montgomery_reduce(i64::from(zeta) * i64::from(coefficients[index + length]));

                let u = coefficients[index];
                coefficients[index + length] = u - t;
                coefficients[index] = u + t;
            }

            start = end + length;
        }

        length >>= 1;
    }

    debug_assert_eq!(k, N - 1);
}

/// Inverse NTT with Montgomery-domain output scaling.
pub fn inverse_to_mont(coefficients: &mut [i32; N]) {
    const F: i32 = -29_720;

    let mut k = N;
    let mut length = 1_usize;

    while length < N {
        let mut start = 0_usize;

        while start < N {
            k -= 1;
            let zeta = -ZETAS[k];
            let end = start + length;

            for index in start..end {
                let t = coefficients[index];
                let v = coefficients[index + length];

                coefficients[index] = t + v;
                coefficients[index + length] =
                    montgomery_reduce(i64::from(zeta) * i64::from(t - v));
            }

            start = end + length;
        }

        length <<= 1;
    }

    debug_assert_eq!(k, 1);

    for coefficient in coefficients {
        *coefficient = montgomery_reduce(i64::from(F) * i64::from(*coefficient));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::reduce;
    use crate::montgomery::MONT;

    #[test]
    fn zero_polynomial_round_trip() {
        let mut coefficients = [0_i32; N];

        forward(&mut coefficients);
        inverse_to_mont(&mut coefficients);

        assert!(coefficients.iter().all(|&x| x == 0));
    }

    #[test]
    fn unit_polynomial_round_trip() {
        let mut coefficients = [0_i32; N];
        coefficients[0] = 1;

        forward(&mut coefficients);
        inverse_to_mont(&mut coefficients);

        assert_eq!(reduce(i64::from(coefficients[0])), MONT);

        for coefficient in &coefficients[1..] {
            assert_eq!(reduce(i64::from(*coefficient)), 0);
        }
    }

    #[test]
    fn deterministic_polynomial_round_trip() {
        let mut state = 0x1234_5678_u32;

        for _ in 0..32 {
            let mut coefficients = [0_i32; N];

            for coefficient in &mut coefficients {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;

                *coefficient = (state % 64513) as i32 - 32256;
            }

            let original = coefficients;

            forward(&mut coefficients);
            inverse_to_mont(&mut coefficients);

            for (actual, expected) in coefficients.iter().zip(original.iter()) {
                assert_eq!(
                    reduce(i64::from(*actual)),
                    reduce(i64::from(*expected) * i64::from(MONT)),
                );
            }
        }
    }
}

// H1.0-D.6c: independent negacyclic multiplication tests
#[cfg(test)]
mod multiplication_tests {
    use super::{forward, inverse_to_mont};
    use crate::montgomery::montgomery_reduce;
    use crate::params::{N, Q};

    fn canonical(x: i64) -> i32 {
        x.rem_euclid(i64::from(Q)) as i32
    }

    // Independent O(N^2) oracle in Z_q[X]/(X^N + 1).
    fn schoolbook(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
        let mut accum = [0_i64; N];

        for (i, &ai) in a.iter().enumerate() {
            for (j, &bj) in b.iter().enumerate() {
                let product = i64::from(ai) * i64::from(bj);
                let index = i + j;

                if index < N {
                    accum[index] += product;
                } else {
                    accum[index - N] -= product;
                }
            }
        }

        accum.map(canonical)
    }

    fn ntt_product(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
        let mut left = *a;
        let mut right = *b;

        forward(&mut left);
        forward(&mut right);

        let mut product = [0_i32; N];

        for i in 0..N {
            product[i] = montgomery_reduce(i64::from(left[i]) * i64::from(right[i]));
        }

        inverse_to_mont(&mut product);
        product.map(|x| canonical(i64::from(x)))
    }

    fn check(a: &[i32; N], b: &[i32; N]) {
        let expected = schoolbook(a, b);
        let actual = ntt_product(a, b);

        assert_eq!(actual, expected);
    }

    #[test]
    fn zero_and_identity() {
        let zero = [0_i32; N];

        let mut one = [0_i32; N];
        one[0] = 1;

        let mut dense = [0_i32; N];
        for (i, x) in dense.iter_mut().enumerate() {
            *x = (i as i32 * 251).rem_euclid(Q);
        }

        check(&zero, &dense);
        check(&one, &dense);
        check(&dense, &one);
    }

    #[test]
    fn negacyclic_wraparound() {
        let mut a = [0_i32; N];
        let mut b = [0_i32; N];

        a[N - 1] = 1;
        b[1] = 1;

        let result = ntt_product(&a, &b);

        assert_eq!(result[0], Q - 1);
        assert!(result[1..].iter().all(|&x| x == 0));

        check(&a, &b);
    }

    #[test]
    fn monomial_products() {
        for &i in &[0, 1, 63, 127, 128, 255] {
            for &j in &[0, 1, 64, 128, 255] {
                let mut a = [0_i32; N];
                let mut b = [0_i32; N];

                a[i] = 7;
                b[j] = -11;

                check(&a, &b);
            }
        }
    }

    #[test]
    fn deterministic_dense_products() {
        let mut state = 0x9e37_79b9_u32;

        for _ in 0..16 {
            let mut a = [0_i32; N];
            let mut b = [0_i32; N];

            for x in a.iter_mut().chain(b.iter_mut()) {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;

                *x = (state % (Q as u32)) as i32;
            }

            check(&a, &b);
        }
    }
}
