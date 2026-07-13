//! Number-theoretic transform for ML-DSA polynomials.

use crate::constants::ZETAS;
use crate::reduce::montgomery_reduce;

/// Apply the forward NTT in place.
pub fn forward(coefficients: &mut [i32; 256]) {
    let mut k = 0_usize;
    let mut length = 128_usize;

    while length > 0 {
        let mut start = 0_usize;

        while start < 256 {
            k += 1;
            let zeta = ZETAS[k];
            let end = start + length;

            for index in start..end {
                let t =
                    montgomery_reduce(i64::from(zeta) * i64::from(coefficients[index + length]));
                coefficients[index + length] = coefficients[index] - t;
                coefficients[index] += t;
            }

            start = end + length;
        }

        length >>= 1;
    }
}

/// Apply the inverse NTT and Montgomery scaling in place.
pub fn inverse_to_mont(coefficients: &mut [i32; 256]) {
    const F: i32 = 41_978;

    let mut k = 256_usize;
    let mut length = 1_usize;

    while length < 256 {
        let mut start = 0_usize;

        while start < 256 {
            k -= 1;
            let zeta = -ZETAS[k];
            let end = start + length;

            for index in start..end {
                let t = coefficients[index];
                coefficients[index] = t + coefficients[index + length];
                coefficients[index + length] = t - coefficients[index + length];
                coefficients[index + length] =
                    montgomery_reduce(i64::from(zeta) * i64::from(coefficients[index + length]));
            }

            start = end + length;
        }

        length <<= 1;
    }

    for coefficient in coefficients {
        *coefficient = montgomery_reduce(i64::from(F) * i64::from(*coefficient));
    }
}
