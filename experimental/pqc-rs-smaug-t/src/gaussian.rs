//! Reference-compatible SMAUG-T discrete Gaussian sampling.
//!
//! Implements the Boolean circuit in the pinned SMAUG-T 1.1.1
//! `d_gaussian_poly` reference implementation.
//!
//! Experimental: not constant-time audited.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::N;

pub const GAUSSIAN_RANDOM_BYTES: usize = 320;
pub const GAUSSIAN_RANDOM_BITS_PER_COEFFICIENT: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GaussianError {
    InvalidLogQ,
    InvalidParameters,
}

/// Expand a 33-byte seed into the reference's 320-byte SHAKE256 stream.
pub fn gaussian_randomness(extended_seed: &[u8; 33]) -> [u8; GAUSSIAN_RANDOM_BYTES] {
    let mut shake = Shake256::default();
    shake.update(extended_seed);

    let mut reader = shake.finalize_xof();
    let mut bytes = [0u8; GAUSSIAN_RANDOM_BYTES];
    reader.read(&mut bytes);
    bytes
}

/// Reproduce `d_gaussian_poly` from its expanded randomness.
///
/// `log_q` must be 10 or 11 for the supported SMAUG-T configurations.
/// Coefficients retain the reference's signed, scaled 16-bit representation.
///
/// This implementation is experimental and has not been side-channel audited.
pub fn gaussian_poly_from_randomness(
    bytes: &[u8; GAUSSIAN_RANDOM_BYTES],
    log_q: u32,
) -> Result<[i16; N], GaussianError> {
    if log_q != 10 && log_q != 11 {
        return Err(GaussianError::InvalidLogQ);
    }

    let shift = 16 - log_q;
    let mut result = [0i16; N];

    // The C reference transposes each 80-byte group into ten
    // little-endian 64-bit bit planes.
    for group in 0..(N / 64) {
        let offset = group * 80;
        let mut x = [0u64; 10];

        for (plane, word) in x.iter_mut().enumerate() {
            let mut le = [0u8; 8];

            for (byte_index, byte) in le.iter_mut().enumerate() {
                *byte = bytes[offset + byte_index * 10 + plane];
            }

            *word = u64::from_le_bytes(le);
        }

        // Exact Boolean magnitude circuit from SMAUG-T 1.1.1 dg.c.
        let s0 = (x[0] & x[1] & x[2] & x[3] & x[4] & x[5] & x[7] & !x[8])
            | (x[0] & x[3] & x[4] & x[5] & x[6] & x[8])
            | (x[1] & x[3] & x[4] & x[5] & x[6] & x[8])
            | (x[2] & x[3] & x[4] & x[5] & x[6] & x[8])
            | (!x[2] & !x[3] & !x[6] & x[8])
            | (!x[1] & !x[3] & !x[6] & x[8])
            | (x[6] & x[7] & !x[8])
            | (!x[5] & !x[6] & x[8])
            | (!x[4] & !x[6] & x[8])
            | (!x[7] & x[8]);

        let s1 = (x[1] & x[2] & x[4] & x[5] & x[7] & x[8])
            | (x[3] & x[4] & x[5] & x[7] & x[8])
            | (x[6] & x[7] & x[8]);

        for bit in 0..64 {
            let magnitude = ((s0 >> bit) & 1) | (((s1 >> bit) & 1) << 1);

            let sign = (x[9] >> bit) & 1;

            // Equivalent to the reference's two's-complement
            // sign application, without signed-shift ambiguity.
            // Apply the sign with a two's-complement mask, avoiding
            // secret-dependent source-level control flow.
            let sign_mask = 0i16.wrapping_sub(sign as i16);
            let signed = ((magnitude as i16) ^ sign_mask).wrapping_sub(sign_mask);

            result[group * 64 + bit] = signed * (1i16 << shift);
        }
    }

    Ok(result)
}

/// Sample one reference-compatible Gaussian polynomial.
///
/// `extended_seed` is the 32-byte seed followed by its domain byte.
pub fn gaussian_poly(extended_seed: &[u8; 33], log_q: u32) -> Result<[i16; N], GaussianError> {
    let randomness = gaussian_randomness(extended_seed);
    gaussian_poly_from_randomness(&randomness, log_q)
}

/// Expand a 32-byte seed into a Gaussian polynomial vector.
///
/// Matches the reference `d_gaussian` domain separation: `k * i`.
///
/// Experimental: not constant-time audited.
pub fn gaussian_vector(
    seed: &[u8; 32],
    k: usize,
    log_q: u32,
) -> Result<Vec<[i16; N]>, GaussianError> {
    if !(2..=4).contains(&k) {
        return Err(GaussianError::InvalidParameters);
    }

    if log_q != 10 && log_q != 11 {
        return Err(GaussianError::InvalidLogQ);
    }

    let mut vector = Vec::with_capacity(k);

    for i in 0..k {
        let mut extended_seed = [0u8; 33];
        extended_seed[..32].copy_from_slice(seed);
        extended_seed[32] = (k * i) as u8;

        vector.push(gaussian_poly(&extended_seed, log_q)?);
    }

    Ok(vector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gaussian_expansion_is_deterministic() {
        let seed = [0x42u8; 33];
        assert_eq!(gaussian_randomness(&seed), gaussian_randomness(&seed));
        assert_eq!(
            gaussian_poly(&seed, 10).unwrap(),
            gaussian_poly(&seed, 10).unwrap()
        );
    }

    #[test]
    fn gaussian_rejects_unsupported_moduli() {
        let seed = [0u8; 33];

        for log_q in [0, 9, 12, 16, u32::MAX] {
            assert_eq!(gaussian_poly(&seed, log_q), Err(GaussianError::InvalidLogQ));
        }
    }

    #[test]
    fn gaussian_coefficients_have_reference_scale() {
        let seed = [0xA5u8; 33];

        for (log_q, scale) in [(10, 64i16), (11, 32i16)] {
            let polynomial = gaussian_poly(&seed, log_q).unwrap();

            assert!(polynomial
                .iter()
                .all(|&c| { c % scale == 0 && (-3 * scale..=3 * scale).contains(&c) }));
        }
    }

    #[test]
    fn gaussian_sign_and_scale_follow_bit_planes() {
        let mut bytes = [0u8; GAUSSIAN_RANDOM_BYTES];

        // All-zero bit planes select magnitude 0.
        let zero = gaussian_poly_from_randomness(&bytes, 10).unwrap();
        assert!(zero.iter().all(|&c| c == 0));

        // Plane 8 set selects magnitude 1 through the !x[7] term.
        for group in 0..4 {
            bytes[group * 80 + 8] = 1;
        }

        let positive = gaussian_poly_from_randomness(&bytes, 10).unwrap();
        for group in 0..4 {
            assert_eq!(positive[group * 64], 64);
        }

        // Set sign bit for the first coefficient in each group.
        for group in 0..4 {
            bytes[group * 80 + 9] = 1;
        }

        let negative = gaussian_poly_from_randomness(&bytes, 10).unwrap();
        for group in 0..4 {
            assert_eq!(negative[group * 64], -64);
        }
    }

    #[test]
    fn gaussian_branchless_sign_matches_arithmetic() {
        for magnitude in 0i16..=3 {
            for sign in 0i16..=1 {
                let mask = 0i16.wrapping_sub(sign);
                let actual = (magnitude ^ mask).wrapping_sub(mask);
                let expected = if sign == 0 { magnitude } else { -magnitude };

                assert_eq!(actual, expected);
            }
        }
    }
}
