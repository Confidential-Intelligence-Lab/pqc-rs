//! ML-DSA bounded secret sampling.
//!
//! This module implements the bounded-polynomial sampler used by `ExpandS`.
//! Coefficients are sampled uniformly from `[-eta, eta]` for `eta` equal to
//! 2 or 4.

use crate::constants::N;
use crate::poly::Poly;
use crate::xof::{ExpandSReader, RHO_PRIME_BYTES};

const BUFFER_BYTES: usize = 168;

/// Error returned by bounded sampling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SamplingError {
    /// The requested `eta` value is not defined by ML-DSA.
    UnsupportedEta,
    /// The requested polynomial vector exceeds the 16-bit nonce space.
    NonceOverflow,
}

/// Sample one polynomial with coefficients in `[-eta, eta]`.
///
/// The output is deterministic for a fixed seed, nonce, and `eta`.
pub fn sample_eta_poly(
    rho_prime: &[u8; RHO_PRIME_BYTES],
    nonce: u16,
    eta: i32,
) -> Result<Poly, SamplingError> {
    if eta != 2 && eta != 4 {
        return Err(SamplingError::UnsupportedEta);
    }

    let mut reader = ExpandSReader::new(rho_prime, nonce);
    let mut coefficients = [0_i32; N];
    let mut filled = 0_usize;
    let mut buffer = [0_u8; BUFFER_BYTES];

    while filled < N {
        reader.read(&mut buffer);

        for byte in buffer {
            let low = byte & 0x0f;
            let high = byte >> 4;

            if let Some(coefficient) = decode_eta_nibble(low, eta) {
                coefficients[filled] = coefficient;
                filled += 1;

                if filled == N {
                    break;
                }
            }

            if let Some(coefficient) = decode_eta_nibble(high, eta) {
                coefficients[filled] = coefficient;
                filled += 1;

                if filled == N {
                    break;
                }
            }
        }
    }

    Ok(Poly::from_coeffs(coefficients))
}

/// Sample a deterministic vector of bounded secret polynomials.
///
/// Nonces are assigned consecutively starting at `nonce_start`.
pub fn sample_eta_polyvec(
    rho_prime: &[u8; RHO_PRIME_BYTES],
    nonce_start: u16,
    length: usize,
    eta: i32,
) -> Result<Vec<Poly>, SamplingError> {
    let available_nonces = usize::from(u16::MAX - nonce_start) + 1;
    if length > available_nonces {
        return Err(SamplingError::NonceOverflow);
    }

    let mut output = Vec::with_capacity(length);

    for index in 0..length {
        let index = u16::try_from(index).map_err(|_| SamplingError::NonceOverflow)?;
        let nonce = nonce_start
            .checked_add(index)
            .ok_or(SamplingError::NonceOverflow)?;
        output.push(sample_eta_poly(rho_prime, nonce, eta)?);
    }

    Ok(output)
}

#[inline]
fn decode_eta_nibble(value: u8, eta: i32) -> Option<i32> {
    match eta {
        2 => {
            if value >= 15 {
                return None;
            }

            // Exact reduction modulo 5 for values in 0..15.
            let reduced = value.wrapping_sub(((205_u16 * u16::from(value)) >> 10) as u8 * 5);
            Some(2 - i32::from(reduced))
        }
        4 => {
            if value < 9 {
                Some(4 - i32::from(value))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eta2_nibble_decoding_matches_expected_values() {
        let expected = [
            Some(2),
            Some(1),
            Some(0),
            Some(-1),
            Some(-2),
            Some(2),
            Some(1),
            Some(0),
            Some(-1),
            Some(-2),
            Some(2),
            Some(1),
            Some(0),
            Some(-1),
            Some(-2),
            None,
        ];

        for (value, expected_value) in expected.into_iter().enumerate() {
            assert_eq!(decode_eta_nibble(value as u8, 2), expected_value);
        }
    }

    #[test]
    fn eta4_nibble_decoding_matches_expected_values() {
        for value in 0_u8..=8 {
            assert_eq!(decode_eta_nibble(value, 4), Some(4 - i32::from(value)));
        }

        for value in 9_u8..=15 {
            assert_eq!(decode_eta_nibble(value, 4), None);
        }
    }

    #[test]
    fn unsupported_eta_is_rejected() {
        assert!(matches!(
            sample_eta_poly(&[0_u8; RHO_PRIME_BYTES], 0, 3),
            Err(SamplingError::UnsupportedEta)
        ));
    }

    #[test]
    fn vector_nonce_overflow_is_reported() {
        assert!(matches!(
            sample_eta_polyvec(&[0_u8; RHO_PRIME_BYTES], u16::MAX, 2, 2),
            Err(SamplingError::NonceOverflow)
        ));
    }
}
