//! ML-DSA sparse challenge sampling.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::constants::N;
use crate::poly::Poly;

/// Seed length used by `SampleInBall`.
pub const CHALLENGE_SEED_BYTES: usize = 32;

/// Error returned by sparse challenge sampling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeError {
    /// The requested challenge weight is not supported.
    InvalidTau,
}

/// Sample a sparse challenge polynomial.
///
/// The resulting polynomial has exactly `tau` nonzero coefficients, each
/// equal to `-1` or `1`.
pub fn sample_in_ball(
    seed: &[u8; CHALLENGE_SEED_BYTES],
    tau: usize,
) -> Result<Poly, ChallengeError> {
    if tau == 0 || tau > 64 || tau > N {
        return Err(ChallengeError::InvalidTau);
    }

    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    let mut sign_bytes = [0_u8; 8];
    reader.read(&mut sign_bytes);
    let mut signs = u64::from_le_bytes(sign_bytes);

    let mut coefficients = [0_i32; N];

    for index in (N - tau)..N {
        let position = loop {
            let mut byte = [0_u8; 1];
            reader.read(&mut byte);
            let candidate = usize::from(byte[0]);

            if candidate <= index {
                break candidate;
            }
        };

        coefficients[index] = coefficients[position];
        coefficients[position] = if signs & 1 == 0 { 1 } else { -1 };
        signs >>= 1;
    }

    Ok(Poly::from_coeffs(coefficients))
}

/// Return the Hamming weight of a sparse challenge polynomial.
pub fn challenge_weight(polynomial: &Poly) -> usize {
    polynomial
        .coeffs()
        .iter()
        .filter(|coefficient| **coefficient != 0)
        .count()
}

/// Return true when every coefficient is in `{ -1, 0, 1 }`.
pub fn is_sparse_signed(polynomial: &Poly) -> bool {
    polynomial
        .coeffs()
        .iter()
        .all(|coefficient| (-1..=1).contains(coefficient))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_tau_is_rejected() {
        assert!(matches!(
            sample_in_ball(&[0_u8; CHALLENGE_SEED_BYTES], 0),
            Err(ChallengeError::InvalidTau)
        ));

        assert!(matches!(
            sample_in_ball(&[0_u8; CHALLENGE_SEED_BYTES], 65),
            Err(ChallengeError::InvalidTau)
        ));
    }

    #[test]
    fn challenge_helpers_classify_sparse_polynomials() {
        let challenge = sample_in_ball(&[0x42; CHALLENGE_SEED_BYTES], 39).unwrap();
        assert_eq!(challenge_weight(&challenge), 39);
        assert!(is_sparse_signed(&challenge));
    }
}
