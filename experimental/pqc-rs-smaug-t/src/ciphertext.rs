//! SMAUG-T IND-CPA ciphertext component construction.
//!
//! Experimental implementation. Not a complete encryption API.

use crate::arithmetic::{matrix_vec_mult_add_scaled, vec_vec_mult_add_scaled};
use crate::{Parameters, Polynomial, N};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiphertextError {
    InvalidParameters,
    InvalidDimensions,
    InvalidMatrixCoefficient,
    InvalidEphemeralCoefficient,
    InvalidPublicCoefficient,
    InvalidMessageLength,
}

/// Compute the reference C1 component:
///
/// ```text
/// C1 = Round1(A^T * r)
/// ```
///
/// The transpose follows the stored-matrix convention in the C reference.
pub fn compute_c1(
    matrix: &[Vec<Polynomial>],
    ephemeral: &[[i16; N]],
    parameters: &Parameters,
) -> Result<Vec<Polynomial>, CiphertextError> {
    let k = parameters.k;

    if !matches!(
        (k, parameters.q, parameters.p, parameters.p_prime),
        (2, 1024, 256, 32) | (3, 2048, 512, 16) | (4, 2048, 512, 128) | (2, 1024, 256, 8)
    ) {
        return Err(CiphertextError::InvalidParameters);
    }

    if matrix.len() != k || matrix.iter().any(|row| row.len() != k) || ephemeral.len() != k {
        return Err(CiphertextError::InvalidDimensions);
    }

    if matrix
        .iter()
        .flatten()
        .flat_map(|poly| poly.coefficients.iter())
        .any(|&value| value >= parameters.q)
    {
        return Err(CiphertextError::InvalidMatrixCoefficient);
    }

    if ephemeral
        .iter()
        .flatten()
        .any(|&value| !(-1..=1).contains(&value))
    {
        return Err(CiphertextError::InvalidEphemeralCoefficient);
    }

    match k {
        2 => compute_c1_fixed::<2>(matrix, ephemeral, parameters),
        3 => compute_c1_fixed::<3>(matrix, ephemeral, parameters),
        4 => compute_c1_fixed::<4>(matrix, ephemeral, parameters),
        _ => Err(CiphertextError::InvalidParameters),
    }
}

fn compute_c1_fixed<const K: usize>(
    matrix: &[Vec<Polynomial>],
    ephemeral: &[[i16; N]],
    parameters: &Parameters,
) -> Result<Vec<Polynomial>, CiphertextError> {
    let shift = 16 - parameters.q.trailing_zeros();
    let round_shift = 16 - parameters.p.trailing_zeros();
    let round_add = 1u16 << (round_shift - 1);
    let round_mask = u16::MAX << round_shift;

    let mut scaled_matrix = [[[0u16; N]; K]; K];
    let mut secret = [[0u16; N]; K];
    let mut output = [[0u16; N]; K];

    for row in 0..K {
        for column in 0..K {
            for i in 0..N {
                scaled_matrix[row][column][i] =
                    matrix[row][column].coefficients[i].wrapping_shl(shift);
            }
        }

        for i in 0..N {
            secret[row][i] = ephemeral[row][i] as u16;
        }
    }

    matrix_vec_mult_add_scaled(&mut output, &scaled_matrix, &secret, shift);

    Ok(output
        .into_iter()
        .map(|poly| Polynomial {
            coefficients: poly
                .map(|value| (value.wrapping_add(round_add) & round_mask) >> round_shift),
        })
        .collect())
}

/// Compute the reference C2 ciphertext component.
///
/// The message is encoded into a scaled 16-bit polynomial,
/// then the public-vector/ephemeral-vector product is accumulated
/// before rounding to p_prime.
///
/// TiMER uses duplicated message bits with amplitude 32767.
pub fn compute_c2(
    public_vector: &[Polynomial],
    ephemeral: &[[i16; N]],
    message: &[u8],
    parameters: &Parameters,
) -> Result<Polynomial, CiphertextError> {
    let (k, message_len) = match (parameters.k, parameters.q, parameters.p, parameters.p_prime) {
        (2, 1024, 256, 32) => (2, 32),
        (3, 2048, 512, 16) => (3, 32),
        (4, 2048, 512, 128) => (4, 32),
        (2, 1024, 256, 8) => (2, 16),
        _ => return Err(CiphertextError::InvalidParameters),
    };

    if public_vector.len() != k || ephemeral.len() != k {
        return Err(CiphertextError::InvalidDimensions);
    }

    if message.len() != message_len {
        return Err(CiphertextError::InvalidMessageLength);
    }

    if public_vector
        .iter()
        .flat_map(|poly| poly.coefficients.iter())
        .any(|&value| value >= parameters.q)
    {
        return Err(CiphertextError::InvalidPublicCoefficient);
    }

    if ephemeral
        .iter()
        .flatten()
        .any(|&value| !(-1..=1).contains(&value))
    {
        return Err(CiphertextError::InvalidEphemeralCoefficient);
    }

    match k {
        2 => compute_c2_fixed::<2>(public_vector, ephemeral, message, parameters),
        3 => compute_c2_fixed::<3>(public_vector, ephemeral, message, parameters),
        4 => compute_c2_fixed::<4>(public_vector, ephemeral, message, parameters),
        _ => Err(CiphertextError::InvalidParameters),
    }
}

fn compute_c2_fixed<const K: usize>(
    public_vector: &[Polynomial],
    ephemeral: &[[i16; N]],
    message: &[u8],
    parameters: &Parameters,
) -> Result<Polynomial, CiphertextError> {
    let shift = 16 - parameters.q.trailing_zeros();
    let round_shift = 16 - parameters.p_prime.trailing_zeros();
    let round_add = 1u16 << (round_shift - 1);
    let round_mask = u16::MAX << round_shift;

    let mut accumulator = [0u16; N];

    let timer = message.len() == 16;
    let amplitude = if timer { 32767u16 } else { 32768u16 };

    for (byte_index, &byte) in message.iter().enumerate() {
        for bit_index in 0..8 {
            let index = 8 * byte_index + bit_index;
            let bit = (byte >> bit_index) & 1;
            let encoded = amplitude.wrapping_mul(u16::from(bit));

            accumulator[index] = encoded;

            if timer {
                accumulator[index + 128] = encoded;
            }
        }
    }

    let mut scaled_public = [[0u16; N]; K];
    let mut secret = [[0u16; N]; K];

    for i in 0..K {
        for j in 0..N {
            scaled_public[i][j] = public_vector[i].coefficients[j].wrapping_shl(shift);
            secret[i][j] = ephemeral[i][j] as u16;
        }
    }

    vec_vec_mult_add_scaled(&mut accumulator, &scaled_public, &secret, shift);

    Ok(Polynomial {
        coefficients: accumulator
            .map(|value| (value.wrapping_add(round_add) & round_mask) >> round_shift),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER};

    // S4.3d.4: C2 component unit tests.

    #[test]
    fn c2_zero_message_and_ephemeral_produce_zero() {
        for parameters in [SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER] {
            let public = vec![Polynomial::zero(); parameters.k];
            let ephemeral = vec![[0i16; N]; parameters.k];
            let message_len = if parameters.p_prime == 8 { 16 } else { 32 };
            let message = vec![0u8; message_len];

            let c2 = compute_c2(&public, &ephemeral, &message, &parameters).unwrap();

            assert!(c2.coefficients.iter().all(|&value| value == 0));
        }
    }

    #[test]
    fn c2_message_bit_encoding_all_modes() {
        for parameters in [SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER] {
            let public = vec![Polynomial::zero(); parameters.k];
            let ephemeral = vec![[0i16; N]; parameters.k];
            let message_len = if parameters.p_prime == 8 { 16 } else { 32 };
            let mut message = vec![0u8; message_len];

            message[0] = 0b1000_0001;

            let c2 = compute_c2(&public, &ephemeral, &message, &parameters).unwrap();

            let expected = parameters.p_prime / 2;

            assert_eq!(c2.coefficients[0], expected);
            assert_eq!(c2.coefficients[7], expected);
            assert_eq!(c2.coefficients[1], 0);

            if parameters.p_prime == 8 {
                assert_eq!(c2.coefficients[128], expected);
                assert_eq!(c2.coefficients[135], expected);
                assert_eq!(c2.coefficients[129], 0);
            } else {
                assert_eq!(c2.coefficients[128], 0);
                assert_eq!(c2.coefficients[135], 0);
            }
        }
    }

    #[test]
    fn c2_accumulates_public_vector_product() {
        let parameters = SMAUG_T128;
        let mut public = vec![Polynomial::zero(); parameters.k];
        let mut ephemeral = vec![[0i16; N]; parameters.k];

        public[0].coefficients[0] = 8;
        ephemeral[0][0] = 1;

        let message = [0u8; 32];

        let c2 = compute_c2(&public, &ephemeral, &message, &parameters).unwrap();

        assert_eq!(c2.coefficients[0], 0);
        assert!(c2.coefficients.iter().all(|&value| value == 0));

        public[0].coefficients[0] = 32;

        let c2 = compute_c2(&public, &ephemeral, &message, &parameters).unwrap();

        assert_eq!(c2.coefficients[0], 1);
    }

    #[test]
    fn c2_rejects_invalid_inputs() {
        let parameters = SMAUG_T128;
        let public = vec![Polynomial::zero(); parameters.k];
        let ephemeral = vec![[0i16; N]; parameters.k];
        let message = [0u8; 32];

        assert_eq!(
            compute_c2(&public[..1], &ephemeral, &message, &parameters),
            Err(CiphertextError::InvalidDimensions)
        );

        assert_eq!(
            compute_c2(&public, &ephemeral, &message[..16], &parameters),
            Err(CiphertextError::InvalidMessageLength)
        );

        let mut invalid_public = public.clone();
        invalid_public[0].coefficients[0] = parameters.q;

        assert_eq!(
            compute_c2(&invalid_public, &ephemeral, &message, &parameters),
            Err(CiphertextError::InvalidPublicCoefficient)
        );

        let mut invalid_ephemeral = ephemeral.clone();
        invalid_ephemeral[0][0] = 2;

        assert_eq!(
            compute_c2(&public, &invalid_ephemeral, &message, &parameters),
            Err(CiphertextError::InvalidEphemeralCoefficient)
        );
    }

    #[test]
    fn c2_output_coefficients_are_canonical() {
        for parameters in [SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER] {
            let mut public = vec![Polynomial::zero(); parameters.k];
            let mut ephemeral = vec![[0i16; N]; parameters.k];
            let message_len = if parameters.p_prime == 8 { 16 } else { 32 };

            for (i, poly) in public.iter_mut().enumerate() {
                for (j, coefficient) in poly.coefficients.iter_mut().enumerate() {
                    *coefficient = ((i * N + j) as u16) % parameters.q;
                }
            }

            for poly in &mut ephemeral {
                for (j, coefficient) in poly.iter_mut().enumerate() {
                    *coefficient = match j % 3 {
                        0 => -1,
                        1 => 0,
                        _ => 1,
                    };
                }
            }

            let message = vec![0xa5; message_len];

            let c2 = compute_c2(&public, &ephemeral, &message, &parameters).unwrap();

            assert!(c2
                .coefficients
                .iter()
                .all(|&value| value < parameters.p_prime));
        }
    }

    #[test]
    fn zero_ephemeral_produces_zero_c1() {
        for parameters in [SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER] {
            let k = parameters.k;
            let matrix = vec![vec![Polynomial::zero(); k]; k];
            let ephemeral = vec![[0i16; N]; k];

            let c1 = compute_c1(&matrix, &ephemeral, &parameters).unwrap();

            assert_eq!(c1.len(), k);
            assert!(c1.iter().all(|p| p.coefficients.iter().all(|&x| x == 0)));
        }
    }

    #[test]
    fn matrix_transpose_is_preserved() {
        let parameters = SMAUG_T128;
        let mut matrix = vec![vec![Polynomial::zero(); 2]; 2];
        let mut ephemeral = vec![[0i16; N]; 2];

        matrix[0][1].coefficients[0] = 12;
        matrix[1][0].coefficients[0] = 28;

        ephemeral[0][0] = 1;
        ephemeral[1][0] = 1;

        let c1 = compute_c1(&matrix, &ephemeral, &parameters).unwrap();

        assert_eq!(c1[0].coefficients[0], 7);
        assert_eq!(c1[1].coefficients[0], 3);
    }

    #[test]
    fn rejects_invalid_dimensions() {
        let parameters = SMAUG_T128;
        let matrix = vec![vec![Polynomial::zero(); 2]; 1];
        let ephemeral = vec![[0i16; N]; 2];

        assert_eq!(
            compute_c1(&matrix, &ephemeral, &parameters),
            Err(CiphertextError::InvalidDimensions)
        );
    }

    #[test]
    fn rejects_nonternary_ephemeral() {
        let parameters = SMAUG_T128;
        let matrix = vec![vec![Polynomial::zero(); 2]; 2];
        let mut ephemeral = vec![[0i16; N]; 2];
        ephemeral[0][0] = 2;

        assert_eq!(
            compute_c1(&matrix, &ephemeral, &parameters),
            Err(CiphertextError::InvalidEphemeralCoefficient)
        );
    }
}
