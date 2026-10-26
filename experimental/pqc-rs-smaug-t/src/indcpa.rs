// SPDX-License-Identifier: MIT
//! Experimental deterministic SMAUG-T IND-CPA key generation.
//!
//! Not constant-time audited. Not suitable for production use.

use crate::arithmetic::matrix_vec_mult_sub_scaled;
use crate::encoding::{pack_secret, pack_unsigned, EncodingError};
use crate::gaussian::{gaussian_vector, GaussianError};
use crate::matrix::expand_matrix;
use crate::sampling::{
    expand_secret_vector, SecretExpansionError, SMAUG_T128_SECRET_WEIGHT, SMAUG_T192_SECRET_WEIGHT,
    SMAUG_T256_SECRET_WEIGHT, TIMER_SECRET_WEIGHT,
};
use crate::{Parameters, N, SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER};
use sha3::{digest::Digest, Sha3_512};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeypairError {
    UnsupportedParameters,
    SecretExpansion(SecretExpansionError),
    Gaussian(GaussianError),
    Encoding(EncodingError),
}

impl From<SecretExpansionError> for KeypairError {
    fn from(error: SecretExpansionError) -> Self {
        Self::SecretExpansion(error)
    }
}

impl From<GaussianError> for KeypairError {
    fn from(error: GaussianError) -> Self {
        Self::Gaussian(error)
    }
}

impl From<EncodingError> for KeypairError {
    fn from(error: EncodingError) -> Self {
        Self::Encoding(error)
    }
}

fn secret_weight(parameters: &Parameters) -> Option<usize> {
    if *parameters == SMAUG_T128 {
        Some(SMAUG_T128_SECRET_WEIGHT)
    } else if *parameters == SMAUG_T192 {
        Some(SMAUG_T192_SECRET_WEIGHT)
    } else if *parameters == SMAUG_T256 {
        Some(SMAUG_T256_SECRET_WEIGHT)
    } else if *parameters == TIMER {
        Some(TIMER_SECRET_WEIGHT)
    } else {
        None
    }
}

/// Deterministically derive an IND-CPA public/secret key pair.
///
/// The input seed is expanded with SHA3-512:
/// - bytes 0..32 seed the ternary secret and Gaussian error;
/// - bytes 32..64 seed the public matrix.
///
/// The public polynomial vector is b = e - A*s, with reference
/// 16-bit wrapping arithmetic and scaled matrix coefficients.
///
/// Returns serialized (public_key, secret_key).
pub fn keypair(
    seed: &[u8; 32],
    parameters: &Parameters,
) -> Result<(Vec<u8>, Vec<u8>), KeypairError> {
    let weight = secret_weight(parameters).ok_or(KeypairError::UnsupportedParameters)?;

    let k = parameters.k;
    let log_q = parameters.q.trailing_zeros();
    let shift = 16 - log_q;

    let digest = Sha3_512::digest(seed);
    let mut secret_seed = [0u8; 32];
    let mut matrix_seed = [0u8; 32];
    secret_seed.copy_from_slice(&digest[..32]);
    matrix_seed.copy_from_slice(&digest[32..64]);

    let secret = expand_secret_vector(&secret_seed, k, weight)?;
    let error = gaussian_vector(&secret_seed, k, log_q)?;
    let matrix = expand_matrix(&matrix_seed, parameters);

    let mut public_vector = [[0u16; N]; 4];
    let mut secret_vector = [[0u16; N]; 4];
    let mut matrix_coefficients = [[[0u16; N]; 4]; 4];

    for row in 0..k {
        public_vector[row] = error[row].map(|x| x as u16);
        secret_vector[row] = secret[row].map(|x| x as u16);

        for column in 0..k {
            matrix_coefficients[row][column] = matrix[row][column]
                .coefficients
                .map(|x| x.wrapping_shl(shift));
        }
    }

    match k {
        2 => {
            let mut out = [public_vector[0], public_vector[1]];
            let a = [
                [matrix_coefficients[0][0], matrix_coefficients[0][1]],
                [matrix_coefficients[1][0], matrix_coefficients[1][1]],
            ];
            let s = [secret_vector[0], secret_vector[1]];
            matrix_vec_mult_sub_scaled::<2>(&mut out, &a, &s, shift);
            public_vector[..2].copy_from_slice(&out);
        }
        3 => {
            let mut out = [public_vector[0], public_vector[1], public_vector[2]];
            let a = [
                [
                    matrix_coefficients[0][0],
                    matrix_coefficients[0][1],
                    matrix_coefficients[0][2],
                ],
                [
                    matrix_coefficients[1][0],
                    matrix_coefficients[1][1],
                    matrix_coefficients[1][2],
                ],
                [
                    matrix_coefficients[2][0],
                    matrix_coefficients[2][1],
                    matrix_coefficients[2][2],
                ],
            ];
            let s = [secret_vector[0], secret_vector[1], secret_vector[2]];
            matrix_vec_mult_sub_scaled::<3>(&mut out, &a, &s, shift);
            public_vector[..3].copy_from_slice(&out);
        }
        4 => {
            matrix_vec_mult_sub_scaled::<4>(
                &mut public_vector,
                &matrix_coefficients,
                &secret_vector,
                shift,
            );
        }
        _ => return Err(KeypairError::UnsupportedParameters),
    }

    let width = log_q as u8;
    let mask = parameters.q - 1;

    let mut public_key = Vec::with_capacity(32 + k * N * usize::from(width) / 8);
    public_key.extend_from_slice(&matrix_seed);

    for polynomial in public_vector.iter().take(k) {
        let canonical = polynomial.map(|x| (x >> shift) & mask);
        public_key.extend_from_slice(&pack_unsigned(&canonical, width)?);
    }

    let mut secret_key = Vec::with_capacity(k * N / 4);

    for polynomial in secret.iter().take(k) {
        secret_key.extend_from_slice(&pack_secret(polynomial)?);
    }

    Ok((public_key, secret_key))
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_keypairs_have_reference_lengths() {
        let seed = [0x42u8; 32];

        for (parameters, pk_len, sk_len) in [
            (SMAUG_T128, 672, 128),
            (SMAUG_T192, 1088, 192),
            (SMAUG_T256, 1440, 256),
            (TIMER, 672, 128),
        ] {
            let first = keypair(&seed, &parameters).unwrap();
            let second = keypair(&seed, &parameters).unwrap();

            assert_eq!(first, second);
            assert_eq!(first.0.len(), pk_len);
            assert_eq!(first.1.len(), sk_len);
        }
    }

    #[test]
    fn distinct_seeds_produce_distinct_keys() {
        let first = keypair(&[0u8; 32], &SMAUG_T128).unwrap();
        let second = keypair(&[1u8; 32], &SMAUG_T128).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn unsupported_parameters_are_rejected() {
        let invalid = Parameters {
            k: 5,
            q: 1024,
            p: 256,
            p_prime: 32,
        };

        assert_eq!(
            keypair(&[0u8; 32], &invalid),
            Err(KeypairError::UnsupportedParameters)
        );
    }
}

// S4.4b: Deterministic IND-CPA encryption.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptError {
    UnsupportedParameters,
    InvalidPublicKeyLength,
    InvalidMessageLength,
    Ephemeral(crate::ephemeral::EphemeralError),
    Ciphertext(crate::ciphertext::CiphertextError),
    Encoding(crate::encoding::EncodingError),
}

impl From<crate::ephemeral::EphemeralError> for EncryptError {
    fn from(error: crate::ephemeral::EphemeralError) -> Self {
        Self::Ephemeral(error)
    }
}

impl From<crate::ciphertext::CiphertextError> for EncryptError {
    fn from(error: crate::ciphertext::CiphertextError) -> Self {
        Self::Ciphertext(error)
    }
}

impl From<crate::encoding::EncodingError> for EncryptError {
    fn from(error: crate::encoding::EncodingError) -> Self {
        Self::Encoding(error)
    }
}

/// Deterministically encrypt an IND-CPA message using an explicit seed.
///
/// Experimental implementation; not constant-time audited.
/// Not suitable for production use.
pub fn encrypt(
    public_key: &[u8],
    message: &[u8],
    seed: &[u8; 32],
    parameters: &Parameters,
) -> Result<Vec<u8>, EncryptError> {
    if ![SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER].contains(parameters) {
        return Err(EncryptError::UnsupportedParameters);
    }

    let k = parameters.k;
    let q_width = parameters.q.trailing_zeros() as u8;
    let p_width = parameters.p.trailing_zeros() as u8;
    let p_prime_width = parameters.p_prime.trailing_zeros() as u8;

    let q_poly_bytes = crate::encoding::packed_len(q_width)?;
    let expected_public_key_bytes = 32 + k * q_poly_bytes;

    if public_key.len() != expected_public_key_bytes {
        return Err(EncryptError::InvalidPublicKeyLength);
    }

    let expected_message_bytes = if *parameters == TIMER { 16 } else { 32 };

    if message.len() != expected_message_bytes {
        return Err(EncryptError::InvalidMessageLength);
    }

    let mut matrix_seed = [0u8; 32];
    matrix_seed.copy_from_slice(&public_key[..32]);

    let matrix = crate::matrix::expand_matrix(&matrix_seed, parameters);

    let mut public_vector = Vec::with_capacity(k);

    for index in 0..k {
        let start = 32 + index * q_poly_bytes;
        let end = start + q_poly_bytes;

        let coefficients = crate::encoding::unpack_unsigned(&public_key[start..end], q_width)?;

        public_vector.push(crate::Polynomial { coefficients });
    }

    let ephemeral = crate::ephemeral::expand_r(seed, parameters)?;

    let c1 = crate::ciphertext::compute_c1(&matrix, &ephemeral, parameters)?;

    let c2 = crate::ciphertext::compute_c2(&public_vector, &ephemeral, message, parameters)?;

    let expected_ciphertext_bytes =
        k * crate::encoding::packed_len(p_width)? + crate::encoding::packed_len(p_prime_width)?;

    let mut ciphertext = Vec::with_capacity(expected_ciphertext_bytes);

    for polynomial in &c1 {
        ciphertext.extend_from_slice(&crate::encoding::pack_unsigned(
            &polynomial.coefficients,
            p_width,
        )?);
    }

    ciphertext.extend_from_slice(&crate::encoding::pack_unsigned(
        &c2.coefficients,
        p_prime_width,
    )?);

    assert_eq!(ciphertext.len(), expected_ciphertext_bytes);

    Ok(ciphertext)
}

// S4.5b: Independent IND-CPA decryption.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecryptError {
    UnsupportedParameters,
    InvalidSecretKeyLength,
    InvalidCiphertextLength,
    Encoding(crate::encoding::EncodingError),
}

impl From<crate::encoding::EncodingError> for DecryptError {
    fn from(error: crate::encoding::EncodingError) -> Self {
        Self::Encoding(error)
    }
}

/// Recover an IND-CPA message from a SMAUG-T ciphertext.
///
/// Experimental implementation; not constant-time audited.
/// Not suitable for production use.
pub fn decrypt(
    secret_key: &[u8],
    ciphertext: &[u8],
    parameters: &Parameters,
) -> Result<Vec<u8>, DecryptError> {
    if ![SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER].contains(parameters) {
        return Err(DecryptError::UnsupportedParameters);
    }

    let k = parameters.k;
    let p_width = parameters.p.trailing_zeros() as u8;
    let p_prime_width = parameters.p_prime.trailing_zeros() as u8;

    let secret_poly_bytes = 64;
    let c1_poly_bytes = crate::encoding::packed_len(p_width)?;
    let c2_poly_bytes = crate::encoding::packed_len(p_prime_width)?;

    if secret_key.len() != k * secret_poly_bytes {
        return Err(DecryptError::InvalidSecretKeyLength);
    }

    if ciphertext.len() != k * c1_poly_bytes + c2_poly_bytes {
        return Err(DecryptError::InvalidCiphertextLength);
    }

    let mut secret = Vec::with_capacity(k);
    for index in 0..k {
        let start = index * secret_poly_bytes;
        let coefficients =
            crate::encoding::unpack_secret(&secret_key[start..start + secret_poly_bytes])?;
        secret.push(coefficients.map(|value| value as u16));
    }

    let mut c1 = Vec::with_capacity(k);
    for index in 0..k {
        let start = index * c1_poly_bytes;
        let coefficients =
            crate::encoding::unpack_unsigned(&ciphertext[start..start + c1_poly_bytes], p_width)?;
        c1.push(coefficients.map(|value| value << (16 - u32::from(p_width))));
    }

    let c2_start = k * c1_poly_bytes;
    let mut delta = crate::encoding::unpack_unsigned(&ciphertext[c2_start..], p_prime_width)?
        .map(|value| value << (16 - u32::from(p_prime_width)));

    match k {
        2 => decrypt_accumulate::<2>(&mut delta, &c1, &secret, p_width),
        3 => decrypt_accumulate::<3>(&mut delta, &c1, &secret, p_width),
        4 => decrypt_accumulate::<4>(&mut delta, &c1, &secret, p_width),
        _ => unreachable!("validated parameter set"),
    }

    let message_bytes = if *parameters == TIMER { 16 } else { 32 };
    let mut message = vec![0u8; message_bytes];

    if *parameters == TIMER {
        for index in 0..128 {
            let first = timer_flipabs(delta[index]);
            let second = timer_flipabs(delta[index + 128]);
            let sum = first.wrapping_add(second);
            let decision = sum.wrapping_sub(32767) >> 15;
            message[index / 8] |= (decision as u8) << (index % 8);
        }
    } else {
        for (index, value) in delta.iter().enumerate() {
            let bit = (value.wrapping_add(0x4000) >> 15) & 1;
            message[index / 8] |= (bit as u8) << (index % 8);
        }
    }

    Ok(message)
}

fn decrypt_accumulate<const K: usize>(
    delta: &mut [u16; N],
    c1: &[[u16; N]],
    secret: &[[u16; N]],
    p_width: u8,
) {
    let c1: [[u16; N]; K] = std::array::from_fn(|i| c1[i]);
    let secret: [[u16; N]; K] = std::array::from_fn(|i| secret[i]);
    crate::arithmetic::vec_vec_mult_add_scaled(delta, &c1, &secret, 16 - u32::from(p_width));
}

fn timer_flipabs(value: u16) -> u16 {
    let signed = value.wrapping_sub(32767) as i16;
    signed.unsigned_abs()
}
