//! Complete deterministic ML-DSA signing loop and signature encoding.

use crate::constants::{N, Q};
use crate::encoding::{encode_z, EncodingError};
use crate::expand_a::expand_a;
use crate::params::MlDsaParameterSet;
use crate::poly::Poly;
use crate::rounding::low_bits;
use crate::signing::{prepare_signing, sample_mask_vector, SigningError, SIGNING_RANDOMNESS_BYTES};
use crate::signing_core::{
    derive_challenge, encode_w1_vector, gamma2_for, high_bits_vector, matrix_vector_product,
    vector_infinity_norm_below, SigningCoreError,
};

const MAX_SIGNING_ATTEMPTS: usize = 10_000;

/// Error returned by deterministic ML-DSA signature generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// Signing transcript preparation failed.
    Preparation,
    /// Signing arithmetic failed.
    Arithmetic,
    /// Canonical signature encoding failed.
    Encoding,
    /// The signing rejection loop exceeded its safety limit.
    RejectionLimitExceeded,
    /// A signing nonce overflowed.
    NonceOverflow,
}

impl From<SigningError> for SignatureError {
    fn from(_: SigningError) -> Self {
        Self::Preparation
    }
}

impl From<SigningCoreError> for SignatureError {
    fn from(_: SigningCoreError) -> Self {
        Self::Arithmetic
    }
}

impl From<EncodingError> for SignatureError {
    fn from(_: EncodingError) -> Self {
        Self::Encoding
    }
}

/// Generate an ML-DSA signature deterministically from explicit randomness.
///
/// Passing an all-zero `randomness` value gives the deterministic signing
/// variant. Passing fresh 32-byte randomness gives the hedged variant.
pub fn sign_internal(
    parameter_set: MlDsaParameterSet,
    encoded_private_key: &[u8],
    message: &[u8],
    context: &[u8],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
) -> Result<Vec<u8>, SignatureError> {
    let parameters = parameter_set.parameters();
    let beta = parameters.tau as i32 * parameters.eta;
    let gamma2 = gamma2_for(parameter_set);

    let preparation = prepare_signing(
        parameter_set,
        encoded_private_key,
        message,
        context,
        randomness,
    )?;

    let matrix = expand_a(preparation.private_key().rho(), parameter_set)
        .map_err(|_| SignatureError::Arithmetic)?;

    let mut kappa = 0_u16;

    for _ in 0..MAX_SIGNING_ATTEMPTS {
        let y = sample_mask_vector(
            preparation.rho_double_prime(),
            kappa,
            parameters.l,
            parameters.gamma1,
        )?;

        kappa = kappa
            .checked_add(u16::try_from(parameters.l).map_err(|_| SignatureError::NonceOverflow)?)
            .ok_or(SignatureError::NonceOverflow)?;

        let w = matrix_vector_product(&matrix, &y)?;
        let w1 = high_bits_vector(&w, gamma2);
        let encoded_w1 = encode_w1_vector(&w1, gamma2)?;
        let (challenge_seed, challenge) =
            derive_challenge(parameter_set, preparation.mu(), &encoded_w1)?;

        let challenge_s1 =
            multiply_challenge_vector_centered(&challenge, preparation.private_key().s1());
        let z = add_centered_vectors(&y, &challenge_s1)?;

        if !vector_infinity_norm_below(&z, parameters.gamma1 - beta) {
            continue;
        }

        let w0 = low_bits_vector(&w, gamma2);
        let challenge_s2 =
            multiply_challenge_vector_centered(&challenge, preparation.private_key().s2());
        let r0 = subtract_centered_vectors(&w0, &challenge_s2)?;

        if !vector_infinity_norm_below(&r0, parameters.gamma2 - beta) {
            continue;
        }

        let challenge_t0 =
            multiply_challenge_vector_centered(&challenge, preparation.private_key().t0());

        if !vector_infinity_norm_below(&challenge_t0, parameters.gamma2) {
            continue;
        }

        let hint_reference =
            add_ring_vectors(&subtract_ring_vectors(&w, &challenge_s2)?, &challenge_t0)?;
        let negative_challenge_t0 = negate_centered_vector(&challenge_t0);
        let (hints, hint_weight) =
            crate::signing_core::make_hint_vector(&negative_challenge_t0, &hint_reference, gamma2)?;

        if hint_weight > parameters.omega {
            continue;
        }

        let signature = encode_signature(parameter_set, &challenge_seed, &z, &hints)?;

        if signature.len() != parameters.signature_bytes {
            return Err(SignatureError::Encoding);
        }

        return Ok(signature);
    }

    Err(SignatureError::RejectionLimitExceeded)
}

/// Encode `sigma = c_tilde || z || h`.
pub fn encode_signature(
    parameter_set: MlDsaParameterSet,
    challenge_seed: &[u8],
    z: &[Poly],
    hints: &[Poly],
) -> Result<Vec<u8>, SignatureError> {
    let parameters = parameter_set.parameters();
    let expected_challenge_bytes = crate::signing_core::challenge_seed_bytes(parameter_set);

    if challenge_seed.len() != expected_challenge_bytes
        || z.len() != parameters.l
        || hints.len() != parameters.k
    {
        return Err(SignatureError::Encoding);
    }

    let mut output = Vec::with_capacity(parameters.signature_bytes);
    output.extend_from_slice(challenge_seed);

    for polynomial in z {
        output.extend_from_slice(&encode_z(polynomial, parameters.gamma1)?);
    }

    output.extend_from_slice(&encode_hint_vector(hints, parameters.omega)?);
    Ok(output)
}

/// Encode the sparse hint vector using the canonical ML-DSA layout.
pub fn encode_hint_vector(hints: &[Poly], omega: usize) -> Result<Vec<u8>, SignatureError> {
    let mut output = vec![0_u8; omega + hints.len()];
    let mut offset = 0_usize;

    for (row, polynomial) in hints.iter().enumerate() {
        for (index, coefficient) in polynomial.coeffs().iter().enumerate() {
            match *coefficient {
                0 => {}
                1 => {
                    if offset >= omega {
                        return Err(SignatureError::Encoding);
                    }
                    output[offset] = u8::try_from(index).map_err(|_| SignatureError::Encoding)?;
                    offset += 1;
                }
                _ => return Err(SignatureError::Encoding),
            }
        }

        output[omega + row] = u8::try_from(offset).map_err(|_| SignatureError::Encoding)?;
    }

    Ok(output)
}

fn low_bits_vector(vector: &[Poly], gamma2: crate::rounding::Gamma2) -> Vec<Poly> {
    vector
        .iter()
        .map(|polynomial| {
            let mut coefficients = [0_i32; N];

            for (output, coefficient) in coefficients.iter_mut().zip(polynomial.coeffs()) {
                *output = low_bits(*coefficient, gamma2);
            }

            Poly::from_coeffs(coefficients)
        })
        .collect()
}

fn multiply_challenge_vector_centered(challenge: &Poly, vector: &[Poly]) -> Vec<Poly> {
    vector
        .iter()
        .map(|polynomial| multiply_challenge_centered(challenge, polynomial))
        .collect()
}

fn multiply_challenge_centered(challenge: &Poly, polynomial: &Poly) -> Poly {
    let mut output = [0_i64; N];

    for (challenge_index, challenge_coefficient) in challenge.coeffs().iter().enumerate() {
        if *challenge_coefficient == 0 {
            continue;
        }

        for (polynomial_index, polynomial_coefficient) in polynomial.coeffs().iter().enumerate() {
            let product =
                i64::from(*challenge_coefficient) * i64::from(centered(*polynomial_coefficient));
            let degree = challenge_index + polynomial_index;

            if degree < N {
                output[degree] += product;
            } else {
                output[degree - N] -= product;
            }
        }
    }

    let mut coefficients = [0_i32; N];
    for (coefficient, value) in coefficients.iter_mut().zip(output) {
        *coefficient = value as i32;
    }

    Poly::from_coeffs(coefficients)
}

fn add_centered_vectors(left: &[Poly], right: &[Poly]) -> Result<Vec<Poly>, SignatureError> {
    combine_centered_vectors(left, right, false)
}

fn subtract_centered_vectors(left: &[Poly], right: &[Poly]) -> Result<Vec<Poly>, SignatureError> {
    combine_centered_vectors(left, right, true)
}

fn combine_centered_vectors(
    left: &[Poly],
    right: &[Poly],
    subtract: bool,
) -> Result<Vec<Poly>, SignatureError> {
    if left.len() != right.len() {
        return Err(SignatureError::Arithmetic);
    }

    let mut output = Vec::with_capacity(left.len());

    for (left_poly, right_poly) in left.iter().zip(right) {
        let mut coefficients = [0_i32; N];

        for ((result, left_coefficient), right_coefficient) in coefficients
            .iter_mut()
            .zip(left_poly.coeffs())
            .zip(right_poly.coeffs())
        {
            let right_value = centered(*right_coefficient);
            *result = if subtract {
                centered(*left_coefficient) - right_value
            } else {
                centered(*left_coefficient) + right_value
            };
        }

        output.push(Poly::from_coeffs(coefficients));
    }

    Ok(output)
}

fn subtract_ring_vectors(left: &[Poly], right: &[Poly]) -> Result<Vec<Poly>, SignatureError> {
    combine_ring_vectors(left, right, true)
}

fn add_ring_vectors(left: &[Poly], right: &[Poly]) -> Result<Vec<Poly>, SignatureError> {
    combine_ring_vectors(left, right, false)
}

fn combine_ring_vectors(
    left: &[Poly],
    right: &[Poly],
    subtract: bool,
) -> Result<Vec<Poly>, SignatureError> {
    if left.len() != right.len() {
        return Err(SignatureError::Arithmetic);
    }

    let mut output = Vec::with_capacity(left.len());

    for (left_poly, right_poly) in left.iter().zip(right) {
        let mut coefficients = [0_i32; N];

        for ((result, left_coefficient), right_coefficient) in coefficients
            .iter_mut()
            .zip(left_poly.coeffs())
            .zip(right_poly.coeffs())
        {
            let value = if subtract {
                i64::from(*left_coefficient) - i64::from(centered(*right_coefficient))
            } else {
                i64::from(*left_coefficient) + i64::from(centered(*right_coefficient))
            };
            *result = value.rem_euclid(i64::from(Q)) as i32;
        }

        output.push(Poly::from_coeffs(coefficients));
    }

    Ok(output)
}

fn negate_centered_vector(vector: &[Poly]) -> Vec<Poly> {
    vector
        .iter()
        .map(|polynomial| {
            let mut coefficients = [0_i32; N];

            for (output, coefficient) in coefficients.iter_mut().zip(polynomial.coeffs()) {
                *output = -centered(*coefficient);
            }

            Poly::from_coeffs(coefficients)
        })
        .collect()
}

#[inline]
fn centered(value: i32) -> i32 {
    let canonical = value.rem_euclid(Q);
    if canonical > Q / 2 {
        canonical - Q
    } else {
        canonical
    }
}
