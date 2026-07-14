//! ML-DSA signing arithmetic and challenge-transcript integration.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::challenge::{sample_in_ball_bytes, ChallengeError};
use crate::constants::{N, Q};
use crate::encoding::{encode_w1, EncodingError};
use crate::expand_a::PolyMatrix;
use crate::hint::make_hint_poly;
use crate::params::MlDsaParameterSet;
use crate::poly::Poly;
use crate::rounding::{high_bits, Gamma2};
use crate::signing::MU_BYTES;

/// Error returned by signing-core operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningCoreError {
    /// Matrix and vector dimensions are inconsistent.
    InvalidDimensions,
    /// Challenge sampling failed.
    Challenge,
    /// Canonical encoding failed.
    Encoding,
}

/// Return the FIPS 204 challenge-seed length for a parameter set.
pub const fn challenge_seed_bytes(parameter_set: MlDsaParameterSet) -> usize {
    match parameter_set {
        MlDsaParameterSet::MlDsa44 => 32,
        MlDsaParameterSet::MlDsa65 => 48,
        MlDsaParameterSet::MlDsa87 => 64,
    }
}

/// Return the `gamma2` selector for a parameter set.
pub const fn gamma2_for(parameter_set: MlDsaParameterSet) -> Gamma2 {
    match parameter_set {
        MlDsaParameterSet::MlDsa44 => Gamma2::QMinusOneOver88,
        MlDsaParameterSet::MlDsa65 | MlDsaParameterSet::MlDsa87 => Gamma2::QMinusOneOver32,
    }
}

/// Derive `c_tilde = H(mu || w1_encode, lambda / 4)`.
pub fn derive_challenge_seed(
    parameter_set: MlDsaParameterSet,
    mu: &[u8; MU_BYTES],
    encoded_w1: &[u8],
) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(mu);
    hasher.update(encoded_w1);

    let mut reader = hasher.finalize_xof();
    let mut output = vec![0_u8; challenge_seed_bytes(parameter_set)];
    reader.read(&mut output);
    output
}

/// Derive the challenge seed and sparse challenge polynomial.
pub fn derive_challenge(
    parameter_set: MlDsaParameterSet,
    mu: &[u8; MU_BYTES],
    encoded_w1: &[u8],
) -> Result<(Vec<u8>, Poly), SigningCoreError> {
    let seed = derive_challenge_seed(parameter_set, mu, encoded_w1);
    let challenge = sample_in_ball_bytes(&seed, parameter_set.parameters().tau)
        .map_err(|_: ChallengeError| SigningCoreError::Challenge)?;

    Ok((seed, challenge))
}

/// Compute `A * y` where `A` is already represented in the NTT domain.
pub fn matrix_vector_product(
    matrix: &PolyMatrix,
    vector: &[Poly],
) -> Result<Vec<Poly>, SigningCoreError> {
    if matrix.columns() != vector.len() {
        return Err(SigningCoreError::InvalidDimensions);
    }

    let mut vector_hat = vector.to_vec();
    for polynomial in &mut vector_hat {
        polynomial.ntt();
    }

    let mut output = Vec::with_capacity(matrix.rows());

    for row in 0..matrix.rows() {
        let mut accumulator = Poly::zero();

        for (column, polynomial_hat) in vector_hat.iter().enumerate() {
            let matrix_entry = matrix
                .get(row, column)
                .ok_or(SigningCoreError::InvalidDimensions)?;
            let product = matrix_entry.pointwise_montgomery(polynomial_hat);
            accumulator.add_assign(&product);
        }

        accumulator.reduce();
        accumulator.inv_ntt_to_mont();
        accumulator.reduce();
        accumulator.freeze();
        output.push(accumulator);
    }

    Ok(output)
}

/// Extract high bits from each polynomial in a vector.
pub fn high_bits_vector(vector: &[Poly], gamma2: Gamma2) -> Vec<Poly> {
    vector
        .iter()
        .map(|polynomial| {
            let mut coefficients = [0_i32; N];

            for (output, coefficient) in coefficients.iter_mut().zip(polynomial.coeffs()) {
                *output = high_bits(*coefficient, gamma2);
            }

            Poly::from_coeffs(coefficients)
        })
        .collect()
}

/// Canonically encode a vector of `w1` polynomials.
pub fn encode_w1_vector(vector: &[Poly], gamma2: Gamma2) -> Result<Vec<u8>, SigningCoreError> {
    let mut output = Vec::new();

    for polynomial in vector {
        output.extend_from_slice(
            &encode_w1(polynomial, gamma2)
                .map_err(|_: EncodingError| SigningCoreError::Encoding)?,
        );
    }

    Ok(output)
}

/// Return true when the infinity norm of a polynomial is strictly below
/// `bound`.
pub fn infinity_norm_below(polynomial: &Poly, bound: i32) -> bool {
    if bound <= 0 {
        return false;
    }

    polynomial
        .coeffs()
        .iter()
        .all(|coefficient| coefficient.abs() < bound)
}

/// Return true when every polynomial in a vector has infinity norm strictly
/// below `bound`.
pub fn vector_infinity_norm_below(vector: &[Poly], bound: i32) -> bool {
    vector
        .iter()
        .all(|polynomial| infinity_norm_below(polynomial, bound))
}

/// Multiply a sparse signed challenge by a polynomial in
/// `Z_q[X] / (X^256 + 1)`.
pub fn multiply_challenge(challenge: &Poly, polynomial: &Poly) -> Poly {
    let mut output = [0_i64; N];

    for (challenge_index, challenge_coefficient) in challenge.coeffs().iter().enumerate() {
        if *challenge_coefficient == 0 {
            continue;
        }

        for (polynomial_index, polynomial_coefficient) in polynomial.coeffs().iter().enumerate() {
            let product = i64::from(*challenge_coefficient) * i64::from(*polynomial_coefficient);
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
        *coefficient = value.rem_euclid(i64::from(Q)) as i32;
    }

    Poly::from_coeffs(coefficients)
}

/// Compute `left + challenge * right` for polynomial vectors.
pub fn add_challenge_product(
    left: &[Poly],
    challenge: &Poly,
    right: &[Poly],
) -> Result<Vec<Poly>, SigningCoreError> {
    if left.len() != right.len() {
        return Err(SigningCoreError::InvalidDimensions);
    }

    let mut output = Vec::with_capacity(left.len());

    for (left_polynomial, right_polynomial) in left.iter().zip(right) {
        let mut result = left_polynomial.clone();
        let product = multiply_challenge(challenge, right_polynomial);
        result.add_assign(&product);
        result.reduce();
        result.freeze();
        output.push(result);
    }

    Ok(output)
}

/// Compute `left - challenge * right` for polynomial vectors.
pub fn subtract_challenge_product(
    left: &[Poly],
    challenge: &Poly,
    right: &[Poly],
) -> Result<Vec<Poly>, SigningCoreError> {
    if left.len() != right.len() {
        return Err(SigningCoreError::InvalidDimensions);
    }

    let mut output = Vec::with_capacity(left.len());

    for (left_polynomial, right_polynomial) in left.iter().zip(right) {
        let mut result = left_polynomial.clone();
        let product = multiply_challenge(challenge, right_polynomial);
        result.sub_assign(&product);
        result.reduce();
        result.freeze();
        output.push(result);
    }

    Ok(output)
}

/// Generate hint polynomials and return their total Hamming weight.
pub fn make_hint_vector(
    z: &[Poly],
    r: &[Poly],
    gamma2: Gamma2,
) -> Result<(Vec<Poly>, usize), SigningCoreError> {
    if z.len() != r.len() {
        return Err(SigningCoreError::InvalidDimensions);
    }

    let mut output = Vec::with_capacity(z.len());
    let mut weight = 0_usize;

    for (z_polynomial, r_polynomial) in z.iter().zip(r) {
        let (hint, polynomial_weight) = make_hint_poly(z_polynomial, r_polynomial, gamma2);
        output.push(hint);
        weight += polynomial_weight;
    }

    Ok((output, weight))
}
