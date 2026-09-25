//! Complete deterministic ML-DSA signing loop and signature encoding.

use std::cell::Cell;

thread_local! {
    static SIGNING_TRACE: Cell<SigningTrace> =
        const { Cell::new(SigningTrace::new()) };
}

/// Audit counters for one ML-DSA signing operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SigningTrace {
    /// Number of rejection-loop attempts.
    pub attempts: u64,
    /// Rejections caused by the response-vector norm check.
    pub reject_z: u64,
    /// Rejections caused by the low-bits norm check.
    pub reject_r0: u64,
    /// Rejections caused by the secret `t0` product norm check.
    pub reject_ct0: u64,
    /// Rejections caused by excessive hint weight.
    pub reject_hint: u64,
}

impl SigningTrace {
    const fn new() -> Self {
        Self {
            attempts: 0,
            reject_z: 0,
            reject_r0: 0,
            reject_ct0: 0,
            reject_hint: 0,
        }
    }

    /// Return the total number of rejected attempts.
    pub const fn total_rejections(self) -> u64 {
        self.reject_z + self.reject_r0 + self.reject_ct0 + self.reject_hint
    }
}

/// Reset the thread-local signing trace.
pub fn clear_signing_trace() {
    SIGNING_TRACE.with(|trace| trace.set(SigningTrace::new()));
}

/// Read the thread-local signing trace.
pub fn signing_trace() -> SigningTrace {
    SIGNING_TRACE.with(Cell::get)
}

fn trace_attempt() {
    SIGNING_TRACE.with(|trace| {
        let mut value = trace.get();
        value.attempts += 1;
        trace.set(value);
    });
}

fn trace_reject_z() {
    SIGNING_TRACE.with(|trace| {
        let mut value = trace.get();
        value.reject_z += 1;
        trace.set(value);
    });
}

fn trace_reject_r0() {
    SIGNING_TRACE.with(|trace| {
        let mut value = trace.get();
        value.reject_r0 += 1;
        trace.set(value);
    });
}

fn trace_reject_ct0() {
    SIGNING_TRACE.with(|trace| {
        let mut value = trace.get();
        value.reject_ct0 += 1;
        trace.set(value);
    });
}

fn trace_reject_hint() {
    SIGNING_TRACE.with(|trace| {
        let mut value = trace.get();
        value.reject_hint += 1;
        trace.set(value);
    });
}

use crate::constants::{N, Q};
use crate::encoding::{encode_z, EncodingError};
use crate::expand_a::expand_a;

#[cfg(feature = "internal-api")]
use crate::expand_a::PolyMatrix;
use crate::params::MlDsaParameterSet;
use crate::poly::Poly;
use crate::rounding::low_bits;
use crate::signing::{
    prepare_internal_signing, prepare_signing, prepare_signing_from_mu, sample_mask_vector,
    SigningError, SigningPreparation, SIGNING_RANDOMNESS_BYTES,
};

#[cfg(feature = "internal-api")]
use crate::signing::{
    compute_message_representative, decode_private_key, derive_rho_double_prime, DecodedPrivateKey,
};
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
    let preparation = prepare_signing(
        parameter_set,
        encoded_private_key,
        message,
        context,
        randomness,
    )?;
    sign_prepared(parameter_set, preparation)
}

/// Generate a signature through `ML-DSA.Sign_internal` from `M'`.
pub fn sign_internal_message(
    parameter_set: MlDsaParameterSet,
    encoded_private_key: &[u8],
    message_prime: &[u8],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
) -> Result<Vec<u8>, SignatureError> {
    let preparation = prepare_internal_signing(
        parameter_set,
        encoded_private_key,
        message_prime,
        randomness,
    )?;
    sign_prepared(parameter_set, preparation)
}

/// Generate a signature through `ML-DSA.Sign_internal` from supplied `mu`.
pub fn sign_internal_mu(
    parameter_set: MlDsaParameterSet,
    encoded_private_key: &[u8],
    mu: &[u8; crate::signing::MU_BYTES],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
) -> Result<Vec<u8>, SignatureError> {
    let preparation = prepare_signing_from_mu(parameter_set, encoded_private_key, mu, randomness)?;
    sign_prepared(parameter_set, preparation)
}

/// Key-dependent ML-DSA state prepared for repeated signing.
///
/// This is exposed only through the repository `internal-api` feature for
/// performance evaluation. It is not part of the stable public API.
///
/// This type intentionally does not implement `Clone` or `Debug`.
#[cfg(feature = "internal-api")]
pub struct PreparedSigningState {
    parameter_set: MlDsaParameterSet,
    private_key: DecodedPrivateKey,
    matrix: PolyMatrix,
    s1_hat: Vec<Poly>,
    s2_hat: Vec<Poly>,
    t0_hat: Vec<Poly>,
}

/// Decode and precompute the key-dependent state used by repeated signing.
#[cfg(feature = "internal-api")]
pub fn prepare_signing_state(
    parameter_set: MlDsaParameterSet,
    encoded_private_key: &[u8],
) -> Result<PreparedSigningState, SignatureError> {
    let private_key = decode_private_key(parameter_set, encoded_private_key)?;

    let matrix =
        expand_a(private_key.rho(), parameter_set).map_err(|_| SignatureError::Arithmetic)?;

    let s1_hat = ntt_vector(private_key.s1());
    let s2_hat = ntt_vector(private_key.s2());
    let t0_hat = ntt_vector(private_key.t0());

    Ok(PreparedSigningState {
        parameter_set,
        private_key,
        matrix,
        s1_hat,
        s2_hat,
        t0_hat,
    })
}

/// Sign using previously prepared key-dependent state.
#[cfg(feature = "internal-api")]
pub fn sign_internal_with_prepared_state(
    state: &PreparedSigningState,
    message: &[u8],
    context: &[u8],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
) -> Result<Vec<u8>, SignatureError> {
    let mu = compute_message_representative(state.private_key.tr(), context, message)?;

    let rho_double_prime = derive_rho_double_prime(state.private_key.key(), randomness, &mu);

    sign_precomputed(
        state.parameter_set,
        &mu,
        &rho_double_prime,
        &state.matrix,
        &state.s1_hat,
        &state.s2_hat,
        &state.t0_hat,
    )
}

fn sign_prepared(
    parameter_set: MlDsaParameterSet,
    preparation: SigningPreparation,
) -> Result<Vec<u8>, SignatureError> {
    let matrix = expand_a(preparation.private_key().rho(), parameter_set)
        .map_err(|_| SignatureError::Arithmetic)?;

    let s1_hat = ntt_vector(preparation.private_key().s1());
    let s2_hat = ntt_vector(preparation.private_key().s2());
    let t0_hat = ntt_vector(preparation.private_key().t0());

    sign_precomputed(
        parameter_set,
        preparation.mu(),
        preparation.rho_double_prime(),
        &matrix,
        &s1_hat,
        &s2_hat,
        &t0_hat,
    )
}

fn sign_precomputed(
    parameter_set: MlDsaParameterSet,
    mu: &[u8; crate::signing::MU_BYTES],
    rho_double_prime: &[u8; crate::xof::RHO_DOUBLE_PRIME_BYTES],
    matrix: &crate::expand_a::PolyMatrix,
    s1_hat: &[Poly],
    s2_hat: &[Poly],
    t0_hat: &[Poly],
) -> Result<Vec<u8>, SignatureError> {
    let parameters = parameter_set.parameters();
    let beta = parameters.tau as i32 * parameters.eta;
    let gamma2 = gamma2_for(parameter_set);

    let mut kappa = 0_u16;

    for _ in 0..MAX_SIGNING_ATTEMPTS {
        trace_attempt();
        let y = sample_mask_vector(rho_double_prime, kappa, parameters.l, parameters.gamma1)?;

        kappa = kappa
            .checked_add(u16::try_from(parameters.l).map_err(|_| SignatureError::NonceOverflow)?)
            .ok_or(SignatureError::NonceOverflow)?;

        let w = matrix_vector_product(matrix, &y)?;
        let w1 = high_bits_vector(&w, gamma2);
        let encoded_w1 = encode_w1_vector(&w1, gamma2)?;
        let (challenge_seed, challenge) = derive_challenge(parameter_set, mu, &encoded_w1)?;

        // The same challenge is used against s1 and, for surviving
        // attempts, s2 and t0. Transform it once for this attempt.
        let mut challenge_hat = challenge.clone();
        challenge_hat.ntt();

        let challenge_s1 = multiply_challenge_vector_centered_ntt_from_hat(&challenge_hat, s1_hat);
        let z = add_centered_vectors(&y, &challenge_s1)?;

        if !vector_infinity_norm_below(&z, parameters.gamma1 - beta) {
            trace_reject_z();
            continue;
        }

        let w0 = low_bits_vector(&w, gamma2);
        let challenge_s2 = multiply_challenge_vector_centered_ntt_from_hat(&challenge_hat, s2_hat);
        let r0 = subtract_centered_vectors(&w0, &challenge_s2)?;

        if !vector_infinity_norm_below(&r0, parameters.gamma2 - beta) {
            trace_reject_r0();
            continue;
        }

        let challenge_t0 = multiply_challenge_vector_centered_ntt_from_hat(&challenge_hat, t0_hat);

        if !vector_infinity_norm_below(&challenge_t0, parameters.gamma2) {
            trace_reject_ct0();
            continue;
        }

        let hint_reference =
            add_ring_vectors(&subtract_ring_vectors(&w, &challenge_s2)?, &challenge_t0)?;
        let negative_challenge_t0 = negate_centered_vector(&challenge_t0);
        let (hints, hint_weight) =
            crate::signing_core::make_hint_vector(&negative_challenge_t0, &hint_reference, gamma2)?;

        if hint_weight > parameters.omega {
            trace_reject_hint();
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

#[cfg(test)]
fn multiply_challenge_vector_centered(challenge: &Poly, vector: &[Poly]) -> Vec<Poly> {
    vector
        .iter()
        .map(|polynomial| multiply_challenge_centered(challenge, polynomial))
        .collect()
}

#[cfg(test)]
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

fn centered_from_ntt_product(challenge_hat: &Poly, polynomial_hat: &Poly) -> Poly {
    let mut product = challenge_hat.pointwise_montgomery(polynomial_hat);

    product.inv_ntt_to_mont();
    product.reduce();
    product.freeze();

    let mut coefficients = [0_i32; N];

    for (output, coefficient) in coefficients.iter_mut().zip(product.coeffs()) {
        *output = centered(*coefficient);
    }

    Poly::from_coeffs(coefficients)
}

fn multiply_challenge_vector_centered_ntt_from_hat(
    challenge_hat: &Poly,
    vector_hat: &[Poly],
) -> Vec<Poly> {
    vector_hat
        .iter()
        .map(|polynomial_hat| centered_from_ntt_product(challenge_hat, polynomial_hat))
        .collect()
}

fn ntt_vector(vector: &[Poly]) -> Vec<Poly> {
    vector
        .iter()
        .map(|polynomial| {
            let mut polynomial_hat = polynomial.clone();
            polynomial_hat.ntt();
            polynomial_hat
        })
        .collect()
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

#[cfg(test)]
mod production_ntt_challenge_equivalence {
    use super::*;

    use crate::keygen::keygen_internal;

    #[test]
    fn production_ntt_challenge_products_match_sparse_reference() {
        let parameter_sets = [
            (MlDsaParameterSet::MlDsa44, "ML-DSA-44"),
            (MlDsaParameterSet::MlDsa65, "ML-DSA-65"),
            (MlDsaParameterSet::MlDsa87, "ML-DSA-87"),
        ];

        for (parameter_index, (parameter_set, name)) in parameter_sets.into_iter().enumerate() {
            let parameters = parameter_set.parameters();
            let gamma2 = gamma2_for(parameter_set);

            for case in 0_u8..4 {
                let seed_byte = 0x31_u8
                    .wrapping_add(parameter_index as u8 * 0x10)
                    .wrapping_add(case);

                let randomness_byte = 0x91_u8
                    .wrapping_add(parameter_index as u8 * 0x10)
                    .wrapping_add(case);

                let xi = [seed_byte; 32];
                let randomness = [randomness_byte; 32];

                let message = format!("pqc-rs O3.5 equivalence {name} case {case}");

                let key_pair = keygen_internal(parameter_set, &xi).expect("keygen");

                let preparation = prepare_signing(
                    parameter_set,
                    key_pair.private_key(),
                    message.as_bytes(),
                    b"o35-equivalence",
                    &randomness,
                )
                .expect("prepare signing");

                let matrix =
                    expand_a(preparation.private_key().rho(), parameter_set).expect("expand A");

                let s1_hat = ntt_vector(preparation.private_key().s1());

                let s2_hat = ntt_vector(preparation.private_key().s2());

                let t0_hat = ntt_vector(preparation.private_key().t0());

                let mut kappa = 0_u16;

                // Exercise many valid challenges independently of whether
                // a particular signing attempt would have been accepted.
                for challenge_index in 0..16 {
                    let y = sample_mask_vector(
                        preparation.rho_double_prime(),
                        kappa,
                        parameters.l,
                        parameters.gamma1,
                    )
                    .expect("sample y");

                    kappa = kappa
                        .checked_add(parameters.l as u16)
                        .expect("kappa overflow");

                    let w = matrix_vector_product(&matrix, &y).expect("A*y");

                    let w1 = high_bits_vector(&w, gamma2);

                    let encoded_w1 = encode_w1_vector(&w1, gamma2).expect("encode w1");

                    let (_, challenge) =
                        derive_challenge(parameter_set, preparation.mu(), &encoded_w1)
                            .expect("derive challenge");

                    let mut challenge_hat = challenge.clone();
                    challenge_hat.ntt();

                    for (class, vector, vector_hat) in [
                        ("s1", preparation.private_key().s1(), s1_hat.as_slice()),
                        ("s2", preparation.private_key().s2(), s2_hat.as_slice()),
                        ("t0", preparation.private_key().t0(), t0_hat.as_slice()),
                    ] {
                        let reference = multiply_challenge_vector_centered(&challenge, vector);

                        let optimized = multiply_challenge_vector_centered_ntt_from_hat(
                            &challenge_hat,
                            vector_hat,
                        );

                        assert_eq!(
                            reference.len(),
                            optimized.len(),
                            "{name} case={case} challenge={challenge_index} \
                             class={class} length"
                        );

                        for index in 0..reference.len() {
                            assert_eq!(
                                reference[index].coeffs(),
                                optimized[index].coeffs(),
                                "{name} case={case} \
                                 challenge={challenge_index} \
                                 class={class} polynomial={index}"
                            );
                        }
                    }
                }
            }
        }
    }
}
