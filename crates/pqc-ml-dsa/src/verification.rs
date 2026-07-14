//! Strict ML-DSA signature decoding and verification.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::challenge::sample_in_ball_bytes;
use crate::constants::{N, Q};
use crate::encoding::{
    decode_t1, decode_z, encode_w1, EncodingError, POLY_T1_BYTES, POLY_Z_17_BYTES, POLY_Z_19_BYTES,
};
use crate::expand_a::expand_a;
use crate::hint::use_hint_poly;
use crate::params::MlDsaParameterSet;
use crate::poly::Poly;
use crate::rounding::D;
use crate::signing::compute_message_representative;
use crate::signing_core::{
    challenge_seed_bytes, gamma2_for, matrix_vector_product, subtract_challenge_product,
    vector_infinity_norm_below,
};

/// Error returned by strict ML-DSA verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    /// The public key has the wrong length.
    InvalidPublicKeyLength,
    /// The public key contains a non-canonical component.
    InvalidPublicKeyEncoding,
    /// The signature has the wrong length.
    InvalidSignatureLength,
    /// The signature contains a non-canonical component.
    InvalidSignatureEncoding,
    /// The context string is longer than 255 bytes.
    ContextTooLong,
    /// Internal arithmetic dimensions are inconsistent.
    Arithmetic,
}

/// Strictly decoded ML-DSA public key.
pub struct DecodedPublicKey {
    rho: [u8; 32],
    t1: Vec<Poly>,
}

impl DecodedPublicKey {
    /// Borrow the public matrix seed.
    pub const fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    /// Borrow the rounded public vector.
    pub fn t1(&self) -> &[Poly] {
        &self.t1
    }
}

/// Strictly decoded ML-DSA signature.
pub struct DecodedSignature {
    challenge_seed: Vec<u8>,
    z: Vec<Poly>,
    hints: Vec<Poly>,
}

impl DecodedSignature {
    /// Borrow the encoded challenge seed.
    pub fn challenge_seed(&self) -> &[u8] {
        &self.challenge_seed
    }

    /// Borrow the response vector.
    pub fn z(&self) -> &[Poly] {
        &self.z
    }

    /// Borrow the hint vector.
    pub fn hints(&self) -> &[Poly] {
        &self.hints
    }
}

/// Strictly decode an ML-DSA public key.
pub fn decode_public_key(
    parameter_set: MlDsaParameterSet,
    encoded: &[u8],
) -> Result<DecodedPublicKey, VerificationError> {
    let parameters = parameter_set.parameters();

    if encoded.len() != parameters.public_key_bytes {
        return Err(VerificationError::InvalidPublicKeyLength);
    }

    let rho: [u8; 32] = encoded[..32]
        .try_into()
        .map_err(|_| VerificationError::InvalidPublicKeyLength)?;

    let mut t1 = Vec::with_capacity(parameters.k);
    let mut offset = 32_usize;

    for _ in 0..parameters.k {
        let end = offset + POLY_T1_BYTES;
        let polynomial = decode_t1(&encoded[offset..end]).map_err(map_public_encoding_error)?;
        t1.push(polynomial);
        offset = end;
    }

    Ok(DecodedPublicKey { rho, t1 })
}

/// Strictly decode an ML-DSA signature.
pub fn decode_signature(
    parameter_set: MlDsaParameterSet,
    encoded: &[u8],
) -> Result<DecodedSignature, VerificationError> {
    let parameters = parameter_set.parameters();

    if encoded.len() != parameters.signature_bytes {
        return Err(VerificationError::InvalidSignatureLength);
    }

    let challenge_bytes = challenge_seed_bytes(parameter_set);
    let z_bytes = match parameters.gamma1 {
        value if value == 1 << 17 => POLY_Z_17_BYTES,
        value if value == 1 << 19 => POLY_Z_19_BYTES,
        _ => return Err(VerificationError::InvalidSignatureEncoding),
    };

    let challenge_seed = encoded[..challenge_bytes].to_vec();
    let mut offset = challenge_bytes;
    let mut z = Vec::with_capacity(parameters.l);

    for _ in 0..parameters.l {
        let end = offset + z_bytes;
        let polynomial = decode_z(&encoded[offset..end], parameters.gamma1)
            .map_err(map_signature_encoding_error)?;
        z.push(polynomial);
        offset = end;
    }

    let hints = decode_hint_vector(&encoded[offset..], parameters.k, parameters.omega)?;

    Ok(DecodedSignature {
        challenge_seed,
        z,
        hints,
    })
}

/// Strictly decode the canonical sparse hint-vector layout.
pub fn decode_hint_vector(
    encoded: &[u8],
    rows: usize,
    omega: usize,
) -> Result<Vec<Poly>, VerificationError> {
    if encoded.len() != omega + rows {
        return Err(VerificationError::InvalidSignatureLength);
    }

    let mut hints = Vec::with_capacity(rows);
    let mut previous_end = 0_usize;

    for row in 0..rows {
        let end = usize::from(encoded[omega + row]);

        if end < previous_end || end > omega {
            return Err(VerificationError::InvalidSignatureEncoding);
        }

        let mut coefficients = [0_i32; N];
        let mut previous_index: Option<u8> = None;

        for index_byte in &encoded[previous_end..end] {
            if previous_index.is_some_and(|previous| *index_byte <= previous) {
                return Err(VerificationError::InvalidSignatureEncoding);
            }

            coefficients[usize::from(*index_byte)] = 1;
            previous_index = Some(*index_byte);
        }

        hints.push(Poly::from_coeffs(coefficients));
        previous_end = end;
    }

    if encoded[previous_end..omega].iter().any(|value| *value != 0) {
        return Err(VerificationError::InvalidSignatureEncoding);
    }

    Ok(hints)
}

/// Verify an ML-DSA signature.
///
/// Returns `Ok(true)` only for a valid, canonically encoded signature.
/// Well-formed but invalid signatures return `Ok(false)`.
pub fn verify_internal(
    parameter_set: MlDsaParameterSet,
    encoded_public_key: &[u8],
    message: &[u8],
    context: &[u8],
    encoded_signature: &[u8],
) -> Result<bool, VerificationError> {
    let parameters = parameter_set.parameters();
    let beta = parameters.tau as i32 * parameters.eta;
    let gamma2 = gamma2_for(parameter_set);

    let public_key = decode_public_key(parameter_set, encoded_public_key)?;
    let signature = decode_signature(parameter_set, encoded_signature)?;

    if !vector_infinity_norm_below(signature.z(), parameters.gamma1 - beta) {
        return Ok(false);
    }

    let tr = hash_public_key(encoded_public_key);
    let mu = compute_message_representative(&tr, context, message)
        .map_err(|_| VerificationError::ContextTooLong)?;

    let challenge = sample_in_ball_bytes(signature.challenge_seed(), parameters.tau)
        .map_err(|_| VerificationError::InvalidSignatureEncoding)?;

    let matrix =
        expand_a(public_key.rho(), parameter_set).map_err(|_| VerificationError::Arithmetic)?;

    let az =
        matrix_vector_product(&matrix, signature.z()).map_err(|_| VerificationError::Arithmetic)?;

    let shifted_t1 = shift_t1(public_key.t1());
    let w_approx = subtract_challenge_product(&az, &challenge, &shifted_t1)
        .map_err(|_| VerificationError::Arithmetic)?;

    let mut w1 = Vec::with_capacity(parameters.k);

    for (polynomial, hints) in w_approx.iter().zip(signature.hints()) {
        w1.push(use_hint_poly(polynomial, hints, gamma2));
    }

    let encoded_w1 = encode_w1_vector(&w1, gamma2)?;
    let expected_challenge_seed =
        hash_challenge_transcript(&mu, &encoded_w1, challenge_seed_bytes(parameter_set));

    Ok(constant_time_equal(
        signature.challenge_seed(),
        &expected_challenge_seed,
    ))
}

fn shift_t1(t1: &[Poly]) -> Vec<Poly> {
    t1.iter()
        .map(|polynomial| {
            let mut coefficients = [0_i32; N];

            for (output, coefficient) in coefficients.iter_mut().zip(polynomial.coeffs()) {
                *output = ((*coefficient as i64) << D).rem_euclid(i64::from(Q)) as i32;
            }

            Poly::from_coeffs(coefficients)
        })
        .collect()
}

fn encode_w1_vector(
    vector: &[Poly],
    gamma2: crate::rounding::Gamma2,
) -> Result<Vec<u8>, VerificationError> {
    let mut output = Vec::new();

    for polynomial in vector {
        output.extend_from_slice(
            &encode_w1(polynomial, gamma2).map_err(map_signature_encoding_error)?,
        );
    }

    Ok(output)
}

fn hash_public_key(public_key: &[u8]) -> [u8; 64] {
    let mut hasher = Shake256::default();
    hasher.update(public_key);
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 64];
    reader.read(&mut output);
    output
}

fn hash_challenge_transcript(mu: &[u8; 64], encoded_w1: &[u8], output_bytes: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(mu);
    hasher.update(encoded_w1);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0_u8; output_bytes];
    reader.read(&mut output);
    output
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut difference = 0_u8;

    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }

    difference == 0
}

fn map_public_encoding_error(_: EncodingError) -> VerificationError {
    VerificationError::InvalidPublicKeyEncoding
}

fn map_signature_encoding_error(_: EncodingError) -> VerificationError {
    VerificationError::InvalidSignatureEncoding
}
