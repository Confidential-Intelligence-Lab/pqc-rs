//! ML-DSA signing transcript and mask-generation core.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::encoding::{
    decode_eta, decode_t0, EncodingError, POLY_ETA2_BYTES, POLY_ETA4_BYTES, POLY_T0_BYTES,
    POLY_Z_17_BYTES, POLY_Z_19_BYTES,
};

#[cfg(test)]
use crate::encoding::decode_z;
use crate::params::MlDsaParameterSet;
use crate::poly::Poly;
use crate::xof::{ExpandMaskReader, RHO_DOUBLE_PRIME_BYTES};

/// ML-DSA message-representative length.
pub const MU_BYTES: usize = 64;
/// Per-signature randomness length.
pub const SIGNING_RANDOMNESS_BYTES: usize = 32;
/// Maximum FIPS 204 context-string length.
pub const MAX_CONTEXT_BYTES: usize = 255;

/// Error returned by signing preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningError {
    /// The encoded private key has the wrong length.
    InvalidPrivateKeyLength,
    /// A private-key component is not canonically encoded.
    InvalidPrivateKeyEncoding,
    /// The context string is longer than 255 bytes.
    ContextTooLong,
    /// A signing nonce overflowed its 16-bit representation.
    NonceOverflow,
}

/// Strictly decoded ML-DSA private-key material.
///
/// This type intentionally does not implement `Debug`.
pub struct DecodedPrivateKey {
    rho: [u8; 32],
    key: [u8; 32],
    tr: [u8; 64],
    s1: Vec<Poly>,
    s2: Vec<Poly>,
    t0: Vec<Poly>,
}

impl DecodedPrivateKey {
    /// Borrow the public matrix seed.
    pub const fn rho(&self) -> &[u8; 32] {
        &self.rho
    }
    /// Borrow the public-key hash.
    pub const fn tr(&self) -> &[u8; 64] {
        &self.tr
    }
    /// Borrow the first bounded secret vector.
    pub fn s1(&self) -> &[Poly] {
        &self.s1
    }
    /// Borrow the second bounded secret vector.
    pub fn s2(&self) -> &[Poly] {
        &self.s2
    }
    /// Borrow the low-order public relation vector.
    pub fn t0(&self) -> &[Poly] {
        &self.t0
    }
    fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Deterministic state prepared for the signing rejection loop.
///
/// This type intentionally does not implement `Debug`.
pub struct SigningPreparation {
    private_key: DecodedPrivateKey,
    mu: [u8; MU_BYTES],
    rho_double_prime: [u8; RHO_DOUBLE_PRIME_BYTES],
}

impl SigningPreparation {
    /// Borrow the decoded private-key material.
    pub const fn private_key(&self) -> &DecodedPrivateKey {
        &self.private_key
    }
    /// Borrow the message representative.
    pub const fn mu(&self) -> &[u8; MU_BYTES] {
        &self.mu
    }
    /// Borrow the mask-generation seed.
    pub const fn rho_double_prime(&self) -> &[u8; RHO_DOUBLE_PRIME_BYTES] {
        &self.rho_double_prime
    }
}

/// Strictly decode an ML-DSA private key.
pub fn decode_private_key(
    parameter_set: MlDsaParameterSet,
    encoded: &[u8],
) -> Result<DecodedPrivateKey, SigningError> {
    let parameters = parameter_set.parameters();
    if encoded.len() != parameters.private_key_bytes {
        return Err(SigningError::InvalidPrivateKeyLength);
    }

    let eta_bytes = match parameters.eta {
        2 => POLY_ETA2_BYTES,
        4 => POLY_ETA4_BYTES,
        _ => return Err(SigningError::InvalidPrivateKeyEncoding),
    };

    let mut offset = 0_usize;
    let rho = take_array::<32>(encoded, &mut offset)?;
    let key = take_array::<32>(encoded, &mut offset)?;
    let tr = take_array::<64>(encoded, &mut offset)?;
    let s1 = decode_poly_vector(encoded, &mut offset, parameters.l, eta_bytes, |bytes| {
        decode_eta(bytes, parameters.eta)
    })?;
    let s2 = decode_poly_vector(encoded, &mut offset, parameters.k, eta_bytes, |bytes| {
        decode_eta(bytes, parameters.eta)
    })?;
    let t0 = decode_poly_vector(encoded, &mut offset, parameters.k, POLY_T0_BYTES, decode_t0)?;

    if offset != encoded.len() {
        return Err(SigningError::InvalidPrivateKeyLength);
    }

    Ok(DecodedPrivateKey {
        rho,
        key,
        tr,
        s1,
        s2,
        t0,
    })
}

/// Compute `SHAKE256(tr || 0x00 || len(ctx) || ctx || message, 64)`.
pub fn compute_message_representative(
    tr: &[u8; 64],
    context: &[u8],
    message: &[u8],
) -> Result<[u8; MU_BYTES], SigningError> {
    let context_length = u8::try_from(context.len()).map_err(|_| SigningError::ContextTooLong)?;

    let mut hasher = Shake256::default();
    hasher.update(tr);
    hasher.update(&[0_u8, context_length]);
    hasher.update(context);
    hasher.update(message);

    let mut reader = hasher.finalize_xof();
    let mut mu = [0_u8; MU_BYTES];
    reader.read(&mut mu);
    Ok(mu)
}

/// Compute the internal-interface message representative.
///
/// This computes `SHAKE256(tr || message_prime, 64)`, where `message_prime`
/// is the input to `ML-DSA.Sign_internal`.
pub fn compute_internal_message_representative(
    tr: &[u8; 64],
    message_prime: &[u8],
) -> [u8; MU_BYTES] {
    let mut hasher = Shake256::default();
    hasher.update(tr);
    hasher.update(message_prime);

    let mut reader = hasher.finalize_xof();
    let mut mu = [0_u8; MU_BYTES];
    reader.read(&mut mu);
    mu
}

/// Decode a private key and prepare signing from an externally supplied `mu`.
pub fn prepare_signing_from_mu(
    parameter_set: MlDsaParameterSet,
    encoded_private_key: &[u8],
    mu: &[u8; MU_BYTES],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
) -> Result<SigningPreparation, SigningError> {
    let private_key = decode_private_key(parameter_set, encoded_private_key)?;
    let rho_double_prime = derive_rho_double_prime(private_key.key(), randomness, mu);

    Ok(SigningPreparation {
        private_key,
        mu: *mu,
        rho_double_prime,
    })
}

/// Decode a private key and prepare the internal signing interface from `M'`.
pub fn prepare_internal_signing(
    parameter_set: MlDsaParameterSet,
    encoded_private_key: &[u8],
    message_prime: &[u8],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
) -> Result<SigningPreparation, SigningError> {
    let private_key = decode_private_key(parameter_set, encoded_private_key)?;
    let mu = compute_internal_message_representative(private_key.tr(), message_prime);
    let rho_double_prime = derive_rho_double_prime(private_key.key(), randomness, &mu);

    Ok(SigningPreparation {
        private_key,
        mu,
        rho_double_prime,
    })
}

/// Derive `rho_double_prime = SHAKE256(K || rnd || mu, 64)`.
pub fn derive_rho_double_prime(
    key: &[u8; 32],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
    mu: &[u8; MU_BYTES],
) -> [u8; RHO_DOUBLE_PRIME_BYTES] {
    let mut hasher = Shake256::default();
    hasher.update(key);
    hasher.update(randomness);
    hasher.update(mu);

    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; RHO_DOUBLE_PRIME_BYTES];
    reader.read(&mut output);
    output
}

/// Decode the private key and prepare the signing transcript.
pub fn prepare_signing(
    parameter_set: MlDsaParameterSet,
    encoded_private_key: &[u8],
    message: &[u8],
    context: &[u8],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
) -> Result<SigningPreparation, SigningError> {
    let private_key = decode_private_key(parameter_set, encoded_private_key)?;
    let mu = compute_message_representative(private_key.tr(), context, message)?;
    let rho_double_prime = derive_rho_double_prime(private_key.key(), randomness, &mu);

    Ok(SigningPreparation {
        private_key,
        mu,
        rho_double_prime,
    })
}

/// Sample one signing-mask polynomial from `ExpandMask`.
pub fn sample_mask_poly(
    rho_double_prime: &[u8; RHO_DOUBLE_PRIME_BYTES],
    nonce: u16,
    gamma1: i32,
) -> Result<Poly, SigningError> {
    let mut reader = ExpandMaskReader::new(rho_double_prime, nonce);
    let mut coefficients = [0_i32; 256];

    match gamma1 {
        value if value == 1 << 17 => {
            let mut encoded = [0_u8; POLY_Z_17_BYTES];
            reader.read(&mut encoded);

            for (group, chunk) in encoded.chunks_exact(9).enumerate() {
                let b0 = u32::from(chunk[0]);
                let b1 = u32::from(chunk[1]);
                let b2 = u32::from(chunk[2]);
                let b3 = u32::from(chunk[3]);
                let b4 = u32::from(chunk[4]);
                let b5 = u32::from(chunk[5]);
                let b6 = u32::from(chunk[6]);
                let b7 = u32::from(chunk[7]);
                let b8 = u32::from(chunk[8]);

                let values = [
                    b0 | (b1 << 8) | ((b2 & 0x03) << 16),
                    (b2 >> 2) | (b3 << 6) | ((b4 & 0x0f) << 14),
                    (b4 >> 4) | (b5 << 4) | ((b6 & 0x3f) << 12),
                    (b6 >> 6) | (b7 << 2) | (b8 << 10),
                ];

                let base = group * 4;

                for (offset, packed) in values.into_iter().enumerate() {
                    coefficients[base + offset] = gamma1 - packed as i32;
                }
            }
        }

        value if value == 1 << 19 => {
            let mut encoded = [0_u8; POLY_Z_19_BYTES];
            reader.read(&mut encoded);

            for (group, chunk) in encoded.chunks_exact(5).enumerate() {
                let b0 = u32::from(chunk[0]);
                let b1 = u32::from(chunk[1]);
                let b2 = u32::from(chunk[2]);
                let b3 = u32::from(chunk[3]);
                let b4 = u32::from(chunk[4]);

                let v0 = b0 | (b1 << 8) | ((b2 & 0x0f) << 16);

                let v1 = (b2 >> 4) | (b3 << 4) | (b4 << 12);

                let base = group * 2;

                coefficients[base] = gamma1 - v0 as i32;

                coefficients[base + 1] = gamma1 - v1 as i32;
            }
        }

        _ => {
            return Err(SigningError::InvalidPrivateKeyEncoding);
        }
    }

    Ok(Poly::from_coeffs(coefficients))
}

#[cfg(test)]
fn sample_mask_poly_reference(
    rho_double_prime: &[u8; RHO_DOUBLE_PRIME_BYTES],
    nonce: u16,
    gamma1: i32,
) -> Result<Poly, SigningError> {
    let byte_length = match gamma1 {
        value if value == 1 << 17 => POLY_Z_17_BYTES,
        value if value == 1 << 19 => POLY_Z_19_BYTES,
        _ => return Err(SigningError::InvalidPrivateKeyEncoding),
    };

    let mut reader = ExpandMaskReader::new(rho_double_prime, nonce);
    let mut encoded = vec![0_u8; byte_length];
    reader.read(&mut encoded);
    decode_z(&encoded, gamma1).map_err(|_| SigningError::InvalidPrivateKeyEncoding)
}

/// Sample the `l`-polynomial signing-mask vector beginning at `kappa`.
pub fn sample_mask_vector(
    rho_double_prime: &[u8; RHO_DOUBLE_PRIME_BYTES],
    kappa: u16,
    length: usize,
    gamma1: i32,
) -> Result<Vec<Poly>, SigningError> {
    let mut output = Vec::with_capacity(length);

    for index in 0..length {
        let index = u16::try_from(index).map_err(|_| SigningError::NonceOverflow)?;
        let nonce = kappa
            .checked_add(index)
            .ok_or(SigningError::NonceOverflow)?;
        output.push(sample_mask_poly(rho_double_prime, nonce, gamma1)?);
    }

    Ok(output)
}
fn take_array<const LENGTH: usize>(
    input: &[u8],
    offset: &mut usize,
) -> Result<[u8; LENGTH], SigningError> {
    let end = offset
        .checked_add(LENGTH)
        .ok_or(SigningError::InvalidPrivateKeyLength)?;
    let bytes = input
        .get(*offset..end)
        .ok_or(SigningError::InvalidPrivateKeyLength)?;
    let array = bytes
        .try_into()
        .map_err(|_| SigningError::InvalidPrivateKeyLength)?;
    *offset = end;
    Ok(array)
}

fn decode_poly_vector<F>(
    input: &[u8],
    offset: &mut usize,
    length: usize,
    polynomial_bytes: usize,
    mut decode: F,
) -> Result<Vec<Poly>, SigningError>
where
    F: FnMut(&[u8]) -> Result<Poly, EncodingError>,
{
    let mut output = Vec::with_capacity(length);

    for _ in 0..length {
        let end = offset
            .checked_add(polynomial_bytes)
            .ok_or(SigningError::InvalidPrivateKeyLength)?;
        let bytes = input
            .get(*offset..end)
            .ok_or(SigningError::InvalidPrivateKeyLength)?;
        output.push(decode(bytes).map_err(|_| SigningError::InvalidPrivateKeyEncoding)?);
        *offset = end;
    }

    Ok(output)
}

#[cfg(test)]
mod expand_mask_specialized_equivalence {
    use super::*;

    #[test]
    fn specialized_expand_mask_matches_generic_decoder() {
        let parameter_sets = [
            (MlDsaParameterSet::MlDsa44, "ML-DSA-44"),
            (MlDsaParameterSet::MlDsa65, "ML-DSA-65"),
            (MlDsaParameterSet::MlDsa87, "ML-DSA-87"),
        ];

        let kappas = [0_u16, 1, 7, 31, 255, 1024, 4096];

        for (parameter_index, (parameter_set, name)) in parameter_sets.into_iter().enumerate() {
            let parameters = parameter_set.parameters();

            for seed_case in 0_u8..8 {
                let seed_byte = 0x21_u8
                    .wrapping_add(parameter_index as u8 * 0x20)
                    .wrapping_add(seed_case);

                let rho_double_prime = [seed_byte; RHO_DOUBLE_PRIME_BYTES];

                for &kappa in &kappas {
                    for index in 0..parameters.l {
                        let index = u16::try_from(index).expect("vector index");

                        let nonce = kappa.checked_add(index).expect("nonce");

                        let reference =
                            sample_mask_poly_reference(&rho_double_prime, nonce, parameters.gamma1)
                                .expect("reference mask");

                        let specialized =
                            sample_mask_poly(&rho_double_prime, nonce, parameters.gamma1)
                                .expect("specialized mask");

                        assert!(
                            reference == specialized,
                            "ExpandMask mismatch: \
                             parameter_set={name} \
                             seed_case={seed_case} \
                             kappa={kappa} \
                             polynomial={index}"
                        );
                    }
                }
            }
        }
    }
}
