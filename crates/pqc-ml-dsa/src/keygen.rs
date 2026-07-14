//! Deterministic ML-DSA key generation.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::encoding::{encode_eta, encode_t0, encode_t1, EncodingError};
use crate::expand_a::{expand_a, ExpandAError};
use crate::params::MlDsaParameterSet;
use crate::poly::Poly;
use crate::rounding::power2round;
use crate::sample::{sample_eta_polyvec, SamplingError};

/// Input seed length for deterministic ML-DSA key generation.
pub const KEYGEN_SEED_BYTES: usize = 32;

/// Hash length stored in an ML-DSA private key.
pub const TR_BYTES: usize = 64;

/// Deterministically generated ML-DSA key pair.
///
/// The private-key bytes are intentionally not `Debug`.
pub struct MlDsaKeyPair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl MlDsaKeyPair {
    /// Borrow the encoded public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Borrow the encoded private key.
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }

    /// Consume the key pair and return both encoded keys.
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.public_key, self.private_key)
    }
}

/// Error returned by deterministic key generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyGenError {
    /// Public-matrix expansion failed.
    ExpandA,
    /// Secret sampling failed.
    Sampling,
    /// Canonical key encoding failed.
    Encoding,
    /// Internal matrix dimensions were inconsistent.
    InvalidDimensions,
}

impl From<ExpandAError> for KeyGenError {
    fn from(_: ExpandAError) -> Self {
        Self::ExpandA
    }
}

impl From<SamplingError> for KeyGenError {
    fn from(_: SamplingError) -> Self {
        Self::Sampling
    }
}

impl From<EncodingError> for KeyGenError {
    fn from(_: EncodingError) -> Self {
        Self::Encoding
    }
}

/// Generate an encoded ML-DSA key pair deterministically from `xi`.
pub fn keygen_internal(
    parameter_set: MlDsaParameterSet,
    xi: &[u8; KEYGEN_SEED_BYTES],
) -> Result<MlDsaKeyPair, KeyGenError> {
    let parameters = parameter_set.parameters();
    let (rho, rho_prime, key) = derive_keygen_seeds(xi, parameters.k, parameters.l);

    let matrix = expand_a(&rho, parameter_set)?;
    let s1 = sample_eta_polyvec(&rho_prime, 0, parameters.l, parameters.eta)?;
    let s2 = sample_eta_polyvec(
        &rho_prime,
        parameters.l as u16,
        parameters.k,
        parameters.eta,
    )?;

    let mut s1_hat = s1.clone();
    for polynomial in &mut s1_hat {
        polynomial.ntt();
    }

    let mut t1 = Vec::with_capacity(parameters.k);
    let mut t0 = Vec::with_capacity(parameters.k);

    for row in 0..parameters.k {
        let mut accumulator = Poly::zero();

        for (column, secret_hat) in s1_hat.iter().enumerate() {
            let matrix_entry = matrix
                .get(row, column)
                .ok_or(KeyGenError::InvalidDimensions)?;
            let product = matrix_entry.pointwise_montgomery(secret_hat);
            accumulator.add_assign(&product);
        }

        accumulator.reduce();
        accumulator.inv_ntt_to_mont();
        accumulator.add_assign(s2.get(row).ok_or(KeyGenError::InvalidDimensions)?);
        accumulator.reduce();
        accumulator.freeze();

        let mut high = [0_i32; 256];
        let mut low = [0_i32; 256];

        for ((high_coefficient, low_coefficient), coefficient) in high
            .iter_mut()
            .zip(low.iter_mut())
            .zip(accumulator.coeffs())
        {
            let (coefficient_high, coefficient_low) = power2round(*coefficient);
            *high_coefficient = coefficient_high;
            *low_coefficient = coefficient_low;
        }

        t1.push(Poly::from_coeffs(high));
        t0.push(Poly::from_coeffs(low));
    }

    let public_key = encode_public_key(&rho, &t1)?;
    let tr = hash_public_key(&public_key);
    let private_key = encode_private_key(&rho, &key, &tr, &s1, &s2, &t0, parameters.eta)?;

    if public_key.len() != parameters.public_key_bytes
        || private_key.len() != parameters.private_key_bytes
    {
        return Err(KeyGenError::Encoding);
    }

    Ok(MlDsaKeyPair {
        public_key,
        private_key,
    })
}

/// Derive `rho`, `rho_prime`, and `K` from the external key-generation seed.
pub fn derive_keygen_seeds(
    xi: &[u8; KEYGEN_SEED_BYTES],
    k: usize,
    l: usize,
) -> ([u8; 32], [u8; 64], [u8; 32]) {
    let mut hasher = Shake256::default();
    hasher.update(xi);
    hasher.update(&[k as u8, l as u8]);
    let mut reader = hasher.finalize_xof();

    let mut rho = [0_u8; 32];
    let mut rho_prime = [0_u8; 64];
    let mut key = [0_u8; 32];

    reader.read(&mut rho);
    reader.read(&mut rho_prime);
    reader.read(&mut key);

    (rho, rho_prime, key)
}

fn encode_public_key(rho: &[u8; 32], t1: &[Poly]) -> Result<Vec<u8>, EncodingError> {
    let mut output = Vec::with_capacity(32 + t1.len() * 320);
    output.extend_from_slice(rho);

    for polynomial in t1 {
        output.extend_from_slice(&encode_t1(polynomial)?);
    }

    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn encode_private_key(
    rho: &[u8; 32],
    key: &[u8; 32],
    tr: &[u8; TR_BYTES],
    s1: &[Poly],
    s2: &[Poly],
    t0: &[Poly],
    eta: i32,
) -> Result<Vec<u8>, EncodingError> {
    let mut output = Vec::new();
    output.extend_from_slice(rho);
    output.extend_from_slice(key);
    output.extend_from_slice(tr);

    for polynomial in s1 {
        output.extend_from_slice(&encode_eta(polynomial, eta)?);
    }

    for polynomial in s2 {
        output.extend_from_slice(&encode_eta(polynomial, eta)?);
    }

    for polynomial in t0 {
        output.extend_from_slice(&encode_t0(polynomial)?);
    }

    Ok(output)
}

fn hash_public_key(public_key: &[u8]) -> [u8; TR_BYTES] {
    let mut hasher = Shake256::default();
    hasher.update(public_key);
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; TR_BYTES];
    reader.read(&mut output);
    output
}
