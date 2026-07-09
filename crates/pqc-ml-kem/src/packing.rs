//! K-PKE byte packing helpers for ML-KEM.
//!
//! Stage 5B-5 adds deterministic packing and unpacking of the object shapes used
//! by K-PKE: public-key components, secret-key components, and ciphertext
//! components. These helpers are structural and tested independently before the
//! real K-PKE algorithms are wired in.

use pqc_core::{PqcError, PqcResult};

use crate::kpke::Message;
use crate::poly::Poly;
use crate::polyvec::PolyVec;
use crate::MlKemParameterSet;

/// Number of bytes used by one 12-bit encoded ML-KEM polynomial.
pub const POLY_12_BYTES: usize = 384;

/// Public matrix seed length.
pub const RHO_BYTES: usize = 32;

/// Hash length used by ML-KEM public-key hash fields.
pub const HASH_BYTES: usize = 32;

/// Secret fallback value length used by ML-KEM CCA transform.
pub const Z_BYTES: usize = 32;

/// Return the byte length of an encoded polynomial vector.
pub fn polyvec_12_bytes(parameter_set: MlKemParameterSet) -> usize {
    parameter_set.k() * POLY_12_BYTES
}

/// Return the public-key component length: encoded `t_hat` plus `rho`.
pub fn public_key_component_bytes(parameter_set: MlKemParameterSet) -> usize {
    polyvec_12_bytes(parameter_set) + RHO_BYTES
}

/// Return the CPA secret-key component length: encoded `s_hat`.
pub fn secret_key_component_bytes(parameter_set: MlKemParameterSet) -> usize {
    polyvec_12_bytes(parameter_set)
}

/// Return the `u` component byte length for a ciphertext.
pub fn ciphertext_u_bytes(parameter_set: MlKemParameterSet) -> usize {
    parameter_set.k() * 32 * parameter_set.du() as usize
}

/// Return the `v` component byte length for a ciphertext.
pub fn ciphertext_v_bytes(parameter_set: MlKemParameterSet) -> usize {
    32 * parameter_set.dv() as usize
}

/// Return the ciphertext component length.
pub fn ciphertext_component_bytes(parameter_set: MlKemParameterSet) -> usize {
    ciphertext_u_bytes(parameter_set) + ciphertext_v_bytes(parameter_set)
}

/// Encode an ML-KEM public key component from `t_hat` and `rho`.
pub fn encode_public_key_component<const BYTES: usize>(
    parameter_set: MlKemParameterSet,
    t_hat: &PolyVec,
    rho: &[u8; RHO_BYTES],
) -> PqcResult<[u8; BYTES]> {
    if t_hat.rank() != parameter_set.k() {
        return Err(PqcError::ProtocolInvariantFailed);
    }
    let expected = public_key_component_bytes(parameter_set);
    if BYTES != expected {
        return Err(PqcError::InvalidLength {
            expected,
            actual: BYTES,
        });
    }

    let mut out = [0u8; BYTES];
    encode_polyvec_12_into(t_hat, &mut out[..polyvec_12_bytes(parameter_set)])?;
    out[polyvec_12_bytes(parameter_set)..].copy_from_slice(rho);
    Ok(out)
}

/// Decode an ML-KEM public key component into encoded vector bytes and `rho`.
pub fn split_public_key_component(
    parameter_set: MlKemParameterSet,
    input: &[u8],
) -> PqcResult<(&[u8], [u8; RHO_BYTES])> {
    let expected = public_key_component_bytes(parameter_set);
    if input.len() != expected {
        return Err(PqcError::InvalidLength {
            expected,
            actual: input.len(),
        });
    }

    let split = polyvec_12_bytes(parameter_set);
    let mut rho = [0u8; RHO_BYTES];
    rho.copy_from_slice(&input[split..]);
    Ok((&input[..split], rho))
}

/// Encode the CPA secret-key component from `s_hat`.
pub fn encode_secret_key_component<const BYTES: usize>(
    parameter_set: MlKemParameterSet,
    s_hat: &PolyVec,
) -> PqcResult<[u8; BYTES]> {
    if s_hat.rank() != parameter_set.k() {
        return Err(PqcError::ProtocolInvariantFailed);
    }
    let expected = secret_key_component_bytes(parameter_set);
    if BYTES != expected {
        return Err(PqcError::InvalidLength {
            expected,
            actual: BYTES,
        });
    }

    let mut out = [0u8; BYTES];
    encode_polyvec_12_into(s_hat, &mut out)?;
    Ok(out)
}

/// Encode ciphertext components from `u` and `v`.
pub fn encode_ciphertext_components<const BYTES: usize>(
    parameter_set: MlKemParameterSet,
    u: &PolyVec,
    v: &Poly,
) -> PqcResult<[u8; BYTES]> {
    if u.rank() != parameter_set.k() {
        return Err(PqcError::ProtocolInvariantFailed);
    }
    let expected = ciphertext_component_bytes(parameter_set);
    if BYTES != expected {
        return Err(PqcError::InvalidLength {
            expected,
            actual: BYTES,
        });
    }

    let mut out = [0u8; BYTES];
    let u_len = ciphertext_u_bytes(parameter_set);

    match parameter_set.du() {
        10 => encode_polyvec_compressed_10_into(u, &mut out[..u_len])?,
        11 => encode_polyvec_compressed_11_into(u, &mut out[..u_len])?,
        _ => return Err(PqcError::UnsupportedParameterSet),
    }

    match parameter_set.dv() {
        4 => out[u_len..].copy_from_slice(&v.compress::<128>(4)),
        5 => out[u_len..].copy_from_slice(&v.compress::<160>(5)),
        _ => return Err(PqcError::UnsupportedParameterSet),
    }

    Ok(out)
}

/// Split ciphertext bytes into `u` and `v` byte slices.
pub fn split_ciphertext_components(
    parameter_set: MlKemParameterSet,
    input: &[u8],
) -> PqcResult<(&[u8], &[u8])> {
    let expected = ciphertext_component_bytes(parameter_set);
    if input.len() != expected {
        return Err(PqcError::InvalidLength {
            expected,
            actual: input.len(),
        });
    }

    let split = ciphertext_u_bytes(parameter_set);
    Ok((&input[..split], &input[split..]))
}

/// Encode a message object into bytes.
pub fn encode_message(message: &Message) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(message.as_bytes());
    out
}

fn encode_polyvec_12_into(polyvec: &PolyVec, out: &mut [u8]) -> PqcResult<()> {
    let expected = polyvec.rank() * POLY_12_BYTES;
    if out.len() != expected {
        return Err(PqcError::InvalidLength {
            expected,
            actual: out.len(),
        });
    }

    for (i, poly) in polyvec.as_slice().iter().enumerate() {
        let encoded = poly.encode_12();
        let start = i * POLY_12_BYTES;
        out[start..start + POLY_12_BYTES].copy_from_slice(&encoded);
    }

    Ok(())
}

fn encode_polyvec_compressed_10_into(polyvec: &PolyVec, out: &mut [u8]) -> PqcResult<()> {
    encode_polyvec_compressed_into::<320>(polyvec, out, 10)
}

fn encode_polyvec_compressed_11_into(polyvec: &PolyVec, out: &mut [u8]) -> PqcResult<()> {
    encode_polyvec_compressed_into::<352>(polyvec, out, 11)
}

fn encode_polyvec_compressed_into<const PER_POLY_BYTES: usize>(
    polyvec: &PolyVec,
    out: &mut [u8],
    d: u32,
) -> PqcResult<()> {
    let expected = polyvec.rank() * PER_POLY_BYTES;
    if out.len() != expected {
        return Err(PqcError::InvalidLength {
            expected,
            actual: out.len(),
        });
    }

    for (i, poly) in polyvec.as_slice().iter().enumerate() {
        let encoded = poly.compress::<PER_POLY_BYTES>(d);
        let start = i * PER_POLY_BYTES;
        out[start..start + PER_POLY_BYTES].copy_from_slice(&encoded);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::N;

    fn sample_poly(offset: i16) -> Poly {
        let mut coeffs = [0i16; N];
        let mut i = 0;
        while i < N {
            coeffs[i] = ((i as i16) + offset) % 3329;
            i += 1;
        }
        Poly::from_coefficients(coeffs)
    }

    #[test]
    fn component_lengths_match_ml_kem_sizes() {
        assert_eq!(public_key_component_bytes(MlKemParameterSet::MlKem512), 800);
        assert_eq!(
            public_key_component_bytes(MlKemParameterSet::MlKem768),
            1184
        );
        assert_eq!(
            public_key_component_bytes(MlKemParameterSet::MlKem1024),
            1568
        );

        assert_eq!(secret_key_component_bytes(MlKemParameterSet::MlKem512), 768);
        assert_eq!(
            secret_key_component_bytes(MlKemParameterSet::MlKem768),
            1152
        );
        assert_eq!(
            secret_key_component_bytes(MlKemParameterSet::MlKem1024),
            1536
        );

        assert_eq!(ciphertext_component_bytes(MlKemParameterSet::MlKem512), 768);
        assert_eq!(
            ciphertext_component_bytes(MlKemParameterSet::MlKem768),
            1088
        );
        assert_eq!(
            ciphertext_component_bytes(MlKemParameterSet::MlKem1024),
            1568
        );
    }

    #[test]
    fn public_key_component_encodes_and_splits() {
        let t = PolyVec::from_slice(&[sample_poly(1), sample_poly(2)]);
        let rho = [7u8; RHO_BYTES];

        let encoded =
            encode_public_key_component::<800>(MlKemParameterSet::MlKem512, &t, &rho).unwrap();
        let (t_bytes, decoded_rho) =
            split_public_key_component(MlKemParameterSet::MlKem512, &encoded).unwrap();

        assert_eq!(t_bytes.len(), 768);
        assert_eq!(decoded_rho, rho);
    }

    #[test]
    fn secret_key_component_encodes() {
        let s = PolyVec::from_slice(&[sample_poly(1), sample_poly(2), sample_poly(3)]);

        let encoded = encode_secret_key_component::<1152>(MlKemParameterSet::MlKem768, &s).unwrap();

        assert_eq!(encoded.len(), 1152);
    }

    #[test]
    fn ciphertext_component_encodes_and_splits() {
        let u = PolyVec::from_slice(&[sample_poly(1), sample_poly(2), sample_poly(3)]);
        let v = sample_poly(9);

        let encoded =
            encode_ciphertext_components::<1088>(MlKemParameterSet::MlKem768, &u, &v).unwrap();
        let (u_bytes, v_bytes) =
            split_ciphertext_components(MlKemParameterSet::MlKem768, &encoded).unwrap();

        assert_eq!(u_bytes.len(), 960);
        assert_eq!(v_bytes.len(), 128);
    }

    #[test]
    fn wrong_rank_is_rejected() {
        let t = PolyVec::from_slice(&[sample_poly(1), sample_poly(2)]);
        let rho = [0u8; RHO_BYTES];

        assert!(
            encode_public_key_component::<1184>(MlKemParameterSet::MlKem768, &t, &rho).is_err()
        );
    }

    #[test]
    fn wrong_length_is_rejected() {
        let t = PolyVec::from_slice(&[sample_poly(1), sample_poly(2)]);
        let rho = [0u8; RHO_BYTES];

        assert!(encode_public_key_component::<799>(MlKemParameterSet::MlKem512, &t, &rho).is_err());
    }
}
