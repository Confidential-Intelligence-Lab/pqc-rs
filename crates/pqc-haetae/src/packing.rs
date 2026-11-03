//! H1.2-D.6B.2: canonical HAETAE 1.2.0 polynomial-Q encoding.
//!
//! Experimental implementation. Not yet independently validated
//! against serialized C-reference fixtures.

use crate::params::{ParameterSet, N, Q};
use crate::poly::Poly;

/// Errors encountered during polynomial encoding or decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackingError {
    /// The supplied byte slice has an incorrect length.
    InvalidLength { expected: usize, actual: usize },
    /// A polynomial coefficient is outside the representable domain.
    InvalidCoefficient { index: usize, value: i32 },
}

/// Encoded length of one public-key polynomial.
pub const fn poly_q_packed_bytes(mode: ParameterSet) -> usize {
    match mode {
        ParameterSet::Haetae2 | ParameterSet::Haetae3 => 480,
        ParameterSet::Haetae5 => 512,
    }
}

/// Pack a polynomial using the reference's little-endian bit order.
///
/// HAETAE-2/3 encode 15 bits per coefficient.
/// HAETAE-5 encodes 16 bits per coefficient.
pub fn pack_poly_q(polynomial: &Poly, mode: ParameterSet) -> Result<Vec<u8>, PackingError> {
    let width = match mode {
        ParameterSet::Haetae2 | ParameterSet::Haetae3 => 15_u32,
        ParameterSet::Haetae5 => 16_u32,
    };

    let maximum = match mode {
        ParameterSet::Haetae2 | ParameterSet::Haetae3 => 0x7fff,
        ParameterSet::Haetae5 => Q - 1,
    };

    let mut output = vec![0_u8; poly_q_packed_bytes(mode)];

    for (index, &coefficient) in polynomial.coeffs.iter().enumerate() {
        if !(0..=maximum).contains(&coefficient) {
            return Err(PackingError::InvalidCoefficient {
                index,
                value: coefficient,
            });
        }

        let value = coefficient as u32;
        let bit_offset = index * width as usize;
        let byte_offset = bit_offset / 8;
        let shift = (bit_offset % 8) as u32;

        let shifted = value << shift;

        output[byte_offset] |= shifted as u8;
        output[byte_offset + 1] |= (shifted >> 8) as u8;

        if shift + width > 16 {
            output[byte_offset + 2] |= (shifted >> 16) as u8;
        }
    }

    Ok(output)
}

/// Decode a polynomial from its canonical byte representation.
pub fn unpack_poly_q(encoded: &[u8], mode: ParameterSet) -> Result<Poly, PackingError> {
    let expected = poly_q_packed_bytes(mode);

    if encoded.len() != expected {
        return Err(PackingError::InvalidLength {
            expected,
            actual: encoded.len(),
        });
    }

    let width = match mode {
        ParameterSet::Haetae2 | ParameterSet::Haetae3 => 15_usize,
        ParameterSet::Haetae5 => 16_usize,
    };

    let mask = (1_u32 << width) - 1;
    let maximum = match mode {
        ParameterSet::Haetae2 | ParameterSet::Haetae3 => 0x7fff,
        ParameterSet::Haetae5 => Q - 1,
    };

    let mut coefficients = [0_i32; N];

    for (index, coefficient) in coefficients.iter_mut().enumerate() {
        let bit_offset = index * width;
        let byte_offset = bit_offset / 8;
        let shift = bit_offset % 8;

        let mut word = u32::from(encoded[byte_offset]);

        if byte_offset + 1 < encoded.len() {
            word |= u32::from(encoded[byte_offset + 1]) << 8;
        }

        if byte_offset + 2 < encoded.len() {
            word |= u32::from(encoded[byte_offset + 2]) << 16;
        }

        let value = ((word >> shift) & mask) as i32;

        if value > maximum {
            return Err(PackingError::InvalidCoefficient { index, value });
        }

        *coefficient = value;
    }

    Ok(Poly::new(coefficients))
}

/// Number of bytes in a polynomial encoded with two bits per coefficient.
pub const POLY_ETA_PACKED_BYTES: usize = 64;

/// Number of bytes in a polynomial encoded with three bits per coefficient.
pub const POLY2_ETA_PACKED_BYTES: usize = 96;

/// Encode coefficients in [-1, 1] using Algorithm 31 (PackPolyEta).
pub fn pack_poly_eta(polynomial: &Poly) -> Result<Vec<u8>, PackingError> {
    pack_small_polynomial(polynomial, 1, 2)
}

/// Decode a canonical Algorithm 32 (UnpackPolyEta) representation.
pub fn unpack_poly_eta(encoded: &[u8]) -> Result<Poly, PackingError> {
    unpack_small_polynomial(encoded, 1, 2)
}

/// Encode coefficients in [-2, 2] using Algorithm 33 (PackPoly2Eta).
///
/// HAETAE-5 secret keys use `pack_poly_eta` for s1 instead.
pub fn pack_poly2_eta(polynomial: &Poly) -> Result<Vec<u8>, PackingError> {
    pack_small_polynomial(polynomial, 2, 3)
}

/// Decode a canonical Algorithm 34 (UnpackPoly2Eta) representation.
pub fn unpack_poly2_eta(encoded: &[u8]) -> Result<Poly, PackingError> {
    unpack_small_polynomial(encoded, 2, 3)
}

fn pack_small_polynomial(
    polynomial: &Poly,
    bound: i32,
    bits: usize,
) -> Result<Vec<u8>, PackingError> {
    let mut output = vec![0_u8; N * bits / 8];

    for (index, &coefficient) in polynomial.coeffs.iter().enumerate() {
        if !(-bound..=bound).contains(&coefficient) {
            return Err(PackingError::InvalidCoefficient {
                index,
                value: coefficient,
            });
        }

        let value = (bound - coefficient) as u8;
        let offset = index * bits;
        let byte = offset / 8;
        let shift = offset % 8;

        output[byte] |= value << shift;

        if shift + bits > 8 {
            output[byte + 1] |= value >> (8 - shift);
        }
    }

    Ok(output)
}

fn unpack_small_polynomial(encoded: &[u8], bound: i32, bits: usize) -> Result<Poly, PackingError> {
    let expected = N * bits / 8;

    if encoded.len() != expected {
        return Err(PackingError::InvalidLength {
            expected,
            actual: encoded.len(),
        });
    }

    let mut coefficients = [0_i32; N];
    let mask = (1_u16 << bits) - 1;

    for (index, coefficient) in coefficients.iter_mut().enumerate() {
        let offset = index * bits;
        let byte = offset / 8;
        let shift = offset % 8;

        let mut word = u16::from(encoded[byte]) >> shift;

        if shift + bits > 8 {
            word |= u16::from(encoded[byte + 1]) << (8 - shift);
        }

        let value = i32::from(word & mask);

        if value > 2 * bound {
            return Err(PackingError::InvalidCoefficient {
                index,
                value: bound - value,
            });
        }

        *coefficient = bound - value;
    }

    Ok(Poly::new(coefficients))
}

/// Reference public-key size for the selected parameter set.
pub const fn public_key_bytes(mode: ParameterSet) -> usize {
    match mode {
        ParameterSet::Haetae2 => 992,
        ParameterSet::Haetae3 => 1472,
        ParameterSet::Haetae5 => 2080,
    }
}

/// Reference secret-key size for the selected parameter set.
pub const fn secret_key_bytes(mode: ParameterSet) -> usize {
    match mode {
        ParameterSet::Haetae2 => 1408,
        ParameterSet::Haetae3 => 2112,
        ParameterSet::Haetae5 => 2752,
    }
}

fn key_dimensions(mode: ParameterSet) -> (usize, usize) {
    match mode {
        ParameterSet::Haetae2 => (2, 3),
        ParameterSet::Haetae3 => (3, 5),
        ParameterSet::Haetae5 => (4, 6),
    }
}

/// Encode the reference verification key: rhoprime || packed public_b.
pub fn pack_vk<const K: usize>(
    rhoprime: &[u8; 32],
    public_b: &crate::polyvec::PolyVecK<K>,
    mode: ParameterSet,
) -> Result<Vec<u8>, PackingError> {
    let (expected_k, _) = key_dimensions(mode);

    if K != expected_k {
        return Err(PackingError::InvalidLength {
            expected: expected_k,
            actual: K,
        });
    }

    let mut encoded = Vec::with_capacity(public_key_bytes(mode));
    encoded.extend_from_slice(rhoprime);

    for polynomial in public_b.as_slice() {
        encoded.extend_from_slice(&pack_poly_q(polynomial, mode)?);
    }

    debug_assert_eq!(encoded.len(), public_key_bytes(mode));
    Ok(encoded)
}

/// Encode the reference secret key:
/// packed_vk || packed_s1 || packed_s2 || key.
///
/// HAETAE-5 uses poly_eta for s2; HAETAE-2/3 use poly2_eta.
pub fn pack_sk<const M: usize, const K: usize>(
    packed_vk: &[u8],
    s1: &crate::polyvec::PolyVecM<M>,
    s2: &crate::polyvec::PolyVecK<K>,
    key: &[u8; 32],
    mode: ParameterSet,
) -> Result<Vec<u8>, PackingError> {
    let (expected_k, expected_m) = key_dimensions(mode);

    if packed_vk.len() != public_key_bytes(mode) {
        return Err(PackingError::InvalidLength {
            expected: public_key_bytes(mode),
            actual: packed_vk.len(),
        });
    }

    if M != expected_m {
        return Err(PackingError::InvalidLength {
            expected: expected_m,
            actual: M,
        });
    }

    if K != expected_k {
        return Err(PackingError::InvalidLength {
            expected: expected_k,
            actual: K,
        });
    }

    let mut encoded = Vec::with_capacity(secret_key_bytes(mode));
    encoded.extend_from_slice(packed_vk);

    for polynomial in s1.as_slice() {
        encoded.extend_from_slice(&pack_poly_eta(polynomial)?);
    }

    for polynomial in s2.as_slice() {
        let packed = match mode {
            ParameterSet::Haetae2 | ParameterSet::Haetae3 => pack_poly2_eta(polynomial)?,
            ParameterSet::Haetae5 => pack_poly_eta(polynomial)?,
        };
        encoded.extend_from_slice(&packed);
    }

    encoded.extend_from_slice(key);

    debug_assert_eq!(encoded.len(), secret_key_bytes(mode));
    Ok(encoded)
}

#[cfg(test)]
mod tests {

    #[test]
    fn key_serialization_lengths_match_reference() {
        assert_eq!(super::public_key_bytes(ParameterSet::Haetae2), 992);
        assert_eq!(super::secret_key_bytes(ParameterSet::Haetae2), 1408);
        assert_eq!(super::public_key_bytes(ParameterSet::Haetae3), 1472);
        assert_eq!(super::secret_key_bytes(ParameterSet::Haetae3), 2112);
        assert_eq!(super::public_key_bytes(ParameterSet::Haetae5), 2080);
        assert_eq!(super::secret_key_bytes(ParameterSet::Haetae5), 2752);
    }

    #[test]
    fn eta_round_trip_all_values() {
        let mut coefficients = [0_i32; N];
        for (i, coefficient) in coefficients.iter_mut().enumerate() {
            *coefficient = (i % 3) as i32 - 1;
        }

        let original = Poly::new(coefficients);
        let encoded = super::pack_poly_eta(&original).unwrap();

        assert_eq!(encoded.len(), super::POLY_ETA_PACKED_BYTES);
        assert_eq!(super::unpack_poly_eta(&encoded).unwrap(), original);
    }

    #[test]
    fn two_eta_round_trip_all_values() {
        let mut coefficients = [0_i32; N];
        for (i, coefficient) in coefficients.iter_mut().enumerate() {
            *coefficient = (i % 5) as i32 - 2;
        }

        let original = Poly::new(coefficients);
        let encoded = super::pack_poly2_eta(&original).unwrap();

        assert_eq!(encoded.len(), super::POLY2_ETA_PACKED_BYTES);
        assert_eq!(super::unpack_poly2_eta(&encoded).unwrap(), original);
    }

    #[test]
    fn eta_known_encoding() {
        let mut coefficients = [0_i32; N];
        coefficients[..4].copy_from_slice(&[-1, 0, 1, -1]);

        let encoded = super::pack_poly_eta(&Poly::new(coefficients)).unwrap();
        assert_eq!(encoded[0], 0x86);
    }

    #[test]
    fn two_eta_known_encoding() {
        let mut coefficients = [0_i32; N];
        coefficients[..8].copy_from_slice(&[-2, -1, 0, 1, 2, -2, -1, 0]);

        let encoded = super::pack_poly2_eta(&Poly::new(coefficients)).unwrap();
        assert_eq!(&encoded[..3], &[0x9c, 0x02, 0x4e]);
    }

    #[test]
    fn eta_rejects_noncanonical_encoding() {
        let encoded = [0xff_u8; super::POLY_ETA_PACKED_BYTES];
        assert!(super::unpack_poly_eta(&encoded).is_err());
    }

    #[test]
    fn two_eta_rejects_noncanonical_encoding() {
        let encoded = [0xff_u8; super::POLY2_ETA_PACKED_BYTES];
        assert!(super::unpack_poly2_eta(&encoded).is_err());
    }

    #[test]
    fn eta_rejects_invalid_coefficients() {
        let mut coefficients = [0_i32; N];
        coefficients[17] = 2;

        assert!(super::pack_poly_eta(&Poly::new(coefficients)).is_err());
    }

    #[test]
    fn two_eta_rejects_invalid_coefficients() {
        let mut coefficients = [0_i32; N];
        coefficients[17] = -3;

        assert!(super::pack_poly2_eta(&Poly::new(coefficients)).is_err());
    }

    #[test]
    fn eta_rejects_incorrect_lengths() {
        assert!(super::unpack_poly_eta(&[0_u8; 63]).is_err());
        assert!(super::unpack_poly_eta(&[0_u8; 65]).is_err());
        assert!(super::unpack_poly2_eta(&[0_u8; 95]).is_err());
        assert!(super::unpack_poly2_eta(&[0_u8; 97]).is_err());
    }
    use super::*;

    fn modes() -> [ParameterSet; 3] {
        [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ]
    }

    fn maximum(mode: ParameterSet) -> i32 {
        match mode {
            ParameterSet::Haetae2 | ParameterSet::Haetae3 => 0x7fff,
            ParameterSet::Haetae5 => Q - 1,
        }
    }

    #[test]
    fn encoded_lengths_match_reference() {
        assert_eq!(poly_q_packed_bytes(ParameterSet::Haetae2), 480);
        assert_eq!(poly_q_packed_bytes(ParameterSet::Haetae3), 480);
        assert_eq!(poly_q_packed_bytes(ParameterSet::Haetae5), 512);
    }

    #[test]
    fn zero_polynomial_encodes_to_zero_bytes() {
        for mode in modes() {
            let encoded = pack_poly_q(&Poly::default(), mode).unwrap();
            assert_eq!(encoded.len(), poly_q_packed_bytes(mode));
            assert!(encoded.iter().all(|&byte| byte == 0));
        }
    }

    #[test]
    fn round_trip_boundary_coefficients() {
        for mode in modes() {
            let max = maximum(mode);
            let coefficients = std::array::from_fn(|index| match index % 4 {
                0 => 0,
                1 => 1,
                2 => max - 1,
                _ => max,
            });

            let original = Poly::new(coefficients);
            let encoded = pack_poly_q(&original, mode).unwrap();
            let decoded = unpack_poly_q(&encoded, mode).unwrap();

            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn round_trip_deterministic_coefficients() {
        for mode in modes() {
            let modulus = maximum(mode) + 1;
            let coefficients =
                std::array::from_fn(|index| ((index as i32 * 7919 + 12345) % modulus).abs());

            let original = Poly::new(coefficients);
            let encoded = pack_poly_q(&original, mode).unwrap();
            let decoded = unpack_poly_q(&encoded, mode).unwrap();

            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn rejects_out_of_range_coefficients() {
        for mode in modes() {
            let mut polynomial = Poly::default();
            polynomial.coeffs[17] = -1;

            assert_eq!(
                pack_poly_q(&polynomial, mode),
                Err(PackingError::InvalidCoefficient {
                    index: 17,
                    value: -1,
                })
            );

            polynomial.coeffs[17] = maximum(mode) + 1;

            assert_eq!(
                pack_poly_q(&polynomial, mode),
                Err(PackingError::InvalidCoefficient {
                    index: 17,
                    value: maximum(mode) + 1,
                })
            );
        }
    }

    #[test]
    fn rejects_incorrect_input_lengths() {
        for mode in modes() {
            let expected = poly_q_packed_bytes(mode);

            for actual in [0, expected - 1, expected + 1] {
                let input = vec![0_u8; actual];

                assert_eq!(
                    unpack_poly_q(&input, mode),
                    Err(PackingError::InvalidLength { expected, actual })
                );
            }
        }
    }

    #[test]
    fn rejects_noncanonical_haetae5_coefficients() {
        let mut encoded = vec![0_u8; 512];

        encoded[0] = 0xff;
        encoded[1] = 0xff;

        assert_eq!(
            unpack_poly_q(&encoded, ParameterSet::Haetae5),
            Err(PackingError::InvalidCoefficient {
                index: 0,
                value: 65535,
            })
        );
    }

    #[test]
    fn little_endian_known_encoding() {
        let mut coefficients = [0_i32; N];
        coefficients[0] = 0x1234;
        coefficients[1] = 0x2345;

        let polynomial = Poly::new(coefficients);

        let encoded = pack_poly_q(&polynomial, ParameterSet::Haetae2).unwrap();

        assert_eq!(&encoded[..4], &[0x34, 0x92, 0xa2, 0x11]);

        let encoded5 = pack_poly_q(&polynomial, ParameterSet::Haetae5).unwrap();

        assert_eq!(&encoded5[..4], &[0x34, 0x12, 0x45, 0x23]);
    }
}

// H1.3-B.5C: serialized secret-key decoding.

/// Decoded HAETAE secret-key components, excluding matrix reconstruction.
#[derive(Clone, Eq, PartialEq)]
pub struct DecodedSecretKey<const K: usize, const M: usize> {
    pub public_key: Vec<u8>,
    pub s0: crate::polyvec::PolyVecM<M>,
    pub s1: crate::polyvec::PolyVecK<K>,
    pub key: [u8; 32],
}

/// Decode the secret-key serialization produced by the reference PackSK.
///
/// The signing matrix is reconstructed separately by UnpackVK.
pub fn unpack_secret_key<const K: usize, const M: usize>(
    encoded: &[u8],
    mode: ParameterSet,
) -> Result<DecodedSecretKey<K, M>, PackingError> {
    let params = mode.parameters();

    if encoded.len() != secret_key_bytes(mode) {
        return Err(PackingError::InvalidLength {
            expected: secret_key_bytes(mode),
            actual: encoded.len(),
        });
    }

    if K != params.k || M != params.l - 1 {
        return Err(PackingError::InvalidLength {
            expected: params.k + params.l - 1,
            actual: K + M,
        });
    }

    let pk_len = public_key_bytes(mode);
    let public_key = encoded[..pk_len].to_vec();

    let mut offset = pk_len;

    let mut s0 = crate::polyvec::PolyVecM::<M>::default();

    for polynomial in &mut s0.0.vec {
        let end = offset + POLY_ETA_PACKED_BYTES;
        *polynomial = unpack_poly_eta(&encoded[offset..end])?;
        offset = end;
    }

    let mut s1 = crate::polyvec::PolyVecK::<K>::default();

    for polynomial in &mut s1.0.vec {
        let polynomial_bytes = match mode {
            ParameterSet::Haetae2 | ParameterSet::Haetae3 => POLY2_ETA_PACKED_BYTES,
            ParameterSet::Haetae5 => POLY_ETA_PACKED_BYTES,
        };

        let end = offset + polynomial_bytes;

        *polynomial = match mode {
            ParameterSet::Haetae2 | ParameterSet::Haetae3 => {
                unpack_poly2_eta(&encoded[offset..end])?
            }
            ParameterSet::Haetae5 => unpack_poly_eta(&encoded[offset..end])?,
        };

        offset = end;
    }

    let key: [u8; 32] = encoded[offset..]
        .try_into()
        .map_err(|_| PackingError::InvalidLength {
            expected: 32,
            actual: encoded.len() - offset,
        })?;

    Ok(DecodedSecretKey {
        public_key,
        s0,
        s1,
        key,
    })
}

// H1.3-B.5D.3: verification-key matrix reconstruction.

/// Reconstructed verification key containing the complete signing matrix.
///
/// Each row contains M+1 polynomials. The first column is reconstructed
/// from the packed public vector; the remaining columns are expanded
/// from the public seed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconstructedVerificationKey<const K: usize, const L: usize> {
    pub matrix: [crate::polyvec::PolyVecL<L>; K],
}

/// Reconstruct Algorithm 24 (UnpackVK) from the serialized public key.
///
/// This is a structural implementation. Exact coefficient-level parity
/// against the C reference is established in a separate integration gate.
pub fn unpack_verification_key<const K: usize, const L: usize>(
    encoded: &[u8],
    mode: ParameterSet,
) -> Result<ReconstructedVerificationKey<K, L>, PackingError> {
    let params = mode.parameters();

    if encoded.len() != public_key_bytes(mode) {
        return Err(PackingError::InvalidLength {
            expected: public_key_bytes(mode),
            actual: encoded.len(),
        });
    }

    if K != params.k || L != params.l {
        return Err(PackingError::InvalidLength {
            expected: params.k + params.l,
            actual: K + L,
        });
    }

    let seed: [u8; 32] = encoded[..32]
        .try_into()
        .expect("validated public-key seed length");

    let polynomial_bytes = poly_q_packed_bytes(mode);
    let mut offset = 32;

    let mut public_b = crate::polyvec::PolyVecK::<K>::default();

    for polynomial in &mut public_b.0.vec {
        let end = offset + polynomial_bytes;
        *polynomial = unpack_poly_q(&encoded[offset..end], mode)?;
        offset = end;
    }

    let mut first_column = public_b;

    if matches!(mode, ParameterSet::Haetae2 | ParameterSet::Haetae3) {
        let auxiliary = crate::polyvec::PolyVecK::<K>::expand_vec_a(&seed, mode);

        first_column.double();
        first_column = auxiliary.sub(&first_column);
        first_column.double();
        first_column.ntt();
    }

    // Const-generic matrix construction uses the existing expansion's
    // nonce schedule, with columns shifted by one for signing.
    //
    // L = M+1, so the expanded K-by-M matrix is reconstructed
    // directly using the same authenticated uniform sampler.
    let matrix = std::array::from_fn(|row| {
        crate::polyvec::PolyVecL::<L>::new(std::array::from_fn(|column| {
            if column == 0 {
                first_column.as_slice()[row].clone()
            } else {
                let nonce = (row << 8) + (column - 1);
                let mut polynomial =
                    crate::sampling::uniform(&seed, u16::try_from(nonce).expect("validated nonce"));

                for coefficient in &mut polynomial.coeffs {
                    *coefficient = coefficient
                        .checked_mul(2)
                        .expect("HAETAE matrix doubling overflow");
                }

                polynomial
            }
        }))
    });

    Ok(ReconstructedVerificationKey { matrix })
}

#[cfg(test)]
mod verification_key_reconstruction_tests {
    use super::*;

    #[test]
    fn authenticated_verification_matrix_matches_independent_c() {
        fn check<const K: usize, const L: usize>(
            mode: ParameterSet,
            mode_number: usize,
            case: usize,
            root: &std::path::Path,
        ) -> usize {
            let path = root.join(format!("mode{mode_number}_case{case}.json"));

            let evidence: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(path).expect("read independent C matrix evidence"),
            )
            .expect("parse independent C matrix evidence");

            assert_eq!(
                evidence["format"].as_str(),
                Some("HAETAE_C_VERIFICATION_MATRIX_V1")
            );
            assert_eq!(evidence["mode"].as_u64(), Some(mode_number as u64));
            assert_eq!(evidence["case"].as_u64(), Some(case as u64));
            assert_eq!(evidence["k"].as_u64(), Some(K as u64));
            assert_eq!(evidence["l"].as_u64(), Some(L as u64));

            let hex = evidence["public_key_hex"].as_str().expect("public key hex");

            assert_eq!(hex.len(), public_key_bytes(mode) * 2);

            let public_key = hex
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>();

            let reconstructed = unpack_verification_key::<K, L>(&public_key, mode)
                .expect("authenticated verification key must decode");

            let expected = evidence["matrix"]
                .as_array()
                .expect("independent C matrix coefficients");

            assert_eq!(expected.len(), K * L * crate::params::N);

            let mut checked = 0_usize;

            for row in 0..K {
                for column in 0..L {
                    for index in 0..crate::params::N {
                        let flat = (row * L + column) * crate::params::N + index;

                        let actual = reconstructed.matrix[row].as_slice()[column].coeffs[index];

                        assert_eq!(
                            Some(i64::from(actual)),
                            expected[flat].as_i64(),
                            "C/Rust verification matrix mismatch: \
                             mode={mode_number} case={case} \
                             row={row} column={column} coefficient={index}"
                        );

                        checked += 1;
                    }
                }
            }

            println!(
                "HAETAE_RUST_MATRIX_MODE={mode_number} CASE={case} \
                 COEFFICIENTS={checked} STATUS=PASS"
            );

            checked
        }

        let root = std::env::var("HAETAE_C_VERIFICATION_MATRIX_PARITY_DIR")
            .expect("HAETAE_C_VERIFICATION_MATRIX_PARITY_DIR must be set");

        let root = std::path::Path::new(&root);
        let mut total = 0_usize;

        for case in 0..5 {
            total += check::<2, 4>(ParameterSet::Haetae2, 2, case, root);
            total += check::<3, 6>(ParameterSet::Haetae3, 3, case, root);
            total += check::<4, 7>(ParameterSet::Haetae5, 5, case, root);
        }

        assert_eq!(total, 69_120);

        println!("HAETAE_RUST_MATRIX_TOTAL={total} STATUS=PASS");
    }

    #[test]
    fn rejects_invalid_public_key_length() {
        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let wrong = vec![0_u8; public_key_bytes(mode) - 1];

            assert!(unpack_verification_key::<2, 4>(&wrong, mode).is_err());
        }
    }

    #[test]
    fn rejects_invalid_matrix_dimensions() {
        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let encoded = vec![0_u8; public_key_bytes(mode)];

            assert!(unpack_verification_key::<1, 1>(&encoded, mode).is_err());
        }
    }
}
