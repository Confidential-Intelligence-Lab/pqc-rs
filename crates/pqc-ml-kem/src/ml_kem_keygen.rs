//! Deterministic ML-KEM key generation for ACVP and conformance testing.
//!
//! FIPS 203 `ML-KEM.KeyGen_internal` consumes two 32-byte values, `d` and `z`.
//! The decapsulation key is assembled as `dkPKE || ek || H(ek) || z`.

use pqc_core::PqcResult;

use crate::kpke_keygen;
use crate::symmetric;
use crate::MlKemParameterSet;

/// Deterministic ML-KEM key-generation output.
#[derive(Clone, Eq, PartialEq)]
pub struct MlKemKeygenOutput<const EK_BYTES: usize, const DK_BYTES: usize> {
    /// Encapsulation key.
    pub encapsulation_key: [u8; EK_BYTES],
    /// Decapsulation key.
    pub decapsulation_key: [u8; DK_BYTES],
}

/// Execute deterministic ML-KEM-512 key generation from `d` and `z`.
pub fn ml_kem_512_keygen_internal(
    d: &[u8; 32],
    z: &[u8; 32],
) -> PqcResult<MlKemKeygenOutput<800, 1632>> {
    keygen_internal::<800, 768, 1632>(MlKemParameterSet::MlKem512, d, z)
}

/// Execute deterministic ML-KEM-768 key generation from `d` and `z`.
pub fn ml_kem_768_keygen_internal(
    d: &[u8; 32],
    z: &[u8; 32],
) -> PqcResult<MlKemKeygenOutput<1184, 2400>> {
    keygen_internal::<1184, 1152, 2400>(MlKemParameterSet::MlKem768, d, z)
}

/// Execute deterministic ML-KEM-1024 key generation from `d` and `z`.
pub fn ml_kem_1024_keygen_internal(
    d: &[u8; 32],
    z: &[u8; 32],
) -> PqcResult<MlKemKeygenOutput<1568, 3168>> {
    keygen_internal::<1568, 1536, 3168>(MlKemParameterSet::MlKem1024, d, z)
}

fn keygen_internal<const EK_BYTES: usize, const DK_PKE_BYTES: usize, const DK_BYTES: usize>(
    parameter_set: MlKemParameterSet,
    d: &[u8; 32],
    z: &[u8; 32],
) -> PqcResult<MlKemKeygenOutput<EK_BYTES, DK_BYTES>> {
    debug_assert_eq!(DK_BYTES, DK_PKE_BYTES + EK_BYTES + 64);

    let kpke = kpke_keygen::keygen_from_seed::<EK_BYTES, DK_PKE_BYTES>(parameter_set, d)?;
    let ek_hash = symmetric::h(&kpke.public_key);

    let mut decapsulation_key = [0u8; DK_BYTES];
    let mut offset = 0usize;

    decapsulation_key[offset..offset + DK_PKE_BYTES].copy_from_slice(&kpke.secret_key);
    offset += DK_PKE_BYTES;

    decapsulation_key[offset..offset + EK_BYTES].copy_from_slice(&kpke.public_key);
    offset += EK_BYTES;

    decapsulation_key[offset..offset + 32].copy_from_slice(&ek_hash);
    offset += 32;

    decapsulation_key[offset..offset + 32].copy_from_slice(z);

    Ok(MlKemKeygenOutput {
        encapsulation_key: kpke.public_key,
        decapsulation_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_internal_is_deterministic_for_all_parameter_sets() {
        let d = [0x11u8; 32];
        let z = [0x22u8; 32];

        assert!(
            ml_kem_512_keygen_internal(&d, &z).unwrap()
                == ml_kem_512_keygen_internal(&d, &z).unwrap()
        );
        assert!(
            ml_kem_768_keygen_internal(&d, &z).unwrap()
                == ml_kem_768_keygen_internal(&d, &z).unwrap()
        );
        assert!(
            ml_kem_1024_keygen_internal(&d, &z).unwrap()
                == ml_kem_1024_keygen_internal(&d, &z).unwrap()
        );
    }

    #[test]
    fn decapsulation_key_layout_ends_with_hash_and_z() {
        let d = [0x33u8; 32];
        let z = [0x44u8; 32];
        let output = ml_kem_512_keygen_internal(&d, &z).unwrap();
        let ek_hash = symmetric::h(&output.encapsulation_key);

        assert_eq!(&output.decapsulation_key[1568..1600], &ek_hash);
        assert_eq!(&output.decapsulation_key[1600..1632], &z);
    }

    #[test]
    fn key_lengths_match_fips_203_parameter_sets() {
        let d = [0u8; 32];
        let z = [1u8; 32];

        let k512 = ml_kem_512_keygen_internal(&d, &z).unwrap();
        let k768 = ml_kem_768_keygen_internal(&d, &z).unwrap();
        let k1024 = ml_kem_1024_keygen_internal(&d, &z).unwrap();

        assert_eq!(k512.encapsulation_key.len(), 800);
        assert_eq!(k512.decapsulation_key.len(), 1632);
        assert_eq!(k768.encapsulation_key.len(), 1184);
        assert_eq!(k768.decapsulation_key.len(), 2400);
        assert_eq!(k1024.encapsulation_key.len(), 1568);
        assert_eq!(k1024.decapsulation_key.len(), 3168);
    }
}
