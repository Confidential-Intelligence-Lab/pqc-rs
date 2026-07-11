//! FIPS 203 ML-KEM key-input checks.
//!
//! This module implements the encapsulation-key check from Section 7.2 and
//! the decapsulation-key check from Section 7.3.

use subtle::ConstantTimeEq;

use crate::symmetric;
use crate::MlKemParameterSet;

const Q: u16 = 3329;

/// Check an ML-KEM encapsulation key according to FIPS 203 Section 7.2.
///
/// The check enforces:
///
/// 1. the parameter-set-specific byte length; and
/// 2. canonical 12-bit encoding of every public-key coefficient.
pub fn encapsulation_key_is_valid(
    parameter_set: MlKemParameterSet,
    encapsulation_key: &[u8],
) -> bool {
    let layout = KeyLayout::for_parameter_set(parameter_set);

    if encapsulation_key.len() != layout.ek_bytes {
        return false;
    }

    let encoded_vector = &encapsulation_key[..layout.dk_pke_bytes];

    encoded_vector.chunks_exact(3).all(|chunk| {
        let first = u16::from(chunk[0]) | (u16::from(chunk[1] & 0x0f) << 8);
        let second = (u16::from(chunk[1]) >> 4) | (u16::from(chunk[2]) << 4);

        first < Q && second < Q
    })
}

/// Check an ML-KEM decapsulation key according to FIPS 203 Section 7.3.
///
/// The check enforces:
///
/// 1. the parameter-set-specific byte length; and
/// 2. consistency of the stored `H(ek)` field.
pub fn decapsulation_key_is_valid(
    parameter_set: MlKemParameterSet,
    decapsulation_key: &[u8],
) -> bool {
    let layout = KeyLayout::for_parameter_set(parameter_set);

    if decapsulation_key.len() != layout.dk_bytes {
        return false;
    }

    let ek_start = layout.dk_pke_bytes;
    let ek_end = ek_start + layout.ek_bytes;
    let embedded_ek = &decapsulation_key[ek_start..ek_end];
    let stored_hash = &decapsulation_key[ek_end..ek_end + 32];
    let computed_hash = symmetric::h(embedded_ek);

    bool::from(computed_hash.ct_eq(stored_hash))
}

#[derive(Clone, Copy)]
struct KeyLayout {
    ek_bytes: usize,
    dk_pke_bytes: usize,
    dk_bytes: usize,
}

impl KeyLayout {
    const fn for_parameter_set(parameter_set: MlKemParameterSet) -> Self {
        match parameter_set {
            MlKemParameterSet::MlKem512 => Self {
                ek_bytes: 800,
                dk_pke_bytes: 768,
                dk_bytes: 1632,
            },
            MlKemParameterSet::MlKem768 => Self {
                ek_bytes: 1184,
                dk_pke_bytes: 1152,
                dk_bytes: 2400,
            },
            MlKemParameterSet::MlKem1024 => Self {
                ek_bytes: 1568,
                dk_pke_bytes: 1536,
                dk_bytes: 3168,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_kem_keygen::{
        ml_kem_1024_keygen_internal, ml_kem_512_keygen_internal, ml_kem_768_keygen_internal,
    };

    #[test]
    fn generated_keys_pass_checks() {
        let d = [0x11u8; 32];
        let z = [0x22u8; 32];

        let k512 = ml_kem_512_keygen_internal(&d, &z).unwrap();
        assert!(encapsulation_key_is_valid(
            MlKemParameterSet::MlKem512,
            &k512.encapsulation_key,
        ));
        assert!(decapsulation_key_is_valid(
            MlKemParameterSet::MlKem512,
            &k512.decapsulation_key,
        ));

        let k768 = ml_kem_768_keygen_internal(&d, &z).unwrap();
        assert!(encapsulation_key_is_valid(
            MlKemParameterSet::MlKem768,
            &k768.encapsulation_key,
        ));
        assert!(decapsulation_key_is_valid(
            MlKemParameterSet::MlKem768,
            &k768.decapsulation_key,
        ));

        let k1024 = ml_kem_1024_keygen_internal(&d, &z).unwrap();
        assert!(encapsulation_key_is_valid(
            MlKemParameterSet::MlKem1024,
            &k1024.encapsulation_key,
        ));
        assert!(decapsulation_key_is_valid(
            MlKemParameterSet::MlKem1024,
            &k1024.decapsulation_key,
        ));
    }

    #[test]
    fn encapsulation_key_rejects_noncanonical_coefficient() {
        let d = [0x33u8; 32];
        let z = [0x44u8; 32];
        let mut key = ml_kem_512_keygen_internal(&d, &z)
            .unwrap()
            .encapsulation_key;

        // Encode 4095 in the first 12-bit lane.
        key[0] = 0xff;
        key[1] = (key[1] & 0xf0) | 0x0f;

        assert!(!encapsulation_key_is_valid(
            MlKemParameterSet::MlKem512,
            &key,
        ));
    }

    #[test]
    fn decapsulation_key_rejects_modified_hash() {
        let d = [0x55u8; 32];
        let z = [0x66u8; 32];
        let mut key = ml_kem_512_keygen_internal(&d, &z)
            .unwrap()
            .decapsulation_key;

        let hash_offset = 768 + 800;
        key[hash_offset] ^= 1;

        assert!(!decapsulation_key_is_valid(
            MlKemParameterSet::MlKem512,
            &key,
        ));
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        assert!(!encapsulation_key_is_valid(
            MlKemParameterSet::MlKem512,
            &[0u8; 799],
        ));
        assert!(!decapsulation_key_is_valid(
            MlKemParameterSet::MlKem512,
            &[0u8; 1631],
        ));
    }
}
