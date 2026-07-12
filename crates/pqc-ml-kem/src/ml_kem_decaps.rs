//! Deterministic FIPS 203 ML-KEM decapsulation.
//!
//! This module implements `ML-KEM.Decaps_internal(dk, c)`, including
//! deterministic re-encryption, constant-time ciphertext comparison, and
//! implicit rejection.

use pqc_core::{PqcError, PqcResult, SharedSecretBytes};
use subtle::ConstantTimeEq;

use crate::kpke::EncryptionRandomness;
use crate::kpke_decrypt;
use crate::kpke_encrypt;
use crate::symmetric;
use crate::MlKemParameterSet;

/// ML-KEM shared-secret length.
pub const ML_KEM_SHARED_SECRET_BYTES: usize = 32;

/// Deterministic decapsulation output.
#[derive(Clone)]
pub struct MlKemDecapsulationOutput {
    /// Decapsulated shared secret.
    pub shared_secret: SharedSecretBytes<ML_KEM_SHARED_SECRET_BYTES>,
}

/// Execute FIPS 203 `ML-KEM.Decaps_internal(dk, c)`.
pub fn decaps_internal(
    parameter_set: MlKemParameterSet,
    decapsulation_key: &[u8],
    ciphertext: &[u8],
) -> PqcResult<MlKemDecapsulationOutput> {
    let layout = DecapsulationKeyLayout::for_parameter_set(parameter_set);

    if decapsulation_key.len() != layout.dk_bytes {
        return Err(PqcError::InvalidLength {
            expected: layout.dk_bytes,
            actual: decapsulation_key.len(),
        });
    }

    if ciphertext.len() != layout.ct_bytes {
        return Err(PqcError::InvalidLength {
            expected: layout.ct_bytes,
            actual: ciphertext.len(),
        });
    }

    let dk_pke = &decapsulation_key[..layout.dk_pke_bytes];
    let ek_start = layout.dk_pke_bytes;
    let ek_end = ek_start + layout.ek_bytes;
    let ek = &decapsulation_key[ek_start..ek_end];
    let h = &decapsulation_key[ek_end..ek_end + 32];
    let z = &decapsulation_key[ek_end + 32..ek_end + 64];

    let decrypted = kpke_decrypt::decrypt_to_message(parameter_set, dk_pke, ciphertext)?;

    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(decrypted.message.as_bytes());
    g_input[32..].copy_from_slice(h);
    let expanded = symmetric::g(&g_input);

    let mut candidate_secret = [0u8; 32];
    let mut randomness = [0u8; 32];
    candidate_secret.copy_from_slice(&expanded[..32]);
    randomness.copy_from_slice(&expanded[32..]);

    let reencryption_randomness = EncryptionRandomness::new(randomness);
    let expected_ciphertext = reencryption(
        parameter_set,
        ek,
        &decrypted.message,
        &reencryption_randomness,
    )?;

    let mut rejection_input = Vec::with_capacity(32 + ciphertext.len());
    rejection_input.extend_from_slice(z);
    rejection_input.extend_from_slice(ciphertext);
    let rejection_secret = symmetric::j(&rejection_input);

    let equal = ciphertext.ct_eq(expected_ciphertext.as_slice());
    let mask = 0u8.wrapping_sub(equal.unwrap_u8());

    let mut selected = [0u8; 32];
    let mut index = 0usize;
    while index < selected.len() {
        selected[index] = (candidate_secret[index] & mask) | (rejection_secret[index] & !mask);
        index += 1;
    }

    Ok(MlKemDecapsulationOutput {
        shared_secret: SharedSecretBytes::new(selected),
    })
}

fn reencryption(
    parameter_set: MlKemParameterSet,
    ek: &[u8],
    message: &crate::kpke::Message,
    randomness: &EncryptionRandomness,
) -> PqcResult<Vec<u8>> {
    match parameter_set {
        MlKemParameterSet::MlKem512 => Ok(kpke_encrypt::encrypt_from_randomness::<768>(
            parameter_set,
            ek,
            message,
            randomness,
        )?
        .ciphertext
        .to_vec()),
        MlKemParameterSet::MlKem768 => Ok(kpke_encrypt::encrypt_from_randomness::<1088>(
            parameter_set,
            ek,
            message,
            randomness,
        )?
        .ciphertext
        .to_vec()),
        MlKemParameterSet::MlKem1024 => Ok(kpke_encrypt::encrypt_from_randomness::<1568>(
            parameter_set,
            ek,
            message,
            randomness,
        )?
        .ciphertext
        .to_vec()),
    }
}

#[derive(Clone, Copy)]
struct DecapsulationKeyLayout {
    ek_bytes: usize,
    dk_pke_bytes: usize,
    dk_bytes: usize,
    ct_bytes: usize,
}

impl DecapsulationKeyLayout {
    const fn for_parameter_set(parameter_set: MlKemParameterSet) -> Self {
        match parameter_set {
            MlKemParameterSet::MlKem512 => Self {
                ek_bytes: 800,
                dk_pke_bytes: 768,
                dk_bytes: 1632,
                ct_bytes: 768,
            },
            MlKemParameterSet::MlKem768 => Self {
                ek_bytes: 1184,
                dk_pke_bytes: 1152,
                dk_bytes: 2400,
                ct_bytes: 1088,
            },
            MlKemParameterSet::MlKem1024 => Self {
                ek_bytes: 1568,
                dk_pke_bytes: 1536,
                dk_bytes: 3168,
                ct_bytes: 1568,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_kem_encaps::encaps_internal;
    use crate::ml_kem_keygen::{
        ml_kem_1024_keygen_internal, ml_kem_512_keygen_internal, ml_kem_768_keygen_internal,
    };

    #[test]
    fn valid_ciphertexts_round_trip_for_all_parameter_sets() {
        let d = [0x11u8; 32];
        let z = [0x22u8; 32];
        let m = [0x33u8; 32];

        let k512 = ml_kem_512_keygen_internal(&d, &z).unwrap();
        let e512 =
            encaps_internal(MlKemParameterSet::MlKem512, &k512.encapsulation_key, &m).unwrap();
        let d512 = decaps_internal(
            MlKemParameterSet::MlKem512,
            &k512.decapsulation_key,
            &e512.ciphertext,
        )
        .unwrap();
        assert_eq!(d512.shared_secret.as_bytes(), e512.shared_secret.as_bytes());

        let k768 = ml_kem_768_keygen_internal(&d, &z).unwrap();
        let e768 =
            encaps_internal(MlKemParameterSet::MlKem768, &k768.encapsulation_key, &m).unwrap();
        let d768 = decaps_internal(
            MlKemParameterSet::MlKem768,
            &k768.decapsulation_key,
            &e768.ciphertext,
        )
        .unwrap();
        assert_eq!(d768.shared_secret.as_bytes(), e768.shared_secret.as_bytes());

        let k1024 = ml_kem_1024_keygen_internal(&d, &z).unwrap();
        let e1024 =
            encaps_internal(MlKemParameterSet::MlKem1024, &k1024.encapsulation_key, &m).unwrap();
        let d1024 = decaps_internal(
            MlKemParameterSet::MlKem1024,
            &k1024.decapsulation_key,
            &e1024.ciphertext,
        )
        .unwrap();
        assert_eq!(
            d1024.shared_secret.as_bytes(),
            e1024.shared_secret.as_bytes()
        );
    }

    #[test]
    fn modified_ciphertext_uses_implicit_rejection() {
        let d = [0x44u8; 32];
        let z = [0x55u8; 32];
        let m = [0x66u8; 32];

        let keypair = ml_kem_512_keygen_internal(&d, &z).unwrap();
        let encapsulated =
            encaps_internal(MlKemParameterSet::MlKem512, &keypair.encapsulation_key, &m).unwrap();

        let mut modified = encapsulated.ciphertext.clone();
        modified[0] ^= 1;

        let decapsulated = decaps_internal(
            MlKemParameterSet::MlKem512,
            &keypair.decapsulation_key,
            &modified,
        )
        .unwrap();

        assert_ne!(
            decapsulated.shared_secret.as_bytes(),
            encapsulated.shared_secret.as_bytes()
        );
    }
}
