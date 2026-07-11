//! Deterministic FIPS 203 ML-KEM encapsulation entry points.

use pqc_core::{PqcError, PqcResult, SharedSecretBytes};

use crate::kpke::{EncryptionRandomness, Message};
use crate::kpke_encrypt;
use crate::symmetric;
use crate::MlKemParameterSet;

/// ML-KEM shared-secret length in bytes.
pub const ML_KEM_SHARED_SECRET_BYTES: usize = 32;

/// Deterministic encapsulation result.
#[derive(Clone, Debug)]
pub struct MlKemEncapsulationOutput {
    /// Encapsulation ciphertext.
    pub ciphertext: Vec<u8>,
    /// Shared secret.
    pub shared_secret: SharedSecretBytes<ML_KEM_SHARED_SECRET_BYTES>,
}

/// Execute FIPS 203 `ML-KEM.Encaps_internal(ek, m)`.
pub fn encaps_internal(
    parameter_set: MlKemParameterSet,
    encapsulation_key: &[u8],
    m: &[u8; 32],
) -> PqcResult<MlKemEncapsulationOutput> {
    if encapsulation_key.len() != parameter_set.public_key_bytes() {
        return Err(PqcError::InvalidLength {
            expected: parameter_set.public_key_bytes(),
            actual: encapsulation_key.len(),
        });
    }

    let ek_hash = symmetric::h(encapsulation_key);
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(m);
    g_input[32..].copy_from_slice(&ek_hash);

    let expanded = symmetric::g(&g_input);
    let mut shared_secret = [0u8; 32];
    let mut randomness = [0u8; 32];
    shared_secret.copy_from_slice(&expanded[..32]);
    randomness.copy_from_slice(&expanded[32..]);

    let message = Message::new(*m);
    let encryption_randomness = EncryptionRandomness::new(randomness);

    let ciphertext = match parameter_set {
        MlKemParameterSet::MlKem512 => kpke_encrypt::encrypt_from_randomness::<768>(
            parameter_set,
            encapsulation_key,
            &message,
            &encryption_randomness,
        )?
        .ciphertext
        .to_vec(),
        MlKemParameterSet::MlKem768 => kpke_encrypt::encrypt_from_randomness::<1088>(
            parameter_set,
            encapsulation_key,
            &message,
            &encryption_randomness,
        )?
        .ciphertext
        .to_vec(),
        MlKemParameterSet::MlKem1024 => kpke_encrypt::encrypt_from_randomness::<1568>(
            parameter_set,
            encapsulation_key,
            &message,
            &encryption_randomness,
        )?
        .ciphertext
        .to_vec(),
    };

    Ok(MlKemEncapsulationOutput {
        ciphertext,
        shared_secret: SharedSecretBytes::new(shared_secret),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encaps_internal_is_deterministic() {
        for (parameter_set, key_length) in [
            (MlKemParameterSet::MlKem512, 800usize),
            (MlKemParameterSet::MlKem768, 1184usize),
            (MlKemParameterSet::MlKem1024, 1568usize),
        ] {
            let ek = vec![0u8; key_length];
            let m = [0x5au8; 32];

            let first = encaps_internal(parameter_set, &ek, &m).unwrap();
            let second = encaps_internal(parameter_set, &ek, &m).unwrap();

            assert_eq!(first.ciphertext, second.ciphertext);
            assert_eq!(
                first.shared_secret.as_bytes(),
                second.shared_secret.as_bytes(),
            );
        }
    }

    #[test]
    fn encaps_internal_rejects_wrong_key_length() {
        assert!(encaps_internal(MlKemParameterSet::MlKem512, &[0u8; 799], &[0u8; 32],).is_err());
    }
}
