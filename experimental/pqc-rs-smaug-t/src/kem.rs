// SPDX-License-Identifier: MIT
//! Experimental deterministic SMAUG-T KEM key generation.
//!
//! Independent Rust implementation of the pinned SMAUG-T 1.1.1
//! reference key-generation serialization contract.
//!
//! Not constant-time audited. Not suitable for production use.

use crate::indcpa::{self, DecryptError, KeypairError};
use crate::indcpa::{encrypt, EncryptError};
use crate::{Parameters, N, SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER};
use sha3::{
    digest::{Digest, ExtendableOutput, Update, XofReader},
    Sha3_256, Shake256,
};
use subtle::{ConditionallySelectable, ConstantTimeEq};

pub const SHARED_SECRET_BYTES: usize = 32;
pub const AUXILIARY_SECRET_BYTES: usize = N / 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KemError {
    UnsupportedParameters,
    IndcpaKeypair(KeypairError),
    IndcpaEncrypt(EncryptError),
    InvalidPublicKeyLength,
    InvalidMessageLength,
    InvalidCiphertextLength,
    InvalidSecretKeyLength,
    IndcpaDecrypt(DecryptError),
}

impl From<KeypairError> for KemError {
    fn from(error: KeypairError) -> Self {
        Self::IndcpaKeypair(error)
    }
}

fn supported(parameters: &Parameters) -> bool {
    matches!(*parameters, SMAUG_T128 | SMAUG_T192 | SMAUG_T256 | TIMER)
}

/// Deterministically generate a SMAUG-T KEM public/secret key pair.
///
/// The KEM secret key is serialized as:
/// `IND-CPA secret key || t || public key`.
///
/// Both randomness inputs must be supplied by the caller.
/// This function is intended for reproducibility and testing.
pub fn keypair(
    seed: &[u8; 32],
    t: &[u8; AUXILIARY_SECRET_BYTES],
    parameters: &Parameters,
) -> Result<(Vec<u8>, Vec<u8>), KemError> {
    if !supported(parameters) {
        return Err(KemError::UnsupportedParameters);
    }

    let (public_key, indcpa_secret_key) = indcpa::keypair(seed, parameters)?;

    let mut secret_key =
        Vec::with_capacity(indcpa_secret_key.len() + AUXILIARY_SECRET_BYTES + public_key.len());

    secret_key.extend_from_slice(&indcpa_secret_key);
    secret_key.extend_from_slice(t);
    secret_key.extend_from_slice(&public_key);

    Ok((public_key, secret_key))
}

/// Deterministically encapsulate using an explicitly supplied message.
///
/// This is the SMAUG-T 1.1.1 internal encapsulation operation.
/// The caller is responsible for supplying appropriate entropy.
/// Not suitable for production use without security review.
pub fn encapsulate_deterministic(
    public_key: &[u8],
    message: &[u8],
    parameters: &Parameters,
) -> Result<(Vec<u8>, [u8; SHARED_SECRET_BYTES]), KemError> {
    if !supported(parameters) {
        return Err(KemError::UnsupportedParameters);
    }

    let public_key_length = 32 + parameters.k * N * parameters.q.trailing_zeros() as usize / 8;

    if public_key.len() != public_key_length {
        return Err(KemError::InvalidPublicKeyLength);
    }

    let message_length = if *parameters == TIMER { 16 } else { 32 };

    if message.len() != message_length {
        return Err(KemError::InvalidMessageLength);
    }

    let pk_hash = Sha3_256::digest(public_key);

    let mut xof = Shake256::default();
    xof.update(message);
    xof.update(&pk_hash);

    let mut reader = xof.finalize_xof();
    let mut material = [0u8; 64];
    reader.read(&mut material);

    let mut encryption_seed = [0u8; 32];
    encryption_seed.copy_from_slice(&material[..32]);

    let ciphertext = encrypt(public_key, message, &encryption_seed, parameters)
        .map_err(KemError::IndcpaEncrypt)?;

    let mut shared_secret = [0u8; SHARED_SECRET_BYTES];
    shared_secret.copy_from_slice(&material[32..64]);

    Ok((ciphertext, shared_secret))
}

/// Decapsulate a SMAUG-T ciphertext with implicit rejection.
///
/// Correctly sized ciphertexts produce a shared secret even when
/// ciphertext verification fails. The validity decision is not
/// returned to the caller.
///
/// Experimental implementation: constant-time machine-code behavior
/// and the complete IND-CPA path have not yet been audited.
pub fn decapsulate(
    ciphertext: &[u8],
    secret_key: &[u8],
    parameters: &Parameters,
) -> Result<[u8; SHARED_SECRET_BYTES], KemError> {
    if !supported(parameters) {
        return Err(KemError::UnsupportedParameters);
    }

    let pke_secret_key_length = parameters.k * 64;
    let public_key_length = 32 + parameters.k * N * parameters.q.trailing_zeros() as usize / 8;

    let ciphertext_length = parameters.k * N * parameters.p.trailing_zeros() as usize / 8
        + N * parameters.p_prime.trailing_zeros() as usize / 8;

    let kem_secret_key_length = pke_secret_key_length + AUXILIARY_SECRET_BYTES + public_key_length;

    if secret_key.len() != kem_secret_key_length {
        return Err(KemError::InvalidSecretKeyLength);
    }

    if ciphertext.len() != ciphertext_length {
        return Err(KemError::InvalidCiphertextLength);
    }

    let (pke_secret_key, remainder) = secret_key.split_at(pke_secret_key_length);

    let (auxiliary_secret, public_key) = remainder.split_at(AUXILIARY_SECRET_BYTES);

    let message =
        indcpa::decrypt(pke_secret_key, ciphertext, parameters).map_err(KemError::IndcpaDecrypt)?;

    let pk_hash = Sha3_256::digest(public_key);

    let mut xof = Shake256::default();
    xof.update(&message);
    xof.update(&pk_hash);

    let mut reader = xof.finalize_xof();
    let mut material = [0u8; 64];
    reader.read(&mut material);

    let mut encryption_seed = [0u8; 32];
    encryption_seed.copy_from_slice(&material[..32]);

    let expected_ciphertext = indcpa::encrypt(public_key, &message, &encryption_seed, parameters)
        .map_err(KemError::IndcpaEncrypt)?;

    let ciphertext_valid = ciphertext.ct_eq(expected_ciphertext.as_slice());

    let ciphertext_hash = Sha3_256::digest(ciphertext);

    let mut rejection_xof = Shake256::default();
    rejection_xof.update(auxiliary_secret);
    rejection_xof.update(&ciphertext_hash);

    let mut rejection_reader = rejection_xof.finalize_xof();
    let mut rejection_material = [0u8; 64];
    rejection_reader.read(&mut rejection_material);

    let reject = !ciphertext_valid;
    let mut shared_secret = [0u8; SHARED_SECRET_BYTES];

    for (index, output) in shared_secret.iter_mut().enumerate() {
        *output = u8::conditional_select(
            &material[32 + index],
            &rejection_material[32 + index],
            reject,
        );
    }

    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decapsulation_recovers_valid_shared_secret() {
        let seed = [0x42u8; 32];
        let auxiliary_secret = [0xA5u8; 32];

        for parameters in [SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER] {
            let (public_key, secret_key) = keypair(&seed, &auxiliary_secret, &parameters).unwrap();

            let message_length = if parameters == TIMER { 16 } else { 32 };
            let message = vec![0x39u8; message_length];

            let (ciphertext, expected_secret) =
                encapsulate_deterministic(&public_key, &message, &parameters).unwrap();

            let recovered_secret = decapsulate(&ciphertext, &secret_key, &parameters).unwrap();

            assert_eq!(recovered_secret, expected_secret);
        }
    }

    #[test]
    fn decapsulation_implicitly_rejects_modified_ciphertext() {
        let seed = [0x42u8; 32];
        let auxiliary_secret = [0xA5u8; 32];

        for parameters in [SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER] {
            let (public_key, secret_key) = keypair(&seed, &auxiliary_secret, &parameters).unwrap();

            let message_length = if parameters == TIMER { 16 } else { 32 };
            let message = vec![0x39u8; message_length];

            let (mut ciphertext, valid_secret) =
                encapsulate_deterministic(&public_key, &message, &parameters).unwrap();

            ciphertext[0] ^= 1;

            let rejected_secret = decapsulate(&ciphertext, &secret_key, &parameters).unwrap();

            assert_ne!(rejected_secret, valid_secret);

            let ciphertext_hash = Sha3_256::digest(&ciphertext);

            let mut xof = Shake256::default();
            xof.update(&auxiliary_secret);
            xof.update(&ciphertext_hash);

            let mut reader = xof.finalize_xof();
            let mut expected_material = [0u8; 64];
            reader.read(&mut expected_material);

            assert_eq!(rejected_secret.as_slice(), &expected_material[32..64],);
        }
    }

    #[test]
    fn decapsulation_rejects_invalid_input_lengths() {
        let parameters = SMAUG_T128;

        let (public_key, secret_key) = keypair(&[0x42u8; 32], &[0xA5u8; 32], &parameters).unwrap();

        let (ciphertext, _) =
            encapsulate_deterministic(&public_key, &[0x39u8; 32], &parameters).unwrap();

        assert_eq!(
            decapsulate(&ciphertext, &[], &parameters),
            Err(KemError::InvalidSecretKeyLength),
        );

        assert_eq!(
            decapsulate(&[], &secret_key, &parameters),
            Err(KemError::InvalidCiphertextLength),
        );
    }

    #[test]
    fn deterministic_encapsulation_is_reproducible() {
        let seed = [0x42u8; 32];
        let t = [0xA5u8; 32];

        for parameters in [SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER] {
            let (pk, _) = keypair(&seed, &t, &parameters).unwrap();
            let message_length = if parameters == TIMER { 16 } else { 32 };
            let message = vec![0x39u8; message_length];

            let first = encapsulate_deterministic(&pk, &message, &parameters).unwrap();
            let second = encapsulate_deterministic(&pk, &message, &parameters).unwrap();

            assert_eq!(first, second);
            assert_eq!(first.1.len(), SHARED_SECRET_BYTES);
        }
    }

    #[test]
    fn deterministic_encapsulation_rejects_invalid_lengths() {
        let message = [0x11u8; 32];

        assert_eq!(
            encapsulate_deterministic(&[], &message, &SMAUG_T128),
            Err(KemError::InvalidPublicKeyLength)
        );

        let (pk, _) = keypair(&[0x42u8; 32], &[0xA5u8; 32], &TIMER).unwrap();

        assert_eq!(
            encapsulate_deterministic(&pk, &message, &TIMER),
            Err(KemError::InvalidMessageLength)
        );
    }

    #[test]
    fn kem_keypair_lengths_and_serialization() {
        let seed = [0x42u8; 32];
        let t = [0xA5u8; AUXILIARY_SECRET_BYTES];

        for (parameters, pk_len, pke_sk_len, kem_sk_len) in [
            (SMAUG_T128, 672, 128, 832),
            (SMAUG_T192, 1088, 192, 1312),
            (SMAUG_T256, 1440, 256, 1728),
            (TIMER, 672, 128, 832),
        ] {
            let (pk, sk) = keypair(&seed, &t, &parameters).unwrap();

            assert_eq!(pk.len(), pk_len);
            assert_eq!(sk.len(), kem_sk_len);
            assert_eq!(&sk[pke_sk_len..pke_sk_len + 32], &t);
            assert_eq!(&sk[pke_sk_len + 32..], pk.as_slice());

            let (expected_pk, expected_sk) = indcpa::keypair(&seed, &parameters).unwrap();

            assert_eq!(pk, expected_pk);
            assert_eq!(&sk[..pke_sk_len], expected_sk.as_slice());
        }
    }

    #[test]
    fn kem_keypair_is_deterministic() {
        let seed = [0x17u8; 32];
        let t = [0xC3u8; AUXILIARY_SECRET_BYTES];

        for parameters in [SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER] {
            let first = keypair(&seed, &t, &parameters).unwrap();
            let second = keypair(&seed, &t, &parameters).unwrap();
            assert_eq!(first, second);
        }
    }

    #[test]
    fn kem_keypair_rejects_unsupported_parameters() {
        let seed = [0u8; 32];
        let t = [0u8; AUXILIARY_SECRET_BYTES];

        let unsupported = Parameters {
            k: 1,
            q: 1024,
            p: 256,
            p_prime: 32,
        };

        assert_eq!(
            keypair(&seed, &t, &unsupported),
            Err(KemError::UnsupportedParameters)
        );
    }
}
