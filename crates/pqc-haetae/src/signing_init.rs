//! Deterministic HAETAE 1.2.0 signing transcript initialization.
//!
//! This module does not generate randomness or produce signatures.

use crate::packing::{public_key_bytes, secret_key_bytes};
use crate::params::ParameterSet;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SigningInitError {
    InvalidSecretKeyLength,
    ContextTooLong,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SigningInitialization {
    pub mu: [u8; 64],
    pub signing_seed: [u8; 64],
}

pub fn derive_signing_initialization(
    secret_key: &[u8],
    message: &[u8],
    context: &[u8],
    randomness: &[u8; 32],
    mode: ParameterSet,
) -> Result<SigningInitialization, SigningInitError> {
    if secret_key.len() != secret_key_bytes(mode) {
        return Err(SigningInitError::InvalidSecretKeyLength);
    }

    let context_len = u8::try_from(context.len()).map_err(|_| SigningInitError::ContextTooLong)?;

    let vk_len = public_key_bytes(mode);
    let vk = &secret_key[..vk_len];
    let key = &secret_key[secret_key.len() - 32..];

    let mut mu_xof = Shake256::default();
    mu_xof.update(vk);
    mu_xof.update(&[context_len]);
    mu_xof.update(context);
    mu_xof.update(message);

    let mut mu = [0_u8; 64];
    mu_xof.finalize_xof().read(&mut mu);

    let mut seed_xof = Shake256::default();
    seed_xof.update(key);
    seed_xof.update(randomness);
    seed_xof.update(&mu);

    let mut signing_seed = [0_u8; 64];
    seed_xof.finalize_xof().read(&mut signing_seed);

    Ok(SigningInitialization { mu, signing_seed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_secret_key_length() {
        let result =
            derive_signing_initialization(&[], b"message", b"", &[0_u8; 32], ParameterSet::Haetae2);
        assert!(matches!(
            result,
            Err(SigningInitError::InvalidSecretKeyLength)
        ));
    }

    #[test]
    fn rejects_context_longer_than_255_bytes() {
        let sk = vec![0_u8; secret_key_bytes(ParameterSet::Haetae2)];
        let result = derive_signing_initialization(
            &sk,
            b"message",
            &[0_u8; 256],
            &[0_u8; 32],
            ParameterSet::Haetae2,
        );
        assert!(matches!(result, Err(SigningInitError::ContextTooLong)));
    }
}
