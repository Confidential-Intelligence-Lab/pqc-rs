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

#[derive(Eq, PartialEq)]
pub struct SigningInitialization {
    pub mu: [u8; 64],
    pub signing_seed: [u8; 64],
}

// The signing seed is secret-derived; mu is a public transcript digest.
impl SigningInitialization {
    fn zeroize_secret_material(&mut self) {
        use zeroize::Zeroize;

        self.signing_seed.zeroize();
    }
}

impl Drop for SigningInitialization {
    fn drop(&mut self) {
        self.zeroize_secret_material();
    }
}

#[cfg(test)]
mod signing_seed_zeroization_tests {
    use super::*;

    #[test]
    fn clears_seed_preserving_public_transcript() {
        let mut initialization = SigningInitialization {
            mu: [0x5A; 64],
            signing_seed: [0xC3; 64],
        };

        initialization.zeroize_secret_material();

        assert_eq!(initialization.signing_seed, [0; 64]);
        assert_eq!(initialization.mu, [0x5A; 64]);

        initialization.zeroize_secret_material();
        assert_eq!(initialization.signing_seed, [0; 64]);

        println!("HAETAE_SIGNING_SEED_ZEROIZATION_STATUS=PASS");
    }
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

    // HAETAE_10K_7D_4C_7C_SIGNING_SEED_CONSTRUCTION
    let mut initialization = SigningInitialization {
        mu,
        signing_seed: [0_u8; 64],
    };
    seed_xof
        .finalize_xof()
        .read(&mut initialization.signing_seed);

    Ok(initialization)
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
