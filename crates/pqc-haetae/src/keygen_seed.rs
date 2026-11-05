// SPDX-License-Identifier: MIT

//! Deterministic HAETAE 1.2.0 key-generation seed expansion.
//!
//! This module does not generate, serialize, or validate key pairs.

use crate::params::{CRH_BYTES, SEED_BYTES};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::Zeroize;

/// Reference-compatible partition of the SHAKE256 key-generation output.
#[derive(Eq, PartialEq)]
pub struct KeygenSeeds {
    /// Seed used for the public matrix and public vector.
    pub rhoprime: [u8; SEED_BYTES],
    /// Seed used for the secret polynomial vectors.
    pub sigma: [u8; CRH_BYTES],
    /// Secret key-generation seed retained in the private key.
    pub key: [u8; SEED_BYTES],
}

// HAETAE_10K_7D_2_SECRET_HYGIENE
impl Drop for KeygenSeeds {
    fn drop(&mut self) {
        self.sigma.zeroize();
        self.key.zeroize();
    }
}

/// Expand the caller-supplied 32-byte seed exactly as HAETAE KeyGenInternal.
///
/// SHAKE256(seed, 128) is partitioned into 32, 64, and 32 bytes.
pub fn expand_keygen_seed(seed: &[u8; SEED_BYTES]) -> KeygenSeeds {
    let mut shake = Shake256::default();
    shake.update(seed);

    let mut reader = shake.finalize_xof();
    let mut output = [0_u8; 2 * SEED_BYTES + CRH_BYTES];
    reader.read(&mut output);

    let mut rhoprime = [0_u8; SEED_BYTES];
    let mut sigma = [0_u8; CRH_BYTES];
    let mut key = [0_u8; SEED_BYTES];

    rhoprime.copy_from_slice(&output[..SEED_BYTES]);
    sigma.copy_from_slice(&output[SEED_BYTES..SEED_BYTES + CRH_BYTES]);
    key.copy_from_slice(&output[SEED_BYTES + CRH_BYTES..]);

    output.zeroize();

    KeygenSeeds {
        rhoprime,
        sigma,
        key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_seed_expansion() {
        let seed = std::array::from_fn(|i| i as u8);
        assert!(expand_keygen_seed(&seed) == expand_keygen_seed(&seed));
    }

    #[test]
    fn seed_changes_expansion() {
        let a = expand_keygen_seed(&[0_u8; SEED_BYTES]);
        let b = expand_keygen_seed(&[1_u8; SEED_BYTES]);
        assert!(a != b);
    }

    #[test]
    fn expansion_matches_single_shake_stream() {
        let seed = std::array::from_fn(|i| (i * 7) as u8);
        let derived = expand_keygen_seed(&seed);

        let mut shake = Shake256::default();
        shake.update(&seed);
        let mut reader = shake.finalize_xof();

        let mut expected = [0_u8; 128];
        reader.read(&mut expected);

        assert_eq!(&derived.rhoprime[..], &expected[..32]);
        assert_eq!(&derived.sigma[..], &expected[32..96]);
        assert_eq!(&derived.key[..], &expected[96..128]);
    }
}
