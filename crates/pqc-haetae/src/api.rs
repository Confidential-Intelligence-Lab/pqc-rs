// SPDX-License-Identifier: MIT
//! Experimental typed public API for HAETAE 1.2.0.
//!
//! This implementation has not undergone a security audit.
//! Do not use it for production cryptographic operations.

use crate::keygen_loop::generate_accepted_state;
use crate::packing::{pack_sk, pack_vk};
use crate::params::{ParameterSet, SEED_BYTES};
use crate::signing::sign_deterministic;
use crate::verification::verify_preformatted;

use pqc_core::secret::SecretVec;
use pqc_core::{PqcError, PqcResult, SignatureScheme};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Maximum context length supported by the HAETAE transcript.
pub const MAX_CONTEXT_BYTES: usize = 255;

/// Maximum key-generation attempts for the experimental API.
const MAX_KEYGEN_ATTEMPTS: usize = 10_000;

/// Parameter-bound experimental HAETAE signature scheme.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Haetae {
    mode: ParameterSet,
}

impl Haetae {
    /// Select a HAETAE parameter set.
    pub const fn new(mode: ParameterSet) -> Self {
        Self { mode }
    }

    /// Return the selected parameter set.
    pub const fn parameter_set(&self) -> ParameterSet {
        self.mode
    }

    /// Generate a parameter-bound key pair using a cryptographic RNG.
    pub fn keygen<R>(&self, rng: &mut R) -> PqcResult<HaetaeKeyPair>
    where
        R: CryptoRng + RngCore,
    {
        let mut seed = [0u8; SEED_BYTES];
        if rng.try_fill_bytes(&mut seed).is_err() {
            seed.zeroize();
            return Err(PqcError::RandomnessFailure);
        }

        let result = match self.mode {
            ParameterSet::Haetae2 => keygen_mode::<2, 3>(&seed, self.mode),
            ParameterSet::Haetae3 => keygen_mode::<3, 5>(&seed, self.mode),
            ParameterSet::Haetae5 => keygen_mode::<4, 6>(&seed, self.mode),
        };

        seed.zeroize();
        result
    }

    /// Sign using fresh RNG-provided randomness.
    pub fn sign<R>(
        &self,
        private_key: &HaetaePrivateKey,
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> PqcResult<HaetaeSignature>
    where
        R: CryptoRng + RngCore,
    {
        ensure_mode(self.mode, private_key.mode)?;
        validate_context(context)?;

        let mut randomness = [0u8; 32];
        if rng.try_fill_bytes(&mut randomness).is_err() {
            randomness.zeroize();
            return Err(PqcError::RandomnessFailure);
        }

        let result = sign_deterministic(
            self.mode,
            private_key.bytes.as_bytes(),
            message,
            context,
            &randomness,
        );

        randomness.zeroize();

        let bytes = result.map_err(|_| PqcError::InternalError)?;

        Ok(HaetaeSignature {
            mode: self.mode,
            bytes,
        })
    }

    /// Verify a detached signature with an optional context.
    pub fn verify(
        &self,
        public_key: &HaetaePublicKey,
        message: &[u8],
        context: &[u8],
        signature: &HaetaeSignature,
    ) -> PqcResult<()> {
        ensure_mode(self.mode, public_key.mode)?;
        ensure_mode(self.mode, signature.mode)?;
        validate_context(context)?;

        let mut prefix = Vec::with_capacity(context.len() + 1);
        prefix.push(context.len() as u8);
        prefix.extend_from_slice(context);

        verify_preformatted(
            self.mode,
            &public_key.bytes,
            &prefix,
            message,
            &signature.bytes,
        )
        .map_err(|_| PqcError::VerificationFailed)
    }
}

fn ensure_mode(expected: ParameterSet, actual: ParameterSet) -> PqcResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(PqcError::ParameterSetMismatch)
    }
}

fn validate_context(context: &[u8]) -> PqcResult<()> {
    if context.len() <= MAX_CONTEXT_BYTES {
        Ok(())
    } else {
        Err(PqcError::InvalidLength {
            expected: MAX_CONTEXT_BYTES,
            actual: context.len(),
        })
    }
}

fn keygen_mode<const K: usize, const M: usize>(
    seed: &[u8; SEED_BYTES],
    mode: ParameterSet,
) -> PqcResult<HaetaeKeyPair> {
    // SECURITY TODO: AcceptedKeygenState contains secret-derived
    // polynomial vectors and currently lacks automatic zeroization.
    let state = generate_accepted_state::<K, M>(seed, mode, MAX_KEYGEN_ATTEMPTS)
        .map_err(|_| PqcError::InternalError)?;

    let public_bytes =
        pack_vk(&state.rhoprime, &state.public_b, mode).map_err(|_| PqcError::InternalError)?;

    let private_bytes = pack_sk(&public_bytes, &state.s1, &state.s2, &state.key, mode)
        .map_err(|_| PqcError::InternalError)?;

    Ok(HaetaeKeyPair {
        public_key: HaetaePublicKey {
            mode,
            bytes: public_bytes,
        },
        private_key: HaetaePrivateKey {
            mode,
            bytes: SecretVec::new(private_bytes),
        },
    })
}

/// Parameter-bound HAETAE public verification key.
pub struct HaetaePublicKey {
    mode: ParameterSet,
    bytes: Vec<u8>,
}

impl HaetaePublicKey {
    /// Return the associated parameter set.
    pub const fn parameter_set(&self) -> ParameterSet {
        self.mode
    }

    /// Borrow the serialized public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Parameter-bound HAETAE private signing key.
///
/// The serialized secret key is zeroized when this object is dropped.
pub struct HaetaePrivateKey {
    mode: ParameterSet,
    bytes: SecretVec,
}

impl HaetaePrivateKey {
    /// Return the associated parameter set.
    pub const fn parameter_set(&self) -> ParameterSet {
        self.mode
    }
}

/// Parameter-bound detached HAETAE signature.
pub struct HaetaeSignature {
    mode: ParameterSet,
    bytes: Vec<u8>,
}

impl HaetaeSignature {
    /// Return the associated parameter set.
    pub const fn parameter_set(&self) -> ParameterSet {
        self.mode
    }

    /// Borrow the serialized signature.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A generated HAETAE signing and verification key pair.
pub struct HaetaeKeyPair {
    /// Public verification key.
    pub public_key: HaetaePublicKey,
    /// Secret signing key.
    pub private_key: HaetaePrivateKey,
}

impl SignatureScheme for Haetae {
    type PublicKey = HaetaePublicKey;
    type SecretKey = HaetaePrivateKey;
    type Signature = HaetaeSignature;

    fn keygen<R>(&self, rng: &mut R) -> PqcResult<(Self::PublicKey, Self::SecretKey)>
    where
        R: CryptoRng + RngCore,
    {
        let pair = Haetae::keygen(self, rng)?;
        Ok((pair.public_key, pair.private_key))
    }

    fn sign<R>(
        &self,
        secret_key: &Self::SecretKey,
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> PqcResult<Self::Signature>
    where
        R: CryptoRng + RngCore,
    {
        Haetae::sign(self, secret_key, message, context, rng)
    }

    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        context: &[u8],
        signature: &Self::Signature,
    ) -> PqcResult<()> {
        Haetae::verify(self, public_key, message, context, signature)
    }
}

// HAETAE_10K_7C_4E_API_REGRESSION_TESTS
#[cfg(test)]
mod api_regression_tests {
    use super::*;
    use rand_core::Error;

    struct TestRng {
        state: u64,
        fail: bool,
    }

    impl TestRng {
        fn new(seed: u64) -> Self {
            Self {
                state: seed,
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                state: 0,
                fail: true,
            }
        }
    }

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.state = self
                .state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.state
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.try_fill_bytes(dest).expect("test RNG failure");
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            if self.fail {
                return Err(Error::from(core::num::NonZeroU32::new(1).unwrap()));
            }

            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }

            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

    const MODES: [ParameterSet; 3] = [
        ParameterSet::Haetae2,
        ParameterSet::Haetae3,
        ParameterSet::Haetae5,
    ];

    #[test]
    fn all_modes_end_to_end_and_tampering() {
        for (index, mode) in MODES.into_iter().enumerate() {
            let scheme = Haetae::new(mode);
            let mut rng = TestRng::new(0x1234_5678 + index as u64);

            let pair = scheme.keygen(&mut rng).unwrap();

            assert_eq!(
                pair.public_key.as_bytes().len(),
                mode.parameters().public_key_bytes,
            );

            let message = b"HAETAE public API regression";
            let context = b"pqc-rs-haetae";

            let signature = scheme
                .sign(&pair.private_key, message, context, &mut rng)
                .unwrap();

            assert_eq!(
                signature.as_bytes().len(),
                mode.parameters().signature_bytes,
            );

            assert!(scheme
                .verify(&pair.public_key, message, context, &signature)
                .is_ok());

            assert!(scheme
                .verify(&pair.public_key, b"modified message", context, &signature)
                .is_err());

            assert!(scheme
                .verify(&pair.public_key, message, b"modified context", &signature)
                .is_err());

            let mut modified_signature = HaetaeSignature {
                mode,
                bytes: signature.as_bytes().to_vec(),
            };

            modified_signature.bytes[0] ^= 1;

            assert!(scheme
                .verify(&pair.public_key, message, context, &modified_signature,)
                .is_err());

            println!("HAETAE_API_ROUNDTRIP_MODE={mode:?} STATUS=PASS");
        }
    }

    #[test]
    fn trait_adapter_roundtrip() {
        let scheme = Haetae::new(ParameterSet::Haetae2);
        let mut rng = TestRng::new(0x9876_5432);

        let (pk, sk) = SignatureScheme::keygen(&scheme, &mut rng).unwrap();

        let sig =
            SignatureScheme::sign(&scheme, &sk, b"trait adapter", b"context", &mut rng).unwrap();

        SignatureScheme::verify(&scheme, &pk, b"trait adapter", b"context", &sig).unwrap();
    }

    #[test]
    fn parameter_set_mismatch() {
        let scheme2 = Haetae::new(ParameterSet::Haetae2);
        let scheme3 = Haetae::new(ParameterSet::Haetae3);
        let mut rng = TestRng::new(42);

        let pair = scheme2.keygen(&mut rng).unwrap();

        assert!(matches!(
            scheme3.sign(&pair.private_key, b"message", b"", &mut rng),
            Err(PqcError::ParameterSetMismatch)
        ));

        let signature = scheme2
            .sign(&pair.private_key, b"message", b"", &mut rng)
            .unwrap();

        assert!(matches!(
            scheme3.verify(&pair.public_key, b"message", b"", &signature),
            Err(PqcError::ParameterSetMismatch)
        ));

        let mismatched_signature = HaetaeSignature {
            mode: ParameterSet::Haetae3,
            bytes: signature.as_bytes().to_vec(),
        };

        assert!(matches!(
            scheme2.verify(&pair.public_key, b"message", b"", &mismatched_signature,),
            Err(PqcError::ParameterSetMismatch)
        ));
    }

    #[test]
    fn context_boundaries() {
        let scheme = Haetae::new(ParameterSet::Haetae2);
        let mut rng = TestRng::new(101);
        let pair = scheme.keygen(&mut rng).unwrap();

        let maximum = [0xA5u8; 255];
        let excessive = [0xA5u8; 256];

        let signature = scheme
            .sign(&pair.private_key, b"boundary", &maximum, &mut rng)
            .unwrap();

        assert!(scheme
            .verify(&pair.public_key, b"boundary", &maximum, &signature)
            .is_ok());

        assert!(matches!(
            scheme.sign(&pair.private_key, b"boundary", &excessive, &mut rng),
            Err(PqcError::InvalidLength {
                expected: 255,
                actual: 256,
            })
        ));

        assert!(matches!(
            scheme.verify(&pair.public_key, b"boundary", &excessive, &signature,),
            Err(PqcError::InvalidLength {
                expected: 255,
                actual: 256,
            })
        ));
    }

    #[test]
    fn rng_failure_keygen() {
        let scheme = Haetae::new(ParameterSet::Haetae2);
        let mut rng = TestRng::failing();

        assert!(matches!(
            scheme.keygen(&mut rng),
            Err(PqcError::RandomnessFailure)
        ));
    }

    #[test]
    fn rng_failure_signing() {
        let scheme = Haetae::new(ParameterSet::Haetae2);
        let mut rng = TestRng::new(202);
        let pair = scheme.keygen(&mut rng).unwrap();

        let mut failing = TestRng::failing();

        assert!(matches!(
            scheme.sign(&pair.private_key, b"message", b"", &mut failing),
            Err(PqcError::RandomnessFailure)
        ));
    }
}
