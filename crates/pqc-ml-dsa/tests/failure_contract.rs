use pqc_ml_dsa::{
    MlDsa, MlDsaError, MlDsaKeyGenSeed, MlDsaParameterSet, MlDsaPrivateKey, MlDsaPublicKey,
    MlDsaSignature, PreHashAlgorithm, ML_DSA_KEYGEN_SEED_BYTES,
};
use rand_core::{CryptoRng, Error as RngError, RngCore};
use std::num::NonZeroU32;

const PARAMETER_SETS: [MlDsaParameterSet; 3] = [
    MlDsaParameterSet::MlDsa44,
    MlDsaParameterSet::MlDsa65,
    MlDsaParameterSet::MlDsa87,
];

struct FailingRng;

impl RngCore for FailingRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        destination.fill(0);
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), RngError> {
        let code = NonZeroU32::new(RngError::CUSTOM_START)
            .expect("rand_core custom error base must be nonzero");
        Err(RngError::from(code))
    }
}

impl CryptoRng for FailingRng {}

fn key_pair(parameter_set: MlDsaParameterSet, fill: u8) -> pqc_ml_dsa::MlDsaKeyPair {
    MlDsaKeyGenSeed::from_bytes(parameter_set, [fill; ML_DSA_KEYGEN_SEED_BYTES])
        .expand()
        .expect("fixed test seed must expand")
}

#[test]
fn malformed_lengths_return_typed_errors_for_every_parameter_set() {
    for parameter_set in PARAMETER_SETS {
        let implementation = MlDsa::new(parameter_set);

        for length in [
            0,
            implementation.public_key_bytes() - 1,
            implementation.public_key_bytes() + 1,
        ] {
            assert_eq!(
                MlDsaPublicKey::from_bytes(parameter_set, &vec![0_u8; length]).unwrap_err(),
                MlDsaError::InvalidPublicKey
            );
        }

        for length in [
            0,
            implementation.private_key_bytes() - 1,
            implementation.private_key_bytes() + 1,
        ] {
            assert_eq!(
                MlDsaPrivateKey::from_bytes(parameter_set, &vec![0_u8; length])
                    .err()
                    .expect("malformed private key must fail"),
                MlDsaError::InvalidPrivateKey
            );
        }

        for length in [
            0,
            implementation.signature_bytes() - 1,
            implementation.signature_bytes() + 1,
        ] {
            assert_eq!(
                MlDsaSignature::from_bytes(parameter_set, &vec![0_u8; length]).unwrap_err(),
                MlDsaError::InvalidSignature
            );
        }
    }
}

#[test]
fn every_randomized_entry_point_propagates_rng_failure() {
    let implementation = MlDsa::new(MlDsaParameterSet::MlDsa44);
    let key_pair = key_pair(MlDsaParameterSet::MlDsa44, 0x51);

    assert_eq!(
        implementation.keygen(&mut FailingRng).err(),
        Some(MlDsaError::RandomnessFailure)
    );
    assert_eq!(
        implementation.generate_keygen_seed(&mut FailingRng).err(),
        Some(MlDsaError::RandomnessFailure)
    );
    assert_eq!(
        implementation
            .sign_hedged(
                key_pair.private_key(),
                b"message",
                b"context",
                &mut FailingRng,
            )
            .err(),
        Some(MlDsaError::RandomnessFailure)
    );
    assert_eq!(
        implementation
            .hash_sign_hedged(
                key_pair.private_key(),
                b"message",
                b"context",
                PreHashAlgorithm::Sha2_256,
                &mut FailingRng,
            )
            .err(),
        Some(MlDsaError::RandomnessFailure)
    );
}

#[test]
fn context_and_parameter_misuse_return_typed_errors() {
    let implementation_44 = MlDsa::new(MlDsaParameterSet::MlDsa44);
    let implementation_65 = MlDsa::new(MlDsaParameterSet::MlDsa65);
    let key_pair_44 = key_pair(MlDsaParameterSet::MlDsa44, 0x52);
    let key_pair_65 = key_pair(MlDsaParameterSet::MlDsa65, 0x53);
    let signature_44 = implementation_44
        .sign_deterministic(key_pair_44.private_key(), b"message", b"")
        .expect("fixed test input must sign");
    let oversized_context = [0_u8; 256];

    assert_eq!(
        implementation_44
            .sign_deterministic(key_pair_44.private_key(), b"message", &oversized_context,)
            .err(),
        Some(MlDsaError::ContextTooLong)
    );
    assert_eq!(
        implementation_44
            .verify(
                key_pair_44.public_key(),
                b"message",
                &oversized_context,
                &signature_44,
            )
            .err(),
        Some(MlDsaError::ContextTooLong)
    );
    assert_eq!(
        implementation_44
            .hash_verify(
                key_pair_44.public_key(),
                b"message",
                &oversized_context,
                PreHashAlgorithm::Sha2_256,
                &signature_44,
            )
            .err(),
        Some(MlDsaError::ContextTooLong)
    );
    assert_eq!(
        implementation_44
            .sign_deterministic(key_pair_65.private_key(), b"message", b"")
            .err(),
        Some(MlDsaError::ParameterSetMismatch)
    );
    assert_eq!(
        implementation_65
            .verify(key_pair_44.public_key(), b"message", b"", &signature_44)
            .err(),
        Some(MlDsaError::ParameterSetMismatch)
    );
}
