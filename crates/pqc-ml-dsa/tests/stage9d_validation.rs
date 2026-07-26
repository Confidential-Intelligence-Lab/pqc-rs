#![cfg(feature = "internal-api")]

use pqc_ml_dsa::keygen::keygen_internal;
use pqc_ml_dsa::params::MlDsaParameterSet;
use pqc_ml_dsa::signature::sign_internal;
use pqc_ml_dsa::verification::{
    decode_public_key, decode_signature, verify_internal, VerificationError,
};

const MESSAGES: [&[u8]; 4] = [
    b"",
    b"a",
    b"ML-DSA Stage 9D validation message",
    &[0xA5; 257],
];

const CONTEXTS: [&[u8]; 4] = [b"", b"pqc-rs", b"FIPS-204", &[0x5A; 255]];

#[test]
fn deterministic_end_to_end_matrix_passes() {
    for parameter_set in parameter_sets() {
        for case_index in 0..MESSAGES.len() {
            let seed = seed_for(parameter_set, case_index as u8);
            let key_pair = keygen_internal(parameter_set, &seed).unwrap();
            let signature = sign_internal(
                parameter_set,
                key_pair.private_key(),
                MESSAGES[case_index],
                CONTEXTS[case_index],
                &[0_u8; 32],
            )
            .unwrap();

            assert!(verify_internal(
                parameter_set,
                key_pair.public_key(),
                MESSAGES[case_index],
                CONTEXTS[case_index],
                &signature,
            )
            .unwrap());
        }
    }
}

#[test]
fn hedged_end_to_end_matrix_passes() {
    for parameter_set in parameter_sets() {
        let key_pair = keygen_internal(parameter_set, &seed_for(parameter_set, 9)).unwrap();

        for randomness_tag in 1_u8..=4 {
            let signature = sign_internal(
                parameter_set,
                key_pair.private_key(),
                b"hedged signature",
                b"stage9d6",
                &[randomness_tag; 32],
            )
            .unwrap();

            assert!(verify_internal(
                parameter_set,
                key_pair.public_key(),
                b"hedged signature",
                b"stage9d6",
                &signature,
            )
            .unwrap());
        }
    }
}

#[test]
fn every_signature_region_detects_mutation() {
    for parameter_set in parameter_sets() {
        let parameters = parameter_set.parameters();
        let key_pair = keygen_internal(parameter_set, &seed_for(parameter_set, 17)).unwrap();
        let signature = sign_internal(
            parameter_set,
            key_pair.private_key(),
            b"mutation campaign",
            b"stage9d6",
            &[0_u8; 32],
        )
        .unwrap();

        let challenge_bytes = match parameter_set {
            MlDsaParameterSet::MlDsa44 => 32,
            MlDsaParameterSet::MlDsa65 => 48,
            MlDsaParameterSet::MlDsa87 => 64,
        };
        let z_bytes =
            (parameters.signature_bytes - challenge_bytes - parameters.omega - parameters.k)
                / parameters.l;

        let locations = [
            0,
            challenge_bytes,
            challenge_bytes + z_bytes * parameters.l / 2,
            challenge_bytes + z_bytes * parameters.l,
            parameters.signature_bytes - 1,
        ];

        for location in locations {
            let mut modified = signature.clone();
            modified[location] ^= 1;

            match verify_internal(
                parameter_set,
                key_pair.public_key(),
                b"mutation campaign",
                b"stage9d6",
                &modified,
            ) {
                Ok(valid) => assert!(!valid),
                Err(
                    VerificationError::InvalidSignatureEncoding
                    | VerificationError::InvalidSignatureLength,
                ) => {}
                Err(other) => panic!("unexpected verification error: {other:?}"),
            }
        }
    }
}

#[test]
fn wrong_parameter_set_is_rejected() {
    let key_pair = keygen_internal(MlDsaParameterSet::MlDsa44, &[0x41; 32]).unwrap();
    let signature = sign_internal(
        MlDsaParameterSet::MlDsa44,
        key_pair.private_key(),
        b"parameter mismatch",
        b"",
        &[0_u8; 32],
    )
    .unwrap();

    assert!(matches!(
        verify_internal(
            MlDsaParameterSet::MlDsa65,
            key_pair.public_key(),
            b"parameter mismatch",
            b"",
            &signature,
        ),
        Err(VerificationError::InvalidPublicKeyLength | VerificationError::InvalidSignatureLength)
    ));
}

#[test]
fn strict_decoders_accept_generated_objects() {
    for parameter_set in parameter_sets() {
        let key_pair = keygen_internal(parameter_set, &seed_for(parameter_set, 23)).unwrap();
        let signature = sign_internal(
            parameter_set,
            key_pair.private_key(),
            b"strict decode",
            b"",
            &[0_u8; 32],
        )
        .unwrap();

        decode_public_key(parameter_set, key_pair.public_key()).unwrap();
        decode_signature(parameter_set, &signature).unwrap();
    }
}

fn parameter_sets() -> [MlDsaParameterSet; 3] {
    [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ]
}

fn seed_for(parameter_set: MlDsaParameterSet, tag: u8) -> [u8; 32] {
    let parameter_tag = match parameter_set {
        MlDsaParameterSet::MlDsa44 => 44,
        MlDsaParameterSet::MlDsa65 => 65,
        MlDsaParameterSet::MlDsa87 => 87,
    };

    let mut seed = [tag; 32];
    seed[0] = parameter_tag;
    seed
}
