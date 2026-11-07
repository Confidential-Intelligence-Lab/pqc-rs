// SPDX-License-Identifier: MIT
//! Systematic SMAUG-T ciphertext mutation testing.
//!
//! Experimental robustness evidence, not constant-time assurance.

use pqc_rs_smaug_t::kem;
use pqc_rs_smaug_t::{Parameters, SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER};
use sha3::{
    digest::{Digest, ExtendableOutput, Update, XofReader},
    Sha3_256, Shake256,
};

fn rejection_secret(auxiliary_secret: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    let ciphertext_hash = Sha3_256::digest(ciphertext);

    let mut xof = Shake256::default();
    xof.update(auxiliary_secret);
    xof.update(&ciphertext_hash);

    let mut reader = xof.finalize_xof();
    let mut material = [0u8; 64];
    reader.read(&mut material);

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&material[32..64]);
    secret
}

fn test_mode(name: &str, parameters: Parameters, expected_ciphertext_bytes: usize) -> usize {
    let seed = [0x42u8; 32];
    let auxiliary_secret = [0xA5u8; 32];

    let (public_key, secret_key) =
        kem::keypair(&seed, &auxiliary_secret, &parameters).expect("keypair");

    let message_length = if parameters == TIMER { 16 } else { 32 };
    let message = vec![0x39u8; message_length];

    let (ciphertext, valid_secret) =
        kem::encapsulate_deterministic(&public_key, &message, &parameters).expect("encapsulation");

    assert_eq!(ciphertext.len(), expected_ciphertext_bytes);

    assert_eq!(
        kem::decapsulate(&ciphertext, &secret_key, &parameters).expect("valid decapsulation"),
        valid_secret
    );

    let mut cases = 0usize;

    let byte_limit = std::env::var("SMAUGT_MUTATION_LIMIT")
        .ok()
        .map(|value| value.parse::<usize>().expect("valid mutation limit"))
        .unwrap_or(ciphertext.len())
        .min(ciphertext.len());

    assert!(byte_limit > 0, "mutation limit must be positive");

    for byte_index in 0..byte_limit {
        for bit_index in 0..8 {
            let mut mutated = ciphertext.clone();
            mutated[byte_index] ^= 1u8 << bit_index;

            let first =
                kem::decapsulate(&mutated, &secret_key, &parameters).unwrap_or_else(|error| {
                    panic!(
                        "{name}: byte={byte_index} bit={bit_index}: \
                         unexpected decapsulation error {error:?}"
                    )
                });

            let second =
                kem::decapsulate(&mutated, &secret_key, &parameters).expect("repeat decapsulation");

            assert_eq!(
                first, second,
                "{name}: nondeterministic result at byte={byte_index} bit={bit_index}"
            );

            let expected_rejection = rejection_secret(&auxiliary_secret, &mutated);

            assert_eq!(
                first, expected_rejection,
                "{name}: unexpected rejection secret at byte={byte_index} bit={bit_index}"
            );

            cases += 1;
        }
    }

    assert_eq!(cases, byte_limit * 8);

    println!(
        "S5_5B_MUTATION_MODE={name} \
         CASES={cases} STATUS=PASS"
    );

    cases
}

#[test]
fn exhaustive_single_bit_ciphertext_mutations() {
    let mut total = 0usize;

    for (name, parameters, ciphertext_bytes) in [
        ("mode1", SMAUG_T128, 672),
        ("mode3", SMAUG_T192, 992),
        ("mode5", SMAUG_T256, 1376),
        ("modet", TIMER, 608),
    ] {
        total += test_mode(name, parameters, ciphertext_bytes);
    }

    let expected_total = std::env::var("SMAUGT_MUTATION_LIMIT")
        .ok()
        .map(|value| value.parse::<usize>().expect("valid mutation limit"))
        .unwrap_or(usize::MAX);

    let expected_total: usize = [672usize, 992, 1376, 608]
        .into_iter()
        .map(|length| length.min(expected_total) * 8)
        .sum();

    assert_eq!(total, expected_total);

    println!(
        "S5_5B_2_EXHAUSTIVE_MUTATION=PASS \
         CASES={total} MODES=4"
    );
}
