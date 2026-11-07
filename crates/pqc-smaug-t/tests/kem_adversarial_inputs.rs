// SPDX-License-Identifier: MIT
//! S5.5b.3: SMAUG-T adversarial input validation.
//! Experimental assurance tests; not a constant-time claim.

use pqc_rs_smaug_t::{
    kem::{self, KemError},
    Parameters, N, SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER,
};

fn fixture(parameters: &Parameters) -> (Vec<u8>, Vec<u8>) {
    let seed = [0x42u8; 32];
    let auxiliary = [0xA5u8; 32];

    let (public_key, secret_key) = kem::keypair(&seed, &auxiliary, parameters).unwrap();

    let message_len = if *parameters == TIMER { 16 } else { 32 };
    let message = vec![0x39u8; message_len];

    let (ciphertext, expected_secret) =
        kem::encapsulate_deterministic(&public_key, &message, parameters).unwrap();

    assert_eq!(
        kem::decapsulate(&ciphertext, &secret_key, parameters),
        Ok(expected_secret)
    );

    (ciphertext, secret_key)
}

fn invalid_lengths(valid: usize) -> Vec<usize> {
    let candidates = [
        0,
        1,
        2,
        7,
        8,
        valid - 1,
        valid + 1,
        valid + 2,
        valid + 64,
        valid * 2,
    ];

    let mut lengths = candidates.to_vec();
    lengths.sort_unstable();
    lengths.dedup();

    assert_eq!(lengths.len(), 10);
    assert!(!lengths.contains(&valid));

    lengths
}

#[test]
fn kem_length_boundaries_all_modes() {
    let modes = [
        ("mode1", SMAUG_T128),
        ("mode3", SMAUG_T192),
        ("mode5", SMAUG_T256),
        ("modet", TIMER),
    ];

    let mut total_cases = 0usize;

    for (name, parameters) in modes {
        let (ciphertext, secret_key) = fixture(&parameters);
        let mut cases = 0usize;

        for length in invalid_lengths(ciphertext.len()) {
            let malformed = vec![0u8; length];

            let result = kem::decapsulate(&malformed, &secret_key, &parameters);

            assert_eq!(
                result,
                Err(KemError::InvalidCiphertextLength),
                "mode={name} ciphertext_length={length}"
            );

            cases += 1;
        }

        for length in invalid_lengths(secret_key.len()) {
            let malformed = vec![0u8; length];

            let result = kem::decapsulate(&ciphertext, &malformed, &parameters);

            assert_eq!(
                result,
                Err(KemError::InvalidSecretKeyLength),
                "mode={name} secret_key_length={length}"
            );

            cases += 1;
        }

        // Secret-key length validation precedes ciphertext validation.
        assert_eq!(
            kem::decapsulate(&[], &[], &parameters),
            Err(KemError::InvalidSecretKeyLength),
            "mode={name} validation precedence"
        );

        cases += 1;
        total_cases += cases;

        println!("S5_5B_3A_MODE={name} CASES={cases} STATUS=PASS");
    }

    assert_eq!(total_cases, 84);

    println!("S5_5B_3A_LENGTH_BOUNDARIES=PASS CASES={total_cases} MODES=4");
}

#[test]
fn kem_secret_key_corruption_all_modes() {
    use pqc_rs_smaug_t::encoding::EncodingError;
    use pqc_rs_smaug_t::indcpa::DecryptError;
    use sha3::{
        digest::{Digest, ExtendableOutput, Update, XofReader},
        Sha3_256, Shake256,
    };

    fn rejection_secret(auxiliary: &[u8], ciphertext: &[u8]) -> [u8; 32] {
        let hash = Sha3_256::digest(ciphertext);
        let mut xof = Shake256::default();
        xof.update(auxiliary);
        xof.update(&hash);

        let mut material = [0u8; 64];
        xof.finalize_xof().read(&mut material);

        let mut result = [0u8; 32];
        result.copy_from_slice(&material[32..]);
        result
    }

    let modes = [
        ("mode1", SMAUG_T128),
        ("mode3", SMAUG_T192),
        ("mode5", SMAUG_T256),
        ("modet", TIMER),
    ];

    let mut total = 0usize;

    for (name, parameters) in modes {
        let (ciphertext, secret_key) = fixture(&parameters);
        let original_secret = kem::decapsulate(&ciphertext, &secret_key, &parameters).unwrap();

        let indcpa_len = parameters.k * 64;
        let auxiliary_start = indcpa_len;
        let public_start = auxiliary_start + 32;

        assert_eq!(
            secret_key.len(),
            public_start + 32 + parameters.k * N * parameters.q.trailing_zeros() as usize / 8
        );

        let mut invalid_ciphertext = ciphertext.clone();
        invalid_ciphertext[0] ^= 1;

        let mut noncanonical = 0usize;
        let mut indcpa_success = 0usize;
        let mut auxiliary_cases = 0usize;
        let mut public_cases = 0usize;
        let mut public_original = 0usize;
        let mut public_rejection = 0usize;
        let mut public_errors = 0usize;

        for index in 0..secret_key.len() {
            for bit in 0..8 {
                let mut mutated = secret_key.clone();
                mutated[index] ^= 1u8 << bit;

                let first = kem::decapsulate(&ciphertext, &mutated, &parameters);
                let second = kem::decapsulate(&ciphertext, &mutated, &parameters);

                assert_eq!(first, second, "mode={name} byte={index} bit={bit}");

                if index < indcpa_len {
                    match first {
                        Err(KemError::IndcpaDecrypt(DecryptError::Encoding(
                            EncodingError::NonCanonicalSecretEncoding,
                        ))) => noncanonical += 1,
                        Ok(_) => indcpa_success += 1,
                        other => panic!(
                            "Unexpected IND-CPA mutation outcome: \
                             mode={name} byte={index} bit={bit} \
                             result={other:?}"
                        ),
                    }
                } else if index < public_start {
                    assert_eq!(
                        first,
                        Ok(original_secret),
                        "Auxiliary mutation changed valid decapsulation: \
                         mode={name} byte={index} bit={bit}"
                    );

                    let rejected =
                        kem::decapsulate(&invalid_ciphertext, &mutated, &parameters).unwrap();

                    assert_eq!(
                        rejected,
                        rejection_secret(
                            &mutated[auxiliary_start..public_start],
                            &invalid_ciphertext
                        ),
                        "Auxiliary rejection mismatch: \
                         mode={name} byte={index} bit={bit}"
                    );

                    auxiliary_cases += 1;
                } else {
                    match first {
                        Ok(value) if value == original_secret => {
                            public_original += 1;
                        }
                        Ok(value) => {
                            let expected = rejection_secret(
                                &mutated[auxiliary_start..public_start],
                                &ciphertext,
                            );
                            assert_eq!(
                                value, expected,
                                "Unexpected public-key corruption result: \
                                 mode={name} byte={index} bit={bit}"
                            );
                            public_rejection += 1;
                        }
                        Err(_) => public_errors += 1,
                    }

                    public_cases += 1;
                }
            }
        }

        let cases = secret_key.len() * 8;
        assert_eq!(noncanonical + indcpa_success, indcpa_len * 8);
        assert_eq!(auxiliary_cases, 256);
        assert_eq!(
            public_original + public_rejection + public_errors,
            public_cases
        );
        assert_eq!(indcpa_len * 8 + auxiliary_cases + public_cases, cases);

        total += cases;

        println!(
            "S5_5B_3B_MODE={name} CASES={cases} \
             NONCANONICAL={noncanonical} \
             INDCPA_OK={indcpa_success} \
             AUXILIARY={auxiliary_cases} \
             PUBLIC_ORIGINAL={public_original} \
             PUBLIC_REJECTION={public_rejection} \
             PUBLIC_ERRORS={public_errors} STATUS=PASS"
        );
    }

    assert_eq!(total, 37_632);

    println!(
        "S5_5B_3B_SECRET_KEY_CORRUPTION=PASS \
         CASES={total} MODES=4"
    );
}

#[test]
fn kem_deterministic_adversarial_inputs_all_modes() {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn next_byte(state: &mut u64) -> u8 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        (*state >> 24) as u8
    }

    fn fill(bytes: &mut [u8], state: &mut u64) {
        for byte in bytes {
            *byte = next_byte(state);
        }
    }

    let modes = [
        ("mode1", SMAUG_T128),
        ("mode3", SMAUG_T192),
        ("mode5", SMAUG_T256),
        ("modet", TIMER),
    ];

    let mut state = 0x534D_4155_4754_3131u64;
    let mut total = 0usize;

    for (name, parameters) in modes {
        let (valid_ct, valid_sk) = fixture(&parameters);
        let public_start = parameters.k * 64 + 32;
        let valid_pk = &valid_sk[public_start..];
        let message_len = if parameters == TIMER { 16 } else { 32 };
        let mut cases = 0usize;

        for iteration in 0..32 {
            // Arbitrary correctly sized ciphertext and secret key.
            let mut ciphertext = vec![0u8; valid_ct.len()];
            let mut secret_key = vec![0u8; valid_sk.len()];
            fill(&mut ciphertext, &mut state);
            fill(&mut secret_key, &mut state);

            let run = || kem::decapsulate(&ciphertext, &secret_key, &parameters);

            let first = catch_unwind(AssertUnwindSafe(run));
            assert!(
                first.is_ok(),
                "Decapsulation panicked: mode={name} case={iteration}"
            );

            let second = catch_unwind(AssertUnwindSafe(run));
            assert!(
                second.is_ok(),
                "Repeated decapsulation panicked: mode={name} case={iteration}"
            );

            assert_eq!(
                first.unwrap(),
                second.unwrap(),
                "Nondeterministic decapsulation: mode={name} case={iteration}"
            );
            cases += 1;

            // Arbitrary correctly sized public key and message.
            let mut public_key = vec![0u8; valid_pk.len()];
            let mut message = vec![0u8; message_len];
            fill(&mut public_key, &mut state);
            fill(&mut message, &mut state);

            let run = || kem::encapsulate_deterministic(&public_key, &message, &parameters);

            let first = catch_unwind(AssertUnwindSafe(run));
            assert!(
                first.is_ok(),
                "Encapsulation panicked: mode={name} case={iteration}"
            );

            let second = catch_unwind(AssertUnwindSafe(run));
            assert!(
                second.is_ok(),
                "Repeated encapsulation panicked: mode={name} case={iteration}"
            );

            assert_eq!(
                first.unwrap(),
                second.unwrap(),
                "Nondeterministic encapsulation: mode={name} case={iteration}"
            );
            cases += 1;

            // Malformed lengths for both public APIs.
            let ct_len = iteration % 17;
            let sk_len = iteration % 19;
            let pk_len = iteration % 23;
            let msg_len = iteration % 11;

            let mut short_ct = vec![0u8; ct_len];
            let mut short_sk = vec![0u8; sk_len];
            let mut short_pk = vec![0u8; pk_len];
            let mut short_msg = vec![0u8; msg_len];

            fill(&mut short_ct, &mut state);
            fill(&mut short_sk, &mut state);
            fill(&mut short_pk, &mut state);
            fill(&mut short_msg, &mut state);

            let decap = catch_unwind(AssertUnwindSafe(|| {
                kem::decapsulate(&short_ct, &short_sk, &parameters)
            }));

            assert_eq!(
                decap.unwrap_or_else(|_| {
                    panic!("Malformed decapsulation panicked: mode={name}")
                }),
                Err(KemError::InvalidSecretKeyLength)
            );
            cases += 1;

            let encap = catch_unwind(AssertUnwindSafe(|| {
                kem::encapsulate_deterministic(&short_pk, &short_msg, &parameters)
            }));

            assert_eq!(
                encap.unwrap_or_else(|_| {
                    panic!("Malformed encapsulation panicked: mode={name}")
                }),
                Err(KemError::InvalidPublicKeyLength)
            );
            cases += 1;
        }

        assert_eq!(cases, 128);
        total += cases;

        println!("S5_5B_3C_MODE={name} CASES={cases} STATUS=PASS");
    }

    assert_eq!(total, 512);
    println!("S5_5B_3C_PANIC_RESISTANCE=PASS CASES={total} MODES=4");
}
