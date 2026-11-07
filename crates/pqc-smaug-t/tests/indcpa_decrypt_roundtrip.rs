use pqc_rs_smaug_t::{
    indcpa::{decrypt, encrypt, keypair, DecryptError},
    Parameters, SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER,
};

fn seed(domain: u8, case: usize) -> [u8; 32] {
    std::array::from_fn(|i| {
        let value = match case {
            0 => 0,
            1 => 0xff,
            2 => i as u8,
            3 => {
                if i % 2 == 0 {
                    0xaa
                } else {
                    0x55
                }
            }
            _ => unreachable!(),
        };
        value ^ domain
    })
}

#[test]
fn indcpa_roundtrip_all_modes() {
    let modes = [
        ("mode1", SMAUG_T128),
        ("mode3", SMAUG_T192),
        ("mode5", SMAUG_T256),
        ("modet", TIMER),
    ];

    let mut cases = 0;

    for (name, parameters) in modes {
        for case in 0..4 {
            let key_seed = seed(0x11, case);
            let encryption_seed = seed(0x5a, case);

            let message_len = if parameters == TIMER { 16 } else { 32 };
            let message = seed(0, case)[..message_len].to_vec();

            let (public_key, secret_key) =
                keypair(&key_seed, &parameters).expect("deterministic keypair");

            let ciphertext = encrypt(&public_key, &message, &encryption_seed, &parameters)
                .expect("deterministic encryption");

            let recovered = decrypt(&secret_key, &ciphertext, &parameters).expect("decryption");

            assert_eq!(
                recovered, message,
                "round-trip mismatch: mode={name}, case={case}"
            );

            cases += 1;
        }
    }

    println!("S4_5B_2_ROUNDTRIP=PASS CASES={cases} MISMATCHES=0");
}

#[test]
fn decrypt_rejects_invalid_lengths_and_secret_encoding() {
    for parameters in [SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER] {
        let (public_key, secret_key) = keypair(&seed(0x11, 0), &parameters).unwrap();

        let message_len = if parameters == TIMER { 16 } else { 32 };
        let message = vec![0u8; message_len];

        let ciphertext = encrypt(&public_key, &message, &seed(0x5a, 0), &parameters).unwrap();

        assert_eq!(
            decrypt(
                &secret_key[..secret_key.len() - 1],
                &ciphertext,
                &parameters
            ),
            Err(DecryptError::InvalidSecretKeyLength)
        );

        assert_eq!(
            decrypt(
                &secret_key,
                &ciphertext[..ciphertext.len() - 1],
                &parameters
            ),
            Err(DecryptError::InvalidCiphertextLength)
        );

        let mut invalid_secret = secret_key.clone();
        invalid_secret[0] = (invalid_secret[0] & !0x03) | 0x03;

        assert_eq!(
            decrypt(&invalid_secret, &ciphertext, &parameters),
            Err(DecryptError::Encoding(
                pqc_rs_smaug_t::encoding::EncodingError::NonCanonicalSecretEncoding
            ))
        );
    }
}

#[test]
fn decrypt_rejects_unsupported_parameters() {
    let unsupported = Parameters {
        k: 2,
        q: 1024,
        p: 256,
        p_prime: 16,
    };

    assert_eq!(
        decrypt(&[], &[], &unsupported),
        Err(DecryptError::UnsupportedParameters)
    );
}
