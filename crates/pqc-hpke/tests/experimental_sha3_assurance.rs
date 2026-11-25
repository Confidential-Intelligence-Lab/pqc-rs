use pqc_hpke::hybrid_kem::HybridKem;
use pqc_hpke::hybrid_setup::{setup_hybrid_base_receiver, setup_hybrid_base_sender_deterministic};
use pqc_hpke::setup::{setup_base_receiver, setup_base_sender_deterministic};
use pqc_hpke::{AeadId, HpkeError, HpkeSuiteId, KdfId, MlKemHpke};

const SHA3_ID: KdfId = KdfId(0xff01);

const INFO: &[u8] = b"experimental-assurance-context";
#[cfg(feature = "experimental-hkdf-sha3")]
const AAD: &[u8] = b"experimental-assurance-aad";
#[cfg(feature = "experimental-hkdf-sha3")]
const MSG: &[u8] = b"synthetic subscriber identity";

#[test]
fn pure_experimental_feature_isolation() {
    let kem = MlKemHpke::MlKem768;

    let keys = kem.derive_key_pair(&[0x11; 64]).unwrap();

    let control_suite = HpkeSuiteId {
        kem_id: kem.kem_id(),
        kdf_id: KdfId::HKDF_SHA256,
        aead_id: AeadId::AES_256_GCM,
    };

    let experimental_suite = HpkeSuiteId {
        kdf_id: SHA3_ID,
        ..control_suite
    };

    let control =
        setup_base_sender_deterministic(kem, control_suite, &keys.public_key, INFO, &[0x22; 32])
            .unwrap();

    let sender = setup_base_sender_deterministic(
        kem,
        experimental_suite,
        &keys.public_key,
        INFO,
        &[0x22; 32],
    );

    let receiver = setup_base_receiver(
        kem,
        experimental_suite,
        keys.private_key_seed.as_bytes(),
        &control.encapsulated_key,
        INFO,
    );

    #[cfg(not(feature = "experimental-hkdf-sha3"))]
    {
        assert!(matches!(sender, Err(HpkeError::UnsupportedKdf)));

        assert!(matches!(receiver, Err(HpkeError::UnsupportedKdf)));
    }

    #[cfg(feature = "experimental-hkdf-sha3")]
    {
        let mut sender = sender.unwrap().context;
        let mut receiver = receiver.unwrap();

        let ciphertext = sender.seal(AAD, MSG).unwrap();

        assert_eq!(receiver.open(AAD, &ciphertext).unwrap(), MSG);
    }
}

#[test]
fn hybrid_experimental_feature_isolation() {
    let kem = HybridKem::MlKem768X25519;

    let keys = kem.derive_key_pair(&[0x33; 32]).unwrap();

    let control_suite = HpkeSuiteId {
        kem_id: kem.kem_id(),
        kdf_id: KdfId::HKDF_SHA256,
        aead_id: AeadId::AES_256_GCM,
    };

    let experimental_suite = HpkeSuiteId {
        kdf_id: SHA3_ID,
        ..control_suite
    };

    let randomness = vec![0x44; kem.randomness_length()];

    let control = setup_hybrid_base_sender_deterministic(
        kem,
        control_suite,
        &keys.public_key,
        INFO,
        &randomness,
    )
    .unwrap();

    let sender = setup_hybrid_base_sender_deterministic(
        kem,
        experimental_suite,
        &keys.public_key,
        INFO,
        &randomness,
    );

    let receiver = setup_hybrid_base_receiver(
        kem,
        experimental_suite,
        keys.private_seed.as_bytes(),
        &control.encapsulated_key,
        INFO,
    );

    #[cfg(not(feature = "experimental-hkdf-sha3"))]
    {
        assert!(matches!(sender, Err(HpkeError::UnsupportedKdf)));

        assert!(matches!(receiver, Err(HpkeError::UnsupportedKdf)));
    }

    #[cfg(feature = "experimental-hkdf-sha3")]
    {
        let mut sender = sender.unwrap().context;
        let mut receiver = receiver.unwrap();

        let ciphertext = sender.seal(AAD, MSG).unwrap();

        assert_eq!(receiver.open(AAD, &ciphertext).unwrap(), MSG);
    }
}

#[cfg(feature = "experimental-hkdf-sha3")]
mod enabled {
    use super::*;

    use pqc_hpke::hybrid_setup::setup_hybrid_base_sender;
    use pqc_hpke::setup::{
        setup_base_sender_with_suite, setup_psk_receiver, setup_psk_sender_deterministic,
    };

    use pqc_hpke::{HpkeSuite, ReceiverContext, SenderContext};

    use rand_core::OsRng;

    fn reject_or_fail_open(result: Result<ReceiverContext, HpkeError>, ciphertext: &[u8]) {
        // ML-KEM implicit rejection may establish a context
        // with an unrelated secret. Authentication must fail.
        if let Ok(mut receiver) = result {
            assert!(receiver.open(AAD, ciphertext).is_err());
            assert_eq!(receiver.sequence_number(), 0);
        }
    }

    fn exporter_boundaries(sender: &SenderContext, receiver: &ReceiverContext) {
        for length in [0, 1, 31, 32, 33, 8160] {
            let lhs = sender.export(b"boundary", length).unwrap();
            let rhs = receiver.export(b"boundary", length).unwrap();

            assert_eq!(lhs.len(), length);
            assert_eq!(lhs, rhs);
        }

        for length in [8161, 65536, usize::MAX] {
            assert_eq!(
                sender.export(b"boundary", length),
                Err(HpkeError::OutputTooLong)
            );

            assert_eq!(
                receiver.export(b"boundary", length),
                Err(HpkeError::OutputTooLong)
            );
        }

        assert_ne!(
            sender.export(b"domain-a", 32).unwrap(),
            sender.export(b"domain-b", 32).unwrap()
        );

        assert_eq!(sender.sequence_number(), 0);
        assert_eq!(receiver.sequence_number(), 0);
    }

    #[test]
    fn pure_receiver_negative_cases_and_exporter() {
        let kem = MlKemHpke::MlKem768;

        let keys = kem.derive_key_pair(&[0x51; 64]).unwrap();
        let wrong_keys = kem.derive_key_pair(&[0x52; 64]).unwrap();

        let suite = HpkeSuiteId {
            kem_id: kem.kem_id(),
            kdf_id: SHA3_ID,
            aead_id: AeadId::AES_256_GCM,
        };

        let sender =
            setup_base_sender_deterministic(kem, suite, &keys.public_key, INFO, &[0x53; 32])
                .unwrap();

        let enc = sender.encapsulated_key;

        let mut receiver =
            setup_base_receiver(kem, suite, keys.private_key_seed.as_bytes(), &enc, INFO).unwrap();

        let mut context = sender.context;

        exporter_boundaries(&context, &receiver);

        let ciphertext = context.seal(AAD, MSG).unwrap();

        reject_or_fail_open(
            setup_base_receiver(
                kem,
                suite,
                wrong_keys.private_key_seed.as_bytes(),
                &enc,
                INFO,
            ),
            &ciphertext,
        );

        reject_or_fail_open(
            setup_base_receiver(
                kem,
                suite,
                keys.private_key_seed.as_bytes(),
                &enc,
                b"wrong application context",
            ),
            &ciphertext,
        );

        let mut modified = enc.clone();
        modified[0] ^= 1;

        reject_or_fail_open(
            setup_base_receiver(
                kem,
                suite,
                keys.private_key_seed.as_bytes(),
                &modified,
                INFO,
            ),
            &ciphertext,
        );

        let mut extended = enc.clone();
        extended.push(0);

        for malformed in [&[][..], &enc[..enc.len() - 1], extended.as_slice()] {
            assert!(setup_base_receiver(
                kem,
                suite,
                keys.private_key_seed.as_bytes(),
                malformed,
                INFO,
            )
            .is_err());
        }

        assert_eq!(receiver.open(AAD, &ciphertext).unwrap(), MSG);
    }

    #[test]
    fn hybrid_receiver_negative_cases_and_exporter() {
        let kem = HybridKem::MlKem768X25519;

        let keys = kem.derive_key_pair(&[0x61; 32]).unwrap();
        let wrong_keys = kem.derive_key_pair(&[0x62; 32]).unwrap();

        let suite = HpkeSuiteId {
            kem_id: kem.kem_id(),
            kdf_id: SHA3_ID,
            aead_id: AeadId::AES_256_GCM,
        };

        let randomness = vec![0x63; kem.randomness_length()];

        let sender =
            setup_hybrid_base_sender_deterministic(kem, suite, &keys.public_key, INFO, &randomness)
                .unwrap();

        let enc = sender.encapsulated_key;

        let mut receiver =
            setup_hybrid_base_receiver(kem, suite, keys.private_seed.as_bytes(), &enc, INFO)
                .unwrap();

        let mut context = sender.context;

        exporter_boundaries(&context, &receiver);

        let ciphertext = context.seal(AAD, MSG).unwrap();

        reject_or_fail_open(
            setup_hybrid_base_receiver(kem, suite, wrong_keys.private_seed.as_bytes(), &enc, INFO),
            &ciphertext,
        );

        reject_or_fail_open(
            setup_hybrid_base_receiver(
                kem,
                suite,
                keys.private_seed.as_bytes(),
                &enc,
                b"wrong application context",
            ),
            &ciphertext,
        );

        // Independently mutate each KEM ciphertext component.
        for offset in [0, enc.len() - 1] {
            let mut modified = enc.clone();
            modified[offset] ^= 0x40;

            reject_or_fail_open(
                setup_hybrid_base_receiver(
                    kem,
                    suite,
                    keys.private_seed.as_bytes(),
                    &modified,
                    INFO,
                ),
                &ciphertext,
            );
        }

        let mut extended = enc.clone();
        extended.push(0);

        for malformed in [&[][..], &enc[..enc.len() - 1], extended.as_slice()] {
            assert!(setup_hybrid_base_receiver(
                kem,
                suite,
                keys.private_seed.as_bytes(),
                malformed,
                INFO,
            )
            .is_err());
        }

        assert_eq!(receiver.open(AAD, &ciphertext).unwrap(), MSG);
    }

    #[test]
    fn incorrect_psk_and_psk_identity_rejected() {
        let kem = MlKemHpke::MlKem768;

        let keys = kem.derive_key_pair(&[0x71; 64]).unwrap();

        let suite = HpkeSuiteId {
            kem_id: kem.kem_id(),
            kdf_id: SHA3_ID,
            aead_id: AeadId::AES_256_GCM,
        };

        let psk = [0x72; 32];
        let wrong_psk = [0x73; 32];
        let psk_id = b"valid-psk-id";

        let sender = setup_psk_sender_deterministic(
            kem,
            suite,
            &keys.public_key,
            INFO,
            &psk,
            psk_id,
            &[0x74; 32],
        )
        .unwrap();

        let enc = sender.encapsulated_key;

        let mut context = sender.context;
        let ciphertext = context.seal(AAD, MSG).unwrap();

        for (candidate_psk, candidate_id) in [
            (&wrong_psk[..], &psk_id[..]),
            (&psk[..], &b"wrong-psk-id"[..]),
        ] {
            reject_or_fail_open(
                setup_psk_receiver(
                    kem,
                    suite,
                    keys.private_key_seed.as_bytes(),
                    &enc,
                    INFO,
                    candidate_psk,
                    candidate_id,
                ),
                &ciphertext,
            );
        }

        for (candidate_psk, candidate_id) in [
            (&[][..], &[][..]),
            (&psk[..], &[][..]),
            (&[][..], &psk_id[..]),
        ] {
            assert!(setup_psk_receiver(
                kem,
                suite,
                keys.private_key_seed.as_bytes(),
                &enc,
                INFO,
                candidate_psk,
                candidate_id,
            )
            .is_err());
        }

        let mut receiver = setup_psk_receiver(
            kem,
            suite,
            keys.private_key_seed.as_bytes(),
            &enc,
            INFO,
            &psk,
            psk_id,
        )
        .unwrap();

        assert_eq!(receiver.open(AAD, &ciphertext).unwrap(), MSG);
    }

    #[test]
    fn randomized_pure_sender_32_fresh_encapsulations() {
        use std::collections::HashSet;

        let kem = MlKemHpke::MlKem768;
        let keys = kem.derive_key_pair(&[0x81; 64]).unwrap();

        let suite = HpkeSuite::new(kem, SHA3_ID, AeadId::AES_256_GCM).unwrap();

        let mut seen = HashSet::new();

        for _ in 0..32 {
            let sender =
                setup_base_sender_with_suite(kem, suite, &keys.public_key, INFO, &mut OsRng)
                    .unwrap();

            assert!(seen.insert(sender.encapsulated_key.clone()));

            let mut receiver = setup_base_receiver(
                kem,
                suite.id(),
                keys.private_key_seed.as_bytes(),
                &sender.encapsulated_key,
                INFO,
            )
            .unwrap();

            let mut context = sender.context;
            let ciphertext = context.seal(AAD, MSG).unwrap();

            assert_eq!(receiver.open(AAD, &ciphertext).unwrap(), MSG);
        }

        assert_eq!(seen.len(), 32);

        println!("RANDOMIZED_PURE_ROUNDTRIPS=32");
    }

    #[test]
    fn randomized_hybrid_sender_32_fresh_encapsulations() {
        use std::collections::HashSet;

        let kem = HybridKem::MlKem768X25519;
        let keys = kem.derive_key_pair(&[0x91; 32]).unwrap();

        let suite = HpkeSuiteId {
            kem_id: kem.kem_id(),
            kdf_id: SHA3_ID,
            aead_id: AeadId::AES_256_GCM,
        };

        let mut seen = HashSet::new();

        for _ in 0..32 {
            let sender =
                setup_hybrid_base_sender(kem, suite, &keys.public_key, INFO, &mut OsRng).unwrap();

            assert!(seen.insert(sender.encapsulated_key.clone()));

            let mut receiver = setup_hybrid_base_receiver(
                kem,
                suite,
                keys.private_seed.as_bytes(),
                &sender.encapsulated_key,
                INFO,
            )
            .unwrap();

            let mut context = sender.context;
            let ciphertext = context.seal(AAD, MSG).unwrap();

            assert_eq!(receiver.open(AAD, &ciphertext).unwrap(), MSG);
        }

        assert_eq!(seen.len(), 32);

        println!("RANDOMIZED_HYBRID_ROUNDTRIPS=32");
    }
}
