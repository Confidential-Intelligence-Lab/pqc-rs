#![cfg(feature = "experimental-hkdf-sha3")]

use pqc_hpke::hybrid_kem::HybridKem;

use pqc_hpke::hybrid_setup::{setup_hybrid_base_receiver, setup_hybrid_base_sender_deterministic};

use pqc_hpke::setup::{
    setup_base_receiver, setup_base_sender_deterministic, setup_psk_receiver,
    setup_psk_sender_deterministic,
};

use pqc_hpke::{
    supported_aeads, AeadId, HpkeSuiteId, KdfId, MlKemHpke, ReceiverContext, SenderContext,
};

const SHA3: KdfId = KdfId::EXPERIMENTAL_HKDF_SHA3_256;
const SHA2: KdfId = KdfId::HKDF_SHA256;

const INFO: &[u8] = b"pqc-rs/experimental/sha3/suite-matrix/v1";

const AAD: &[u8] = b"experimental-suite-aad";

const PSK: &[u8] = &[0x73; 32];
const PSK_ID: &[u8] = b"experimental-psk-id";

const PURE_KEMS: [MlKemHpke; 3] = [
    MlKemHpke::MlKem512,
    MlKemHpke::MlKem768,
    MlKemHpke::MlKem1024,
];

const HYBRID_KEMS: [HybridKem; 3] = [
    HybridKem::MlKem768X25519,
    HybridKem::MlKem768P256,
    HybridKem::MlKem1024P384,
];

fn exercise_contexts(
    mut sender: SenderContext,
    mut receiver: ReceiverContext,
    mut wrong_kdf_receiver: ReceiverContext,
) -> Vec<u8> {
    assert_eq!(sender.sequence_number(), 0);
    assert_eq!(receiver.sequence_number(), 0);

    // Exporter agreement and domain separation.

    let exported = sender.export(b"matrix exporter", 80).unwrap();

    assert_eq!(exported, receiver.export(b"matrix exporter", 80).unwrap());

    assert_ne!(exported, sender.export(b"different exporter", 80).unwrap());

    assert_ne!(
        exported,
        wrong_kdf_receiver.export(b"matrix exporter", 80).unwrap()
    );

    // Three messages with different plaintext lengths.

    let empty = Vec::new();
    let short = b"subscriber identity".to_vec();
    let long = vec![0x5a; 1024];

    let messages = [empty, short, long];

    for (index, plaintext) in messages.iter().enumerate() {
        let sequence = index as u64;

        assert_eq!(sender.sequence_number(), sequence);

        assert_eq!(receiver.sequence_number(), sequence);

        let ciphertext = sender.seal(AAD, plaintext).unwrap();

        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        // Negative case 1: cross-KDF authentication.

        if index == 0 {
            assert!(wrong_kdf_receiver.open(AAD, &ciphertext).is_err());

            assert_eq!(wrong_kdf_receiver.sequence_number(), 0);
        }

        // Negative case 2: altered AAD.

        assert!(receiver.open(b"incorrect aad", &ciphertext).is_err());

        assert_eq!(receiver.sequence_number(), sequence);

        // Negative case 3: altered ciphertext.

        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0x01;

        assert!(receiver.open(AAD, &tampered).is_err());

        assert_eq!(receiver.sequence_number(), sequence);

        // Correct ciphertext remains usable after
        // the unsuccessful authentication attempts.

        assert_eq!(receiver.open(AAD, &ciphertext).unwrap(), *plaintext);

        assert_eq!(receiver.sequence_number(), sequence + 1);

        assert_eq!(sender.sequence_number(), sequence + 1);

        // Negative case 4: replay within this context.

        assert!(receiver.open(AAD, &ciphertext).is_err());

        assert_eq!(receiver.sequence_number(), sequence + 1);
    }

    assert!(!sender.is_exhausted());
    assert!(!receiver.is_exhausted());

    exported
}

fn pure_base_case(
    kem: MlKemHpke,
    aead: AeadId,
    kdf: KdfId,
    other_kdf: KdfId,
    domain: u8,
) -> Vec<u8> {
    let seed = [domain; 64];

    let randomness = [domain.wrapping_add(0x80); 32];

    let keys = kem.derive_key_pair(&seed).unwrap();

    let suite = HpkeSuiteId {
        kem_id: kem.kem_id(),
        kdf_id: kdf,
        aead_id: aead,
    };

    let wrong_suite = HpkeSuiteId {
        kdf_id: other_kdf,
        ..suite
    };

    let sender =
        setup_base_sender_deterministic(kem, suite, &keys.public_key, INFO, &randomness).unwrap();

    let receiver = setup_base_receiver(
        kem,
        suite,
        keys.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        INFO,
    )
    .unwrap();

    let wrong_receiver = setup_base_receiver(
        kem,
        wrong_suite,
        keys.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        INFO,
    )
    .unwrap();

    exercise_contexts(sender.context, receiver, wrong_receiver)
}

fn pure_psk_case(
    kem: MlKemHpke,
    aead: AeadId,
    kdf: KdfId,
    other_kdf: KdfId,
    domain: u8,
) -> Vec<u8> {
    let seed = [domain; 64];

    let randomness = [domain.wrapping_add(0x80); 32];

    let keys = kem.derive_key_pair(&seed).unwrap();

    let suite = HpkeSuiteId {
        kem_id: kem.kem_id(),
        kdf_id: kdf,
        aead_id: aead,
    };

    let wrong_suite = HpkeSuiteId {
        kdf_id: other_kdf,
        ..suite
    };

    let sender = setup_psk_sender_deterministic(
        kem,
        suite,
        &keys.public_key,
        INFO,
        PSK,
        PSK_ID,
        &randomness,
    )
    .unwrap();

    let receiver = setup_psk_receiver(
        kem,
        suite,
        keys.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        INFO,
        PSK,
        PSK_ID,
    )
    .unwrap();

    let wrong_receiver = setup_psk_receiver(
        kem,
        wrong_suite,
        keys.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        INFO,
        PSK,
        PSK_ID,
    )
    .unwrap();

    exercise_contexts(sender.context, receiver, wrong_receiver)
}

fn hybrid_base_case(
    kem: HybridKem,
    aead: AeadId,
    kdf: KdfId,
    other_kdf: KdfId,
    domain: u8,
) -> Vec<u8> {
    let seed = [domain; 32];

    let randomness = vec![domain.wrapping_add(0x80); kem.randomness_length()];

    let keys = kem.derive_key_pair(&seed).unwrap();

    let suite = HpkeSuiteId {
        kem_id: kem.kem_id(),
        kdf_id: kdf,
        aead_id: aead,
    };

    let wrong_suite = HpkeSuiteId {
        kdf_id: other_kdf,
        ..suite
    };

    let sender =
        setup_hybrid_base_sender_deterministic(kem, suite, &keys.public_key, INFO, &randomness)
            .unwrap();

    assert_eq!(sender.encapsulated_key.len(), kem.encapsulation_length());

    let receiver = setup_hybrid_base_receiver(
        kem,
        suite,
        keys.private_seed.as_bytes(),
        &sender.encapsulated_key,
        INFO,
    )
    .unwrap();

    let wrong_receiver = setup_hybrid_base_receiver(
        kem,
        wrong_suite,
        keys.private_seed.as_bytes(),
        &sender.encapsulated_key,
        INFO,
    )
    .unwrap();

    exercise_contexts(sender.context, receiver, wrong_receiver)
}

#[test]
fn pure_base_sha3_suite_matrix() {
    let mut count = 0;

    for (i, kem) in PURE_KEMS.into_iter().enumerate() {
        for (j, aead) in supported_aeads().into_iter().enumerate() {
            let domain = (1 + i * 3 + j) as u8;

            let sha3 = pure_base_case(kem, aead, SHA3, SHA2, domain);

            let sha2 = pure_base_case(kem, aead, SHA2, SHA3, domain);

            assert_ne!(sha3, sha2);

            println!("PURE_BASE_PAIR=PASS kem={:?} aead={:?}", kem, aead);

            count += 1;
        }
    }

    assert_eq!(count, 9);

    println!("PURE_BASE_SHA3_SUITES={count}");
    println!("PURE_BASE_SHA2_CONTROLS={count}");
}

#[test]
fn pure_psk_sha3_suite_matrix() {
    let mut count = 0;

    for (i, kem) in PURE_KEMS.into_iter().enumerate() {
        for (j, aead) in supported_aeads().into_iter().enumerate() {
            let domain = (21 + i * 3 + j) as u8;

            let sha3 = pure_psk_case(kem, aead, SHA3, SHA2, domain);

            let sha2 = pure_psk_case(kem, aead, SHA2, SHA3, domain);

            assert_ne!(sha3, sha2);

            println!("PURE_PSK_PAIR=PASS kem={:?} aead={:?}", kem, aead);

            count += 1;
        }
    }

    assert_eq!(count, 9);

    println!("PURE_PSK_SHA3_SUITES={count}");
    println!("PURE_PSK_SHA2_CONTROLS={count}");
}

#[test]
fn hybrid_base_sha3_suite_matrix() {
    let mut count = 0;

    for (i, kem) in HYBRID_KEMS.into_iter().enumerate() {
        for (j, aead) in supported_aeads().into_iter().enumerate() {
            let domain = (41 + i * 3 + j) as u8;

            let sha3 = hybrid_base_case(kem, aead, SHA3, SHA2, domain);

            let sha2 = hybrid_base_case(kem, aead, SHA2, SHA3, domain);

            assert_ne!(sha3, sha2);

            println!("HYBRID_BASE_PAIR=PASS kem={:?} aead={:?}", kem, aead);

            count += 1;
        }
    }

    assert_eq!(count, 9);

    println!("HYBRID_BASE_SHA3_SUITES={count}");
    println!("HYBRID_BASE_SHA2_CONTROLS={count}");
}
