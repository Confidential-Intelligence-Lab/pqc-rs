use pqc_hpke::identifiers::{AeadId, HpkeSuiteId, KdfId};
use pqc_hpke::ml_kem::MlKemHpke;
use pqc_hpke::setup::{
    setup_base_receiver, setup_base_receiver_with_suite, setup_base_sender_deterministic,
    setup_base_sender_with_suite_deterministic, setup_psk_receiver, setup_psk_receiver_with_suite,
    setup_psk_sender_deterministic, setup_psk_sender_with_suite_deterministic,
};
use pqc_hpke::suite::{supported_aeads, supported_kdfs, HpkeSuite};
use pqc_hpke::HpkeError;

const KEMS: [MlKemHpke; 3] = [
    MlKemHpke::MlKem512,
    MlKemHpke::MlKem768,
    MlKemHpke::MlKem1024,
];

fn deterministic_material(kem_index: usize, kdf: KdfId, aead: AeadId) -> ([u8; 64], [u8; 32]) {
    let mut ikm = [0u8; 64];
    let mut randomness = [0u8; 32];
    let domain = (kem_index as u8)
        .wrapping_mul(37)
        .wrapping_add(kdf.0 as u8)
        .wrapping_add((aead.0 as u8).wrapping_mul(11));
    for (index, byte) in ikm.iter_mut().enumerate() {
        *byte = domain.wrapping_add(index as u8);
    }
    for (index, byte) in randomness.iter_mut().enumerate() {
        *byte = domain.wrapping_add(0x80).wrapping_add(index as u8);
    }
    (ikm, randomness)
}

#[test]
fn base_mode_covers_all_twenty_seven_message_suites() {
    let mut executed = 0;

    for (kem_index, kem) in KEMS.into_iter().enumerate() {
        for kdf_id in supported_kdfs() {
            for aead_id in supported_aeads() {
                let suite = HpkeSuite::new(kem, kdf_id, aead_id).unwrap();
                let (ikm, randomness) = deterministic_material(kem_index, kdf_id, aead_id);
                let key_pair = kem.derive_key_pair(&ikm).unwrap();
                let sender = setup_base_sender_deterministic(
                    kem,
                    suite.id(),
                    &key_pair.public_key,
                    b"b1.2 base matrix",
                    &randomness,
                )
                .unwrap();
                let mut receiver = setup_base_receiver(
                    kem,
                    suite.id(),
                    key_pair.private_key_seed.as_bytes(),
                    &sender.encapsulated_key,
                    b"b1.2 base matrix",
                )
                .unwrap();
                let mut sender_context = sender.context;

                let ciphertext = sender_context
                    .seal(b"matrix aad", b"base-mode matrix message")
                    .unwrap();
                assert_eq!(
                    receiver.open(b"matrix aad", &ciphertext).unwrap(),
                    b"base-mode matrix message"
                );
                assert_eq!(
                    sender_context.export(b"b1.2 exporter", 64).unwrap(),
                    receiver.export(b"b1.2 exporter", 64).unwrap()
                );
                executed += 1;
            }
        }
    }

    assert_eq!(executed, 27);
}

#[test]
fn psk_mode_covers_all_twenty_seven_message_suites() {
    let mut executed = 0;

    for (kem_index, kem) in KEMS.into_iter().enumerate() {
        for kdf_id in supported_kdfs() {
            for aead_id in supported_aeads() {
                let suite = HpkeSuite::new(kem, kdf_id, aead_id).unwrap();
                let (ikm, randomness) = deterministic_material(kem_index, kdf_id, aead_id);
                let key_pair = kem.derive_key_pair(&ikm).unwrap();
                let sender = setup_psk_sender_deterministic(
                    kem,
                    suite.id(),
                    &key_pair.public_key,
                    b"b1.2 psk matrix",
                    b"b1.2 shared psk",
                    b"b1.2 psk identifier",
                    &randomness,
                )
                .unwrap();
                let mut receiver = setup_psk_receiver(
                    kem,
                    suite.id(),
                    key_pair.private_key_seed.as_bytes(),
                    &sender.encapsulated_key,
                    b"b1.2 psk matrix",
                    b"b1.2 shared psk",
                    b"b1.2 psk identifier",
                )
                .unwrap();
                let mut sender_context = sender.context;

                let ciphertext = sender_context
                    .seal(b"matrix aad", b"psk-mode matrix message")
                    .unwrap();
                assert_eq!(
                    receiver.open(b"matrix aad", &ciphertext).unwrap(),
                    b"psk-mode matrix message"
                );
                assert_eq!(
                    sender_context.export(b"b1.2 exporter", 64).unwrap(),
                    receiver.export(b"b1.2 exporter", 64).unwrap()
                );
                executed += 1;
            }
        }
    }

    assert_eq!(executed, 27);
}

#[test]
fn setup_rejects_unsupported_suite_identifiers() {
    let kem = MlKemHpke::MlKem512;
    let key_pair = kem.derive_key_pair(&[0x55; 64]).unwrap();

    let unsupported_kdf = HpkeSuiteId {
        kem_id: kem.kem_id(),
        kdf_id: KdfId(0xfffe),
        aead_id: AeadId::AES_128_GCM,
    };
    assert!(matches!(
        setup_base_sender_deterministic(
            kem,
            unsupported_kdf,
            &key_pair.public_key,
            b"unsupported",
            &[0x66; 32],
        ),
        Err(HpkeError::UnsupportedKdf)
    ));

    let unsupported_aead = HpkeSuiteId {
        kem_id: kem.kem_id(),
        kdf_id: KdfId::HKDF_SHA256,
        aead_id: AeadId(0xfffe),
    };
    assert!(matches!(
        setup_base_sender_deterministic(
            kem,
            unsupported_aead,
            &key_pair.public_key,
            b"unsupported",
            &[0x77; 32],
        ),
        Err(HpkeError::UnsupportedAead)
    ));
}

#[test]
fn suite_first_entry_points_preserve_validated_suite() {
    let kem = MlKemHpke::MlKem768;
    let suite = HpkeSuite::new(kem, KdfId::HKDF_SHA384, AeadId::AES_256_GCM).unwrap();
    let key_pair = kem.derive_key_pair(&[0x31; 64]).unwrap();

    let sender = setup_base_sender_with_suite_deterministic(
        kem,
        suite,
        &key_pair.public_key,
        b"b1.3.1 suite-first",
        &[0x42; 32],
    )
    .unwrap();
    let mut receiver = setup_base_receiver_with_suite(
        kem,
        suite,
        key_pair.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        b"b1.3.1 suite-first",
    )
    .unwrap();
    let mut sender_context = sender.context;
    let ciphertext = sender_context.seal(b"aad", b"suite-first base").unwrap();
    assert_eq!(
        receiver.open(b"aad", &ciphertext).unwrap(),
        b"suite-first base"
    );

    let psk_sender = setup_psk_sender_with_suite_deterministic(
        kem,
        suite,
        &key_pair.public_key,
        b"b1.3.1 suite-first psk",
        b"shared psk",
        b"psk id",
        &[0x43; 32],
    )
    .unwrap();
    let mut psk_receiver = setup_psk_receiver_with_suite(
        kem,
        suite,
        key_pair.private_key_seed.as_bytes(),
        &psk_sender.encapsulated_key,
        b"b1.3.1 suite-first psk",
        b"shared psk",
        b"psk id",
    )
    .unwrap();
    let mut psk_sender_context = psk_sender.context;
    let ciphertext = psk_sender_context.seal(b"aad", b"suite-first psk").unwrap();
    assert_eq!(
        psk_receiver.open(b"aad", &ciphertext).unwrap(),
        b"suite-first psk"
    );
}
