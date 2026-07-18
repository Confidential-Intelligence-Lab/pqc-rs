use pqc_hpke::identifiers::{AeadId, HpkeSuiteId, KdfId};
use pqc_hpke::ml_kem::MlKemHpke;
use pqc_hpke::setup::{setup_psk_receiver, setup_psk_sender_deterministic};
use pqc_hpke::HpkeError;

fn suite(kem: MlKemHpke) -> HpkeSuiteId {
    HpkeSuiteId {
        kem_id: kem.kem_id(),
        kdf_id: KdfId::HKDF_SHA256,
        aead_id: AeadId::AES_128_GCM,
    }
}

#[test]
fn psk_mode_round_trips_for_all_ml_kem_parameter_sets() {
    for kem in [
        MlKemHpke::MlKem512,
        MlKemHpke::MlKem768,
        MlKemHpke::MlKem1024,
    ] {
        let key_pair = kem.derive_key_pair(&[0x11; 64]).unwrap();
        let sender = setup_psk_sender_deterministic(
            kem,
            suite(kem),
            &key_pair.public_key,
            b"b1.1 psk mode",
            b"shared deployment secret",
            b"deployment-key-2026",
            &[0x22; 32],
        )
        .unwrap();
        let mut receiver = setup_psk_receiver(
            kem,
            suite(kem),
            key_pair.private_key_seed.as_bytes(),
            &sender.encapsulated_key,
            b"b1.1 psk mode",
            b"shared deployment secret",
            b"deployment-key-2026",
        )
        .unwrap();
        let mut sender_context = sender.context;

        let ciphertext = sender_context.seal(b"aad", b"protected message").unwrap();
        assert_eq!(
            receiver.open(b"aad", &ciphertext).unwrap(),
            b"protected message"
        );
        assert_eq!(
            sender_context.export(b"application exporter", 64).unwrap(),
            receiver.export(b"application exporter", 64).unwrap()
        );
    }
}

#[test]
fn psk_inputs_are_strictly_validated() {
    let kem = MlKemHpke::MlKem768;
    let key_pair = kem.derive_key_pair(&[0x31; 64]).unwrap();

    let missing_id = setup_psk_sender_deterministic(
        kem,
        suite(kem),
        &key_pair.public_key,
        b"info",
        b"psk",
        b"",
        &[0x41; 32],
    );
    assert!(matches!(missing_id, Err(HpkeError::InconsistentPskInputs)));

    let missing_both = setup_psk_sender_deterministic(
        kem,
        suite(kem),
        &key_pair.public_key,
        b"info",
        b"",
        b"",
        &[0x41; 32],
    );
    assert!(matches!(missing_both, Err(HpkeError::MissingPsk)));
}

#[test]
fn incorrect_psk_or_identity_cannot_open_ciphertext() {
    let kem = MlKemHpke::MlKem512;
    let key_pair = kem.derive_key_pair(&[0x51; 64]).unwrap();
    let sender = setup_psk_sender_deterministic(
        kem,
        suite(kem),
        &key_pair.public_key,
        b"info",
        b"correct psk",
        b"correct id",
        &[0x61; 32],
    )
    .unwrap();
    let mut sender_context = sender.context;
    let ciphertext = sender_context.seal(b"aad", b"message").unwrap();

    for (psk, psk_id) in [
        (&b"wrong psk"[..], &b"correct id"[..]),
        (&b"correct psk"[..], &b"wrong id"[..]),
    ] {
        let mut receiver = setup_psk_receiver(
            kem,
            suite(kem),
            key_pair.private_key_seed.as_bytes(),
            &sender.encapsulated_key,
            b"info",
            psk,
            psk_id,
        )
        .unwrap();
        assert!(matches!(
            receiver.open(b"aad", &ciphertext),
            Err(HpkeError::OpenError)
        ));
        assert_eq!(receiver.sequence_number(), 0);
    }
}

#[test]
fn exporter_accepts_zero_and_maximum_hkdf_sha256_lengths() {
    let kem = MlKemHpke::MlKem512;
    let key_pair = kem.derive_key_pair(&[0x71; 64]).unwrap();
    let sender = setup_psk_sender_deterministic(
        kem,
        suite(kem),
        &key_pair.public_key,
        b"export lengths",
        b"psk",
        b"id",
        &[0x81; 32],
    )
    .unwrap();

    assert!(sender.context.export(b"zero", 0).unwrap().is_empty());
    assert_eq!(
        sender.context.export(b"maximum", 255 * 32).unwrap().len(),
        255 * 32
    );
    assert_eq!(
        sender.context.export(b"too long", 255 * 32 + 1),
        Err(HpkeError::OutputTooLong)
    );
}
