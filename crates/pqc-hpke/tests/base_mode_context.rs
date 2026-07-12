use pqc_hpke::identifiers::{AeadId, HpkeSuiteId, KdfId};
use pqc_hpke::ml_kem::MlKemHpke;
use pqc_hpke::setup::{setup_base_receiver, setup_base_sender_deterministic};

fn suite(kem: MlKemHpke, aead: AeadId) -> HpkeSuiteId {
    HpkeSuiteId {
        kem_id: kem.kem_id(),
        kdf_id: KdfId::HKDF_SHA256,
        aead_id: aead,
    }
}

#[test]
fn base_mode_round_trips_multiple_messages() {
    let kem = MlKemHpke::MlKem768;
    let key_pair = kem.derive_key_pair(&[0x11; 64]).unwrap();
    let suite = suite(kem, AeadId::AES_128_GCM);
    let sender =
        setup_base_sender_deterministic(kem, suite, &key_pair.public_key, b"stage7b4", &[0x22; 32])
            .unwrap();
    let mut receiver = setup_base_receiver(
        kem,
        suite,
        key_pair.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        b"stage7b4",
    )
    .unwrap();
    let mut sender_context = sender.context;
    for index in 0u8..3 {
        let plaintext = vec![index; 19];
        let ciphertext = sender_context.seal(b"associated data", &plaintext).unwrap();
        let recovered = receiver.open(b"associated data", &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }
    assert_eq!(sender_context.sequence_number(), 3);
    assert_eq!(receiver.sequence_number(), 3);
}

#[test]
fn sender_and_receiver_export_same_secret() {
    let kem = MlKemHpke::MlKem512;
    let key_pair = kem.derive_key_pair(&[0x31; 64]).unwrap();
    let suite = suite(kem, AeadId::CHACHA20_POLY1305);
    let sender = setup_base_sender_deterministic(
        kem,
        suite,
        &key_pair.public_key,
        b"export-test",
        &[0x41; 32],
    )
    .unwrap();
    let receiver = setup_base_receiver(
        kem,
        suite,
        key_pair.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        b"export-test",
    )
    .unwrap();
    assert_eq!(
        sender.context.export(b"context", 48).unwrap(),
        receiver.export(b"context", 48).unwrap(),
    );
}

#[test]
fn failed_open_does_not_advance_sequence() {
    let kem = MlKemHpke::MlKem768;
    let key_pair = kem.derive_key_pair(&[0x51; 64]).unwrap();
    let suite = suite(kem, AeadId::AES_256_GCM);
    let sender = setup_base_sender_deterministic(
        kem,
        suite,
        &key_pair.public_key,
        b"failure-test",
        &[0x61; 32],
    )
    .unwrap();
    let mut receiver = setup_base_receiver(
        kem,
        suite,
        key_pair.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        b"failure-test",
    )
    .unwrap();
    assert!(receiver.open(b"aad", &[0u8; 32]).is_err());
    assert_eq!(receiver.sequence_number(), 0);
}
