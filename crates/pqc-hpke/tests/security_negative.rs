use pqc_hpke::identifiers::{AeadId, HpkeSuiteId, KdfId};
use pqc_hpke::ml_kem::MlKemHpke;
use pqc_hpke::setup::{setup_base_receiver, setup_base_sender_deterministic};

fn suite(kem: MlKemHpke) -> HpkeSuiteId {
    HpkeSuiteId {
        kem_id: kem.kem_id(),
        kdf_id: KdfId::HKDF_SHA256,
        aead_id: AeadId::AES_128_GCM,
    }
}

#[test]
fn altered_aad_is_rejected_without_advancing_receiver_sequence() {
    let kem = MlKemHpke::MlKem768;
    let key_pair = kem.derive_key_pair(&[0x11; 64]).unwrap();
    let suite = suite(kem);

    let sender = setup_base_sender_deterministic(
        kem,
        suite,
        &key_pair.public_key,
        b"security-negative",
        &[0x22; 32],
    )
    .unwrap();

    let mut sender_context = sender.context;
    let mut receiver_context = setup_base_receiver(
        kem,
        suite,
        key_pair.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        b"security-negative",
    )
    .unwrap();

    let ciphertext = sender_context.seal(b"correct aad", b"message").unwrap();

    assert!(receiver_context.open(b"wrong aad", &ciphertext).is_err());
    assert_eq!(receiver_context.sequence_number(), 0);
    assert_eq!(
        receiver_context.open(b"correct aad", &ciphertext).unwrap(),
        b"message"
    );
    assert_eq!(receiver_context.sequence_number(), 1);
}

#[test]
fn modified_ciphertext_is_rejected_without_advancing_sequence() {
    let kem = MlKemHpke::MlKem512;
    let key_pair = kem.derive_key_pair(&[0x31; 64]).unwrap();
    let suite = suite(kem);

    let sender = setup_base_sender_deterministic(
        kem,
        suite,
        &key_pair.public_key,
        b"tamper-test",
        &[0x41; 32],
    )
    .unwrap();

    let mut sender_context = sender.context;
    let mut receiver_context = setup_base_receiver(
        kem,
        suite,
        key_pair.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        b"tamper-test",
    )
    .unwrap();

    let mut ciphertext = sender_context.seal(b"aad", b"message").unwrap();
    ciphertext[0] ^= 1;

    assert!(receiver_context.open(b"aad", &ciphertext).is_err());
    assert_eq!(receiver_context.sequence_number(), 0);
}

#[test]
fn different_info_values_produce_incompatible_contexts() {
    let kem = MlKemHpke::MlKem768;
    let key_pair = kem.derive_key_pair(&[0x51; 64]).unwrap();
    let suite = suite(kem);

    let sender = setup_base_sender_deterministic(
        kem,
        suite,
        &key_pair.public_key,
        b"sender info",
        &[0x61; 32],
    )
    .unwrap();

    let mut sender_context = sender.context;
    let mut receiver_context = setup_base_receiver(
        kem,
        suite,
        key_pair.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        b"receiver info",
    )
    .unwrap();

    let ciphertext = sender_context.seal(b"aad", b"message").unwrap();
    assert!(receiver_context.open(b"aad", &ciphertext).is_err());
    assert_eq!(receiver_context.sequence_number(), 0);
}

#[test]
fn exporter_is_domain_separated_by_context() {
    let kem = MlKemHpke::MlKem512;
    let key_pair = kem.derive_key_pair(&[0x71; 64]).unwrap();
    let suite = suite(kem);

    let sender = setup_base_sender_deterministic(
        kem,
        suite,
        &key_pair.public_key,
        b"exporter-test",
        &[0x81; 32],
    )
    .unwrap();

    let left = sender.context.export(b"left", 32).unwrap();
    let right = sender.context.export(b"right", 32).unwrap();

    assert_ne!(left, right);
}
