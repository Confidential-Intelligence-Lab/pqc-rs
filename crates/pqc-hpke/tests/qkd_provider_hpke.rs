//! End-to-end integration of experimental paired-key provisioning with HPKE.
use pqc_hpke::qkd::{QkdKeyStore, QkdProvenance, QkdProviderError};
use pqc_hpke::setup::setup_psk_receiver_with_suite;
use pqc_hpke::{setup_psk_sender_with_suite, AeadId, HpkeSuite, KdfId, MlKemHpke};
use rand_core::OsRng;

const INFO: &[u8] = b"pqc-rs/qkd-hybrid/experimental-hpke/v1;alice;bob";
const AAD: &[u8] = b"qkd-m1b;alice-to-bob";

#[test]
fn paired_simulated_keys_drive_randomized_ml_kem_768_hpke() {
    let mut alice = QkdKeyStore::new();
    let mut bob = QkdKeyStore::new();
    // Fixed artificial fixture; not a claim of QKD-derived security.
    alice
        .provision_fixture("sim-key-0001", "alice", "bob", [0xA5; 32])
        .unwrap();
    bob.provision_fixture("sim-key-0001", "bob", "alice", [0xA5; 32])
        .unwrap();
    let sender_key = alice.take_for("sim-key-0001", "alice", "bob").unwrap();
    let receiver_key = bob.take_for("sim-key-0001", "bob", "alice").unwrap();
    assert_eq!(sender_key.provenance(), QkdProvenance::SimulationFixture);
    assert_eq!(sender_key.secret(), receiver_key.secret());

    let kem = MlKemHpke::MlKem768;
    let suite = HpkeSuite::new(kem, KdfId::HKDF_SHA256, AeadId::CHACHA20_POLY1305).unwrap();
    let recipient = kem.generate_key_pair(&mut OsRng).unwrap();
    let sender = setup_psk_sender_with_suite(
        kem,
        suite,
        &recipient.public_key,
        INFO,
        sender_key.secret(),
        sender_key.id().as_bytes(),
        &mut OsRng,
    )
    .unwrap();
    let mut receiver = setup_psk_receiver_with_suite(
        kem,
        suite,
        recipient.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        INFO,
        receiver_key.secret(),
        receiver_key.id().as_bytes(),
    )
    .unwrap();
    let mut sender_context = sender.context;
    let ciphertext = sender_context
        .seal(AAD, b"QKD M1.B encrypted message")
        .unwrap();
    assert_eq!(
        receiver.open(AAD, &ciphertext).unwrap(),
        b"QKD M1.B encrypted message"
    );
    assert_eq!(
        alice.take_for("sim-key-0001", "alice", "bob").unwrap_err(),
        QkdProviderError::KeyUnavailable
    );
    assert_eq!(
        bob.take_for("sim-key-0001", "bob", "alice").unwrap_err(),
        QkdProviderError::KeyUnavailable
    );
}

#[test]
fn provider_rejects_duplicate_wrong_party_and_missing_keys() {
    let mut provider = QkdKeyStore::new();
    provider
        .provision_fixture("id-1", "alice", "bob", [7; 32])
        .unwrap();
    assert_eq!(
        provider.provision_fixture("id-1", "alice", "bob", [9; 32]),
        Err(QkdProviderError::DuplicateKeyId)
    );
    assert_eq!(
        provider.take_for("id-1", "eve", "bob").unwrap_err(),
        QkdProviderError::Unauthorized
    );
    assert_eq!(
        provider.take_for("unknown", "alice", "bob").unwrap_err(),
        QkdProviderError::KeyUnavailable
    );
    assert!(provider.take_for("id-1", "alice", "bob").is_ok());
    assert_eq!(
        provider.take_for("id-1", "alice", "bob").unwrap_err(),
        QkdProviderError::KeyUnavailable
    );
    assert_eq!(
        provider.provision_fixture("id-1", "alice", "bob", [7; 32]),
        Err(QkdProviderError::DuplicateKeyId)
    );
    assert_eq!(
        provider.provision_fixture("", "alice", "bob", [0; 32]),
        Err(QkdProviderError::InvalidMetadata)
    );
    assert_eq!(
        provider.provision_fixture("id-2", "alice", "alice", [0; 32]),
        Err(QkdProviderError::InvalidMetadata)
    );
}

#[test]
fn incorrect_qkd_key_rejects_hpke_ciphertext() {
    let kem = MlKemHpke::MlKem768;
    let suite = HpkeSuite::new(kem, KdfId::HKDF_SHA256, AeadId::CHACHA20_POLY1305).unwrap();
    let recipient = kem.generate_key_pair(&mut OsRng).unwrap();
    let sender = setup_psk_sender_with_suite(
        kem,
        suite,
        &recipient.public_key,
        INFO,
        &[0xA5; 32],
        b"sim-key-0002",
        &mut OsRng,
    )
    .unwrap();
    let mut context = sender.context;
    let ciphertext = context.seal(AAD, b"must remain confidential").unwrap();
    let mut receiver = setup_psk_receiver_with_suite(
        kem,
        suite,
        recipient.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        INFO,
        &[0xB6; 32],
        b"sim-key-0002",
    )
    .unwrap();
    assert!(receiver.open(AAD, &ciphertext).is_err());
    assert_eq!(receiver.sequence_number(), 0);
}
