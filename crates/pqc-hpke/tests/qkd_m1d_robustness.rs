//! M1.D: protocol-composition negative cases for simulated QKD + HPKE PSK.
//! Does not establish security of BB84, a quantum link, or an authenticated KME.
use pqc_hpke::qkd::{QkdKeyStore, QkdProviderError};
use pqc_hpke::setup::setup_psk_receiver_with_suite;
use pqc_hpke::{setup_psk_sender_with_suite, AeadId, HpkeSuite, KdfId, MlKemHpke};
use rand_core::OsRng;

const INFO: &[u8] = b"pqc-rs/qkd-m1d/hybrid-hpke/v1;alice;bob";
const AAD: &[u8] = b"qkd-m1d;alice-to-bob";

#[test]
fn hybrid_messaging_rejects_tampering_wrong_context_and_wrong_psk_identity() {
    let kem = MlKemHpke::MlKem768;
    let suite = HpkeSuite::new(kem, KdfId::HKDF_SHA256, AeadId::CHACHA20_POLY1305).unwrap();
    let recipient = kem.generate_key_pair(&mut OsRng).unwrap();
    let sender = setup_psk_sender_with_suite(
        kem,
        suite,
        &recipient.public_key,
        INFO,
        &[0xA5; 32],
        b"qkd-m1d-key-001",
        &mut OsRng,
    )
    .unwrap();
    let mut sender_ctx = sender.context;
    let ct = sender_ctx
        .seal(AAD, b"protected experimental message")
        .unwrap();

    let receiver = |info: &[u8], psk: &[u8], id: &[u8]| {
        setup_psk_receiver_with_suite(
            kem,
            suite,
            recipient.private_key_seed.as_bytes(),
            &sender.encapsulated_key,
            info,
            psk,
            id,
        )
        .unwrap()
    };

    let mut valid = receiver(INFO, &[0xA5; 32], b"qkd-m1d-key-001");
    let mut tampered = ct.clone();
    tampered[0] ^= 1;
    assert!(valid.open(AAD, &tampered).is_err());
    assert_eq!(valid.sequence_number(), 0);
    assert!(valid.open(b"different-aad", &ct).is_err());
    assert_eq!(valid.sequence_number(), 0);
    assert_eq!(
        valid.open(AAD, &ct).unwrap(),
        b"protected experimental message"
    );

    for (info, psk, id) in [
        (INFO, &[0xB6; 32][..], &b"qkd-m1d-key-001"[..]),
        (INFO, &[0xA5; 32][..], &b"qkd-m1d-key-OTHER"[..]),
        (
            &b"wrong-application-context"[..],
            &[0xA5; 32][..],
            &b"qkd-m1d-key-001"[..],
        ),
    ] {
        let mut wrong = receiver(info, psk, id);
        assert!(wrong.open(AAD, &ct).is_err());
        assert_eq!(wrong.sequence_number(), 0);
    }
}

#[test]
fn provider_denies_key_reuse_unauthorized_access_and_reprovisioning() {
    let mut alice = QkdKeyStore::new();
    let mut bob = QkdKeyStore::new();
    alice
        .provision_fixture("qkd-m1d-key-002", "alice", "bob", [0x23; 32])
        .unwrap();
    bob.provision_fixture("qkd-m1d-key-002", "bob", "alice", [0x23; 32])
        .unwrap();
    assert_eq!(
        alice.take_for("qkd-m1d-key-002", "eve", "bob").unwrap_err(),
        QkdProviderError::Unauthorized
    );
    let a = alice.take_for("qkd-m1d-key-002", "alice", "bob").unwrap();
    let b = bob.take_for("qkd-m1d-key-002", "bob", "alice").unwrap();
    assert_eq!(a.secret(), b.secret());
    assert_eq!(
        alice
            .take_for("qkd-m1d-key-002", "alice", "bob")
            .unwrap_err(),
        QkdProviderError::KeyUnavailable
    );
    assert_eq!(
        bob.take_for("qkd-m1d-key-002", "bob", "alice").unwrap_err(),
        QkdProviderError::KeyUnavailable
    );
    assert_eq!(
        alice.provision_fixture("qkd-m1d-key-002", "alice", "bob", [0x23; 32]),
        Err(QkdProviderError::DuplicateKeyId)
    );
    assert_eq!(
        bob.take_for("unknown-key", "bob", "alice").unwrap_err(),
        QkdProviderError::KeyUnavailable
    );
    assert!(!format!("{a:?}").contains("35, 35, 35")); // Secret excluded from Debug.
    assert!(format!("{a:?}").contains("[REDACTED]"));
}
