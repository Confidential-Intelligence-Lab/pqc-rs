use pqc_hpke::identifiers::{AeadId, HpkeSuiteId, KdfId, KemId};
use pqc_hpke::kdf::KdfAlgorithm;
use pqc_hpke::key_schedule::{key_schedule, AeadParameters, HpkeMode, KeyScheduleInputs};

#[test]
fn suite_and_key_schedule_are_stable() {
    let suite = HpkeSuiteId {
        kem_id: KemId(0x0020),
        kdf_id: KdfId::HKDF_SHA256,
        aead_id: AeadId::AES_128_GCM,
    };
    let shared_secret: Vec<u8> = (0u8..32).collect();

    let output = key_schedule(
        suite,
        KdfAlgorithm::HkdfSha256,
        AeadParameters::for_id(AeadId::AES_128_GCM).unwrap(),
        KeyScheduleInputs {
            mode: HpkeMode::Base,
            shared_secret: &shared_secret,
            info: b"stage7b1",
            psk: b"",
            psk_id: b"",
        },
    )
    .unwrap();

    assert_eq!(output.key.as_bytes().len(), 16);
    assert_eq!(output.base_nonce.len(), 12);
    assert_eq!(output.exporter_secret.as_bytes().len(), 32);
    assert_eq!(output.sequence_number, 0);
}
