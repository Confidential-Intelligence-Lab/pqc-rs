use pqc_core::Decode;
use pqc_ml_kem::conformance::{parameter_set_status, ConformanceLevel, COMPONENT_STATUS};
use pqc_ml_kem::{
    MlKem1024PublicKey, MlKem512PublicKey, MlKem768PublicKey, MlKemParameterSet,
    ML_KEM_1024_PUBLIC_KEY_BYTES, ML_KEM_512_PUBLIC_KEY_BYTES, ML_KEM_768_PUBLIC_KEY_BYTES,
};

#[test]
fn repository_does_not_claim_fips203_conformance() {
    for parameter_set in [
        MlKemParameterSet::MlKem512,
        MlKemParameterSet::MlKem768,
        MlKemParameterSet::MlKem1024,
    ] {
        let status = parameter_set_status(parameter_set);
        assert!(!status.fips203_conformant);
        assert!(!status.official_kats_passed);
    }
}

#[test]
fn only_keygen_is_marked_kat_validated() {
    let validated: Vec<_> = COMPONENT_STATUS
        .iter()
        .filter(|entry| entry.level == ConformanceLevel::KatValidated)
        .map(|entry| entry.id)
        .collect();

    assert_eq!(validated, vec!["kpke-keygen"]);
}

#[test]
fn parameter_set_mismatched_public_key_lengths_are_rejected() {
    let key_512 = [0u8; ML_KEM_512_PUBLIC_KEY_BYTES];
    let key_768 = [0u8; ML_KEM_768_PUBLIC_KEY_BYTES];
    let key_1024 = [0u8; ML_KEM_1024_PUBLIC_KEY_BYTES];

    assert!(MlKem512PublicKey::decode(&key_512).is_ok());
    assert!(MlKem768PublicKey::decode(&key_768).is_ok());
    assert!(MlKem1024PublicKey::decode(&key_1024).is_ok());

    assert!(MlKem512PublicKey::decode(&key_768).is_err());
    assert!(MlKem768PublicKey::decode(&key_1024).is_err());
    assert!(MlKem1024PublicKey::decode(&key_512).is_err());
}
