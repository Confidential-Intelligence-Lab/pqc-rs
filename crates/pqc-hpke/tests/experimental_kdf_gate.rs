use pqc_hpke::{supported_kdfs, AeadId, HpkeSuite, KdfId, MlKemHpke};

#[test]
fn standardized_suite_enumeration_is_unchanged() {
    assert_eq!(
        supported_kdfs(),
        [KdfId::HKDF_SHA256, KdfId::HKDF_SHA384, KdfId::HKDF_SHA512,]
    );
}

#[test]
fn experimental_kdf_requires_explicit_feature() {
    let result = HpkeSuite::new(MlKemHpke::MlKem768, KdfId(0xff01), AeadId::AES_256_GCM);

    #[cfg(feature = "experimental-hkdf-sha3")]
    assert!(result.is_ok());

    #[cfg(not(feature = "experimental-hkdf-sha3"))]
    assert_eq!(result, Err(pqc_hpke::HpkeError::UnsupportedKdf));
}
