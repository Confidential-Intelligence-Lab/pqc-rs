use pqc_core::Decode;
use pqc_ml_kem::{
    MlKem1024, MlKem1024PublicKey, MlKem512, MlKem512PublicKey, MlKem768, MlKem768PublicKey,
    ML_KEM_1024_PUBLIC_KEY_BYTES, ML_KEM_512_PUBLIC_KEY_BYTES, ML_KEM_768_PUBLIC_KEY_BYTES,
};
use rand_core::OsRng;
use subtle::ConstantTimeEq;

#[test]
fn public_key_decoding_rejects_wrong_lengths() {
    assert!(MlKem512PublicKey::decode(&[0u8; ML_KEM_512_PUBLIC_KEY_BYTES]).is_ok());
    assert!(MlKem512PublicKey::decode(&[0u8; ML_KEM_512_PUBLIC_KEY_BYTES - 1]).is_err());

    assert!(MlKem768PublicKey::decode(&[0u8; ML_KEM_768_PUBLIC_KEY_BYTES]).is_ok());
    assert!(MlKem768PublicKey::decode(&[0u8; ML_KEM_768_PUBLIC_KEY_BYTES - 1]).is_err());

    assert!(MlKem1024PublicKey::decode(&[0u8; ML_KEM_1024_PUBLIC_KEY_BYTES]).is_ok());
    assert!(MlKem1024PublicKey::decode(&[0u8; ML_KEM_1024_PUBLIC_KEY_BYTES - 1]).is_err());
}

#[test]
fn all_parameter_sets_round_trip() {
    let mut rng = OsRng;

    let (pk512, sk512) = MlKem512::keygen(&mut rng).unwrap();
    let (ct512, ss512_a) = MlKem512::encaps(&pk512, &mut rng).unwrap();
    let ss512_b = MlKem512::decaps(&sk512, &ct512).unwrap();
    assert_eq!(ss512_a.ct_eq(&ss512_b).unwrap_u8(), 1);

    let (pk768, sk768) = MlKem768::keygen(&mut rng).unwrap();
    let (ct768, ss768_a) = MlKem768::encaps(&pk768, &mut rng).unwrap();
    let ss768_b = MlKem768::decaps(&sk768, &ct768).unwrap();
    assert_eq!(ss768_a.ct_eq(&ss768_b).unwrap_u8(), 1);

    let (pk1024, sk1024) = MlKem1024::keygen(&mut rng).unwrap();
    let (ct1024, ss1024_a) = MlKem1024::encaps(&pk1024, &mut rng).unwrap();
    let ss1024_b = MlKem1024::decaps(&sk1024, &ct1024).unwrap();
    assert_eq!(ss1024_a.ct_eq(&ss1024_b).unwrap_u8(), 1);
}
