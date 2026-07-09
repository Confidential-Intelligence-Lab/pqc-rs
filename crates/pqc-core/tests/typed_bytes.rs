use pqc_core::{Decode, PublicKeyBytes, SharedSecretBytes};
use subtle::ConstantTimeEq;

#[test]
fn public_key_decode_checks_length() {
    let pk = PublicKeyBytes::<3>::decode(&[1, 2, 3]).unwrap();
    assert_eq!(pk.as_bytes(), &[1, 2, 3]);
    assert!(PublicKeyBytes::<3>::decode(&[1, 2]).is_err());
}

#[test]
fn shared_secret_constant_time_eq_works() {
    let a = SharedSecretBytes::<2>::new([1, 2]);
    let b = SharedSecretBytes::<2>::new([1, 2]);
    let c = SharedSecretBytes::<2>::new([2, 1]);
    assert_eq!(a.ct_eq(&b).unwrap_u8(), 1);
    assert_eq!(a.ct_eq(&c).unwrap_u8(), 0);
}
