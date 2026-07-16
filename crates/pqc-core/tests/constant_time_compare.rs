use pqc_core::ct::{ct_eq_bytes, ct_eq_slices, ct_is_zero_bytes, ct_is_zero_slice, CtMask8};

#[test]
fn empty_values_compare_equal_and_are_zero() {
    assert_eq!(ct_eq_bytes(&[], &[]), CtMask8::TRUE);
    assert_eq!(ct_is_zero_bytes(&[]), CtMask8::TRUE);
    assert_eq!(ct_eq_slices(&[], &[]), CtMask8::TRUE);
    assert_eq!(ct_is_zero_slice(&[]), CtMask8::TRUE);
}

#[test]
fn fixed_array_comparison_detects_every_mismatch_position() {
    const LENGTH: usize = 64;
    let reference = [0xA5_u8; LENGTH];
    assert_eq!(ct_eq_bytes(&reference, &reference), CtMask8::TRUE);
    for position in 0..LENGTH {
        let mut candidate = reference;
        candidate[position] ^= 1;
        assert_eq!(ct_eq_bytes(&reference, &candidate), CtMask8::FALSE);
    }
}

#[test]
fn fixed_array_zero_test_detects_every_nonzero_position() {
    const LENGTH: usize = 64;
    let zero = [0_u8; LENGTH];
    assert_eq!(ct_is_zero_bytes(&zero), CtMask8::TRUE);
    for position in 0..LENGTH {
        let mut candidate = zero;
        candidate[position] = 1;
        assert_eq!(ct_is_zero_bytes(&candidate), CtMask8::FALSE);
    }
}

#[test]
fn slice_comparison_treats_length_as_public() {
    assert_eq!(ct_eq_slices(&[1, 2], &[1, 2]), CtMask8::TRUE);
    assert_eq!(ct_eq_slices(&[1, 2], &[1, 3]), CtMask8::FALSE);
    assert_eq!(ct_eq_slices(&[1, 2], &[1, 2, 3]), CtMask8::FALSE);
}

#[test]
fn large_arrays_are_supported() {
    let left = [0x3C_u8; 4096];
    let mut right = left;
    assert_eq!(ct_eq_bytes(&left, &right), CtMask8::TRUE);
    right[2048] ^= 1;
    assert_eq!(ct_eq_bytes(&left, &right), CtMask8::FALSE);
    assert_eq!(ct_is_zero_bytes(&[0_u8; 4096]), CtMask8::TRUE);
}
