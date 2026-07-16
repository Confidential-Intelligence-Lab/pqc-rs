use pqc_core::ct::{
    ct_assign_bytes, ct_eq_u16, ct_eq_u32, ct_eq_u64, ct_eq_u8, ct_is_nonzero_u16,
    ct_is_nonzero_u32, ct_is_nonzero_u64, ct_is_nonzero_u8, ct_is_zero_u16, ct_is_zero_u32,
    ct_is_zero_u64, ct_is_zero_u8, ct_select_bytes, ct_select_u16, ct_select_u32, ct_select_u64,
    ct_select_u8, CtMask16, CtMask32, CtMask64, CtMask8,
};

#[test]
fn masks_are_canonical() {
    for mask in [CtMask8::FALSE, CtMask8::TRUE] {
        assert!(mask.is_canonical());
    }
    for mask in [CtMask16::FALSE, CtMask16::TRUE] {
        assert!(mask.is_canonical());
    }
    for mask in [CtMask32::FALSE, CtMask32::TRUE] {
        assert!(mask.is_canonical());
    }
    for mask in [CtMask64::FALSE, CtMask64::TRUE] {
        assert!(mask.is_canonical());
    }
}

#[test]
fn operator_traits_preserve_canonical_masks() {
    assert_eq!(!CtMask8::TRUE, CtMask8::FALSE);
    assert_eq!(CtMask8::TRUE & CtMask8::FALSE, CtMask8::FALSE);
    assert_eq!(CtMask8::TRUE | CtMask8::FALSE, CtMask8::TRUE);
    assert_eq!(CtMask8::TRUE ^ CtMask8::TRUE, CtMask8::FALSE);
}

#[test]
fn u8_predicates_are_exhaustive() {
    for value in u8::MIN..=u8::MAX {
        assert_eq!(
            ct_is_zero_u8(value).raw(),
            if value == 0 { u8::MAX } else { 0 }
        );
        assert_eq!(
            ct_is_nonzero_u8(value).raw(),
            if value != 0 { u8::MAX } else { 0 }
        );

        for other in u8::MIN..=u8::MAX {
            assert_eq!(
                ct_eq_u8(value, other).raw(),
                if value == other { u8::MAX } else { 0 },
            );
        }
    }
}

#[test]
fn wider_predicates_cover_boundaries() {
    assert_eq!(ct_is_zero_u16(0).raw(), u16::MAX);
    assert_eq!(ct_is_nonzero_u16(u16::MAX).raw(), u16::MAX);
    assert_eq!(ct_eq_u16(7, 7).raw(), u16::MAX);
    assert_eq!(ct_eq_u16(7, 8).raw(), 0);

    assert_eq!(ct_is_zero_u32(0).raw(), u32::MAX);
    assert_eq!(ct_is_nonzero_u32(u32::MAX).raw(), u32::MAX);
    assert_eq!(ct_eq_u32(7, 7).raw(), u32::MAX);
    assert_eq!(ct_eq_u32(7, 8).raw(), 0);

    assert_eq!(ct_is_zero_u64(0).raw(), u64::MAX);
    assert_eq!(ct_is_nonzero_u64(u64::MAX).raw(), u64::MAX);
    assert_eq!(ct_eq_u64(7, 7).raw(), u64::MAX);
    assert_eq!(ct_eq_u64(7, 8).raw(), 0);
}

#[test]
fn scalar_selection_is_correct() {
    assert_eq!(ct_select_u8(CtMask8::TRUE, 1, 2), 1);
    assert_eq!(ct_select_u8(CtMask8::FALSE, 1, 2), 2);
    assert_eq!(ct_select_u16(CtMask16::TRUE, 1, 2), 1);
    assert_eq!(ct_select_u16(CtMask16::FALSE, 1, 2), 2);
    assert_eq!(ct_select_u32(CtMask32::TRUE, 1, 2), 1);
    assert_eq!(ct_select_u32(CtMask32::FALSE, 1, 2), 2);
    assert_eq!(ct_select_u64(CtMask64::TRUE, 1, 2), 1);
    assert_eq!(ct_select_u64(CtMask64::FALSE, 1, 2), 2);
}

#[test]
fn byte_array_selection_and_assignment_are_correct() {
    let left = [0xAA_u8; 32];
    let right = [0x55_u8; 32];

    assert_eq!(ct_select_bytes(CtMask8::TRUE, &left, &right), left);
    assert_eq!(ct_select_bytes(CtMask8::FALSE, &left, &right), right);

    let mut destination = right;
    ct_assign_bytes(CtMask8::TRUE, &mut destination, &left);
    assert_eq!(destination, left);

    ct_assign_bytes(CtMask8::FALSE, &mut destination, &right);
    assert_eq!(destination, left);
}
