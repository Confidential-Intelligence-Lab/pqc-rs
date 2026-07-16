use pqc_core::ct::{
    ct_assign_u16_array, ct_assign_u32_array, ct_assign_u64_array, CtMask16, CtMask32, CtMask64,
    CtMask8, SecretBytes,
};

#[test]
fn secret_bytes_debug_output_is_redacted() {
    let secret = SecretBytes::<4>::new([1, 2, 3, 4]);
    let rendered = format!("{secret:?}");

    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains("[1, 2, 3, 4]"));
}

#[test]
fn secret_bytes_conditional_assignment_is_correct() {
    let source = SecretBytes::<32>::new([0xA5; 32]);
    let mut destination = SecretBytes::<32>::new([0x5A; 32]);

    destination.conditional_assign(CtMask8::FALSE, &source);
    assert_eq!(destination.as_bytes(), &[0x5A; 32]);

    destination.conditional_assign(CtMask8::TRUE, &source);
    assert_eq!(destination.as_bytes(), &[0xA5; 32]);
}

#[test]
fn secret_bytes_conditional_selection_is_correct() {
    let left = SecretBytes::<16>::new([0x11; 16]);
    let right = SecretBytes::<16>::new([0x22; 16]);

    assert_eq!(
        SecretBytes::conditional_select(CtMask8::TRUE, &left, &right),
        left,
    );
    assert_eq!(
        SecretBytes::conditional_select(CtMask8::FALSE, &left, &right),
        right,
    );
}

#[test]
fn secret_bytes_conditional_swap_is_correct() {
    let original_left = SecretBytes::<16>::new([0x11; 16]);
    let original_right = SecretBytes::<16>::new([0x22; 16]);

    let mut left = original_left.clone();
    let mut right = original_right.clone();

    SecretBytes::conditional_swap(CtMask8::FALSE, &mut left, &mut right);
    assert_eq!(left, original_left);
    assert_eq!(right, original_right);

    SecretBytes::conditional_swap(CtMask8::TRUE, &mut left, &mut right);
    assert_eq!(left, original_right);
    assert_eq!(right, original_left);
}

#[test]
fn typed_u16_assignment_is_correct() {
    let source = [0xAAAA_u16; 32];
    let mut destination = [0x5555_u16; 32];

    ct_assign_u16_array(CtMask16::FALSE, &mut destination, &source);
    assert_eq!(destination, [0x5555; 32]);

    ct_assign_u16_array(CtMask16::TRUE, &mut destination, &source);
    assert_eq!(destination, source);
}

#[test]
fn typed_u32_assignment_is_correct() {
    let source = [0xAAAA_AAAA_u32; 32];
    let mut destination = [0x5555_5555_u32; 32];

    ct_assign_u32_array(CtMask32::FALSE, &mut destination, &source);
    assert_eq!(destination, [0x5555_5555; 32]);

    ct_assign_u32_array(CtMask32::TRUE, &mut destination, &source);
    assert_eq!(destination, source);
}

#[test]
fn typed_u64_assignment_is_correct() {
    let source = [0xAAAA_AAAA_AAAA_AAAA_u64; 32];
    let mut destination = [0x5555_5555_5555_5555_u64; 32];

    ct_assign_u64_array(CtMask64::FALSE, &mut destination, &source);
    assert_eq!(destination, [0x5555_5555_5555_5555; 32]);

    ct_assign_u64_array(CtMask64::TRUE, &mut destination, &source);
    assert_eq!(destination, source);
}

#[test]
fn zero_length_secret_containers_are_supported() {
    let mut left = SecretBytes::<0>::new([]);
    let mut right = SecretBytes::<0>::new([]);

    left.conditional_assign(CtMask8::TRUE, &right);
    SecretBytes::conditional_swap(CtMask8::TRUE, &mut left, &mut right);

    assert_eq!(left.as_bytes(), &[]);
    assert_eq!(right.as_bytes(), &[]);
}
