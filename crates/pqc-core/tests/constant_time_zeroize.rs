use pqc_core::ct::{zeroize_bytes, zeroize_u16, zeroize_u32, zeroize_u64, SecretBytes};

#[test]
fn explicit_byte_zeroization_clears_every_byte() {
    let mut value = [0xA5_u8; 256];
    zeroize_bytes(&mut value);
    assert_eq!(value, [0_u8; 256]);
}

#[test]
fn explicit_integer_zeroization_clears_every_element() {
    let mut words16 = [u16::MAX; 64];
    let mut words32 = [u32::MAX; 64];
    let mut words64 = [u64::MAX; 64];

    zeroize_u16(&mut words16);
    zeroize_u32(&mut words32);
    zeroize_u64(&mut words64);

    assert_eq!(words16, [0_u16; 64]);
    assert_eq!(words32, [0_u32; 64]);
    assert_eq!(words64, [0_u64; 64]);
}

#[test]
fn zero_length_values_are_supported() {
    let mut bytes: [u8; 0] = [];
    let mut words16: [u16; 0] = [];
    let mut words32: [u32; 0] = [];
    let mut words64: [u64; 0] = [];

    zeroize_bytes(&mut bytes);
    zeroize_u16(&mut words16);
    zeroize_u32(&mut words32);
    zeroize_u64(&mut words64);
}

#[test]
fn secret_bytes_can_be_cleared_before_drop() {
    let mut secret = SecretBytes::<32>::new([0x5A; 32]);
    zeroize_bytes(secret.as_mut_bytes());
    assert_eq!(secret.as_bytes(), &[0_u8; 32]);
}
