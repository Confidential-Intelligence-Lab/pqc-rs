use std::hint::black_box;

use pqc_core::ct::{zeroize_bytes, zeroize_u32, SecretBytes};

#[inline(never)]
fn audit_zeroize_bytes(value: &mut [u8; 64]) {
    zeroize_bytes(black_box(value));
}

#[inline(never)]
fn audit_zeroize_words(value: &mut [u32; 64]) {
    zeroize_u32(black_box(value));
}

#[inline(never)]
fn audit_secret_drop() {
    let secret = SecretBytes::<64>::new([0xA5; 64]);
    black_box(&secret);
    drop(secret);
}

fn main() {
    let mut bytes = [0x5A_u8; 64];
    let mut words = [0xA5A5_A5A5_u32; 64];

    audit_zeroize_bytes(&mut bytes);
    audit_zeroize_words(&mut words);
    audit_secret_drop();

    black_box(bytes);
    black_box(words);
}
