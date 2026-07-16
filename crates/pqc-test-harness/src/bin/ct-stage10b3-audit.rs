//! Audit wrapper for Stage 10B-3 typed secret assignment.

use std::hint::black_box;

use pqc_core::ct::{ct_assign_u32_array, CtMask32, CtMask8, SecretBytes};

#[inline(never)]
fn audit_secret_assign(mask: CtMask8, destination: &mut SecretBytes<32>, source: &SecretBytes<32>) {
    destination.conditional_assign(black_box(mask), black_box(source));
}

#[inline(never)]
fn audit_secret_swap(mask: CtMask8, left: &mut SecretBytes<32>, right: &mut SecretBytes<32>) {
    SecretBytes::conditional_swap(black_box(mask), black_box(left), black_box(right));
}

#[inline(never)]
fn audit_typed_assign(mask: CtMask32, destination: &mut [u32; 32], source: &[u32; 32]) {
    ct_assign_u32_array(black_box(mask), black_box(destination), black_box(source));
}

fn main() {
    let source = SecretBytes::new([0xA5; 32]);
    let mut destination = SecretBytes::new([0x5A; 32]);
    audit_secret_assign(CtMask8::TRUE, &mut destination, &source);

    let mut left = SecretBytes::new([0x11; 32]);
    let mut right = SecretBytes::new([0x22; 32]);
    audit_secret_swap(CtMask8::FALSE, &mut left, &mut right);

    let source_words = [0xAAAA_AAAA_u32; 32];
    let mut destination_words = [0x5555_5555_u32; 32];
    audit_typed_assign(CtMask32::TRUE, &mut destination_words, &source_words);

    black_box(destination);
    black_box(left);
    black_box(right);
    black_box(destination_words);
}
