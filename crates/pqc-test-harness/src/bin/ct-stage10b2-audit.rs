use pqc_core::ct::{ct_eq_bytes, ct_eq_slices, ct_is_zero_bytes, ct_is_zero_slice, CtMask8};
use std::hint::black_box;
#[inline(never)]
fn audit_eq_32(left: &[u8; 32], right: &[u8; 32]) -> CtMask8 {
    ct_eq_bytes(black_box(left), black_box(right))
}
#[inline(never)]
fn audit_zero_32(value: &[u8; 32]) -> CtMask8 {
    ct_is_zero_bytes(black_box(value))
}
#[inline(never)]
fn audit_eq_slice(left: &[u8], right: &[u8]) -> CtMask8 {
    ct_eq_slices(black_box(left), black_box(right))
}
#[inline(never)]
fn audit_zero_slice(value: &[u8]) -> CtMask8 {
    ct_is_zero_slice(black_box(value))
}
fn main() {
    let left = [0xA5_u8; 32];
    let mut right = left;
    right[31] ^= 1;
    black_box(audit_eq_32(&left, &right));
    black_box(audit_zero_32(&left));
    black_box(audit_eq_slice(&left, &right));
    black_box(audit_zero_slice(&left));
}
