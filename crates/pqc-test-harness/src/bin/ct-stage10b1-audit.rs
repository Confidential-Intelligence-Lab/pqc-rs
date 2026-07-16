use std::hint::black_box;

use pqc_core::ct::{
    ct_assign_bytes, ct_eq_u32, ct_is_nonzero_u32, ct_is_zero_u32, ct_select_bytes, ct_select_u32,
    CtMask8,
};

#[inline(never)]
fn audit_scalar_masks(value: u32, other: u32) -> u32 {
    let zero = ct_is_zero_u32(black_box(value));
    let nonzero = ct_is_nonzero_u32(black_box(value));
    let equal = ct_eq_u32(black_box(value), black_box(other));
    ct_select_u32(equal, zero.raw(), nonzero.raw())
}

#[inline(never)]
fn audit_array_selection(mask: CtMask8) -> [u8; 32] {
    ct_select_bytes(black_box(mask), &[0xAA; 32], &[0x55; 32])
}

#[inline(never)]
fn audit_array_assignment(mask: CtMask8) -> [u8; 32] {
    let source = [0xA5_u8; 32];
    let mut destination = [0x5A_u8; 32];
    ct_assign_bytes(black_box(mask), &mut destination, &source);
    destination
}

fn main() {
    black_box(audit_scalar_masks(7, 7));
    black_box(audit_array_selection(CtMask8::TRUE));
    black_box(audit_array_assignment(CtMask8::FALSE));
}
