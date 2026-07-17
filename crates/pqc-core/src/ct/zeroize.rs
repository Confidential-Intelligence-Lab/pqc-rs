//! Explicit zeroization primitives for secret-bearing memory.

use zeroize::Zeroize;

/// Overwrite a mutable byte slice with zeros.
#[inline(never)]
pub fn zeroize_bytes(value: &mut [u8]) {
    value.zeroize();
}

/// Overwrite a mutable `u16` slice with zeros.
#[inline(never)]
pub fn zeroize_u16(value: &mut [u16]) {
    value.zeroize();
}

/// Overwrite a mutable `u32` slice with zeros.
#[inline(never)]
pub fn zeroize_u32(value: &mut [u32]) {
    value.zeroize();
}

/// Overwrite a mutable `u64` slice with zeros.
#[inline(never)]
pub fn zeroize_u64(value: &mut [u64]) {
    value.zeroize();
}
