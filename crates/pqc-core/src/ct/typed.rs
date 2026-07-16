//! Constant-time conditional assignment for typed integer arrays.

use super::{ct_select_u16, ct_select_u32, ct_select_u64, CtMask16, CtMask32, CtMask64};

/// Conditionally assign a fixed-size `u16` array.
#[inline(always)]
pub fn ct_assign_u16_array<const LENGTH: usize>(
    mask: CtMask16,
    destination: &mut [u16; LENGTH],
    source: &[u16; LENGTH],
) {
    for (destination_value, source_value) in destination.iter_mut().zip(source.iter()) {
        *destination_value = ct_select_u16(mask, *source_value, *destination_value);
    }
}

/// Conditionally assign a fixed-size `u32` array.
#[inline(always)]
pub fn ct_assign_u32_array<const LENGTH: usize>(
    mask: CtMask32,
    destination: &mut [u32; LENGTH],
    source: &[u32; LENGTH],
) {
    for (destination_value, source_value) in destination.iter_mut().zip(source.iter()) {
        *destination_value = ct_select_u32(mask, *source_value, *destination_value);
    }
}

/// Conditionally assign a fixed-size `u64` array.
#[inline(always)]
pub fn ct_assign_u64_array<const LENGTH: usize>(
    mask: CtMask64,
    destination: &mut [u64; LENGTH],
    source: &[u64; LENGTH],
) {
    for (destination_value, source_value) in destination.iter_mut().zip(source.iter()) {
        *destination_value = ct_select_u64(mask, *source_value, *destination_value);
    }
}
