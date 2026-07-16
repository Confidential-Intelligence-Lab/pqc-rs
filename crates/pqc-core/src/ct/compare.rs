//! Constant-time byte comparison and validation masks.

use super::{ct_is_zero_u8, CtMask8};

/// Compare two fixed-size byte arrays without early exit.
#[must_use]
#[inline(always)]
pub fn ct_eq_bytes<const LENGTH: usize>(left: &[u8; LENGTH], right: &[u8; LENGTH]) -> CtMask8 {
    let mut difference = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        difference |= *left_byte ^ *right_byte;
    }
    ct_is_zero_u8(difference)
}

/// Test whether every byte in a fixed-size array equals zero.
#[must_use]
#[inline(always)]
pub fn ct_is_zero_bytes<const LENGTH: usize>(value: &[u8; LENGTH]) -> CtMask8 {
    let mut aggregate = 0_u8;
    for byte in value {
        aggregate |= *byte;
    }
    ct_is_zero_u8(aggregate)
}

/// Compare two byte slices without early exit when public lengths match.
#[must_use]
#[inline(always)]
pub fn ct_eq_slices(left: &[u8], right: &[u8]) -> CtMask8 {
    if left.len() != right.len() {
        return CtMask8::FALSE;
    }
    let mut difference = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        difference |= *left_byte ^ *right_byte;
    }
    ct_is_zero_u8(difference)
}

/// Test whether every byte in a slice equals zero.
#[must_use]
#[inline(always)]
pub fn ct_is_zero_slice(value: &[u8]) -> CtMask8 {
    let mut aggregate = 0_u8;
    for byte in value {
        aggregate |= *byte;
    }
    ct_is_zero_u8(aggregate)
}
