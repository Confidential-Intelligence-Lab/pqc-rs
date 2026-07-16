//! Constant-time selection and conditional assignment.

use super::{CtMask16, CtMask32, CtMask64, CtMask8};

macro_rules! define_select {
    ($function:ident, $integer:ty, $mask:ty) => {
        #[doc = "Select `when_true` for an all-one mask and `when_false` otherwise."]
        #[must_use]
        #[inline(always)]
        pub const fn $function(mask: $mask, when_true: $integer, when_false: $integer) -> $integer {
            (mask.raw() & when_true) | (!mask.raw() & when_false)
        }
    };
}

define_select!(ct_select_u8, u8, CtMask8);
define_select!(ct_select_u16, u16, CtMask16);
define_select!(ct_select_u32, u32, CtMask32);
define_select!(ct_select_u64, u64, CtMask64);

/// Select one fixed-size byte array without secret-dependent branching.
#[must_use]
#[inline(always)]
pub fn ct_select_bytes<const LENGTH: usize>(
    mask: CtMask8,
    when_true: &[u8; LENGTH],
    when_false: &[u8; LENGTH],
) -> [u8; LENGTH] {
    let mut output = [0_u8; LENGTH];

    for ((slot, true_byte), false_byte) in output
        .iter_mut()
        .zip(when_true.iter())
        .zip(when_false.iter())
    {
        *slot = ct_select_u8(mask, *true_byte, *false_byte);
    }

    output
}

/// Conditionally assign a fixed-size byte array.
#[inline(always)]
pub fn ct_assign_bytes<const LENGTH: usize>(
    mask: CtMask8,
    destination: &mut [u8; LENGTH],
    source: &[u8; LENGTH],
) {
    for (destination_byte, source_byte) in destination.iter_mut().zip(source.iter()) {
        *destination_byte = ct_select_u8(mask, *source_byte, *destination_byte);
    }
}
