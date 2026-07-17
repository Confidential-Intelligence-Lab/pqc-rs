//! Constant-time utility primitives.
//!
//! Conditions are represented as canonical all-zero or all-one masks.
//! Secret masks must not be converted into Rust `bool` values inside
//! secret-bearing code paths.

mod compare;
mod container;
mod mask;
mod select;
mod typed;
mod zeroize;

pub use compare::{ct_eq_bytes, ct_eq_slices, ct_is_zero_bytes, ct_is_zero_slice};
pub use container::SecretBytes;
pub use mask::{
    ct_eq_u16, ct_eq_u32, ct_eq_u64, ct_eq_u8, ct_is_nonzero_u16, ct_is_nonzero_u32,
    ct_is_nonzero_u64, ct_is_nonzero_u8, ct_is_zero_u16, ct_is_zero_u32, ct_is_zero_u64,
    ct_is_zero_u8, CtMask16, CtMask32, CtMask64, CtMask8,
};
pub use select::{
    ct_assign_bytes, ct_select_bytes, ct_select_u16, ct_select_u32, ct_select_u64, ct_select_u8,
};
pub use typed::{ct_assign_u16_array, ct_assign_u32_array, ct_assign_u64_array};
pub use zeroize::{zeroize_bytes, zeroize_u16, zeroize_u32, zeroize_u64};
