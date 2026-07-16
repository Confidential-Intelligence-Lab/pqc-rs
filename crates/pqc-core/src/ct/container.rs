//! Fixed-size secret containers and conditional assignment.

use core::fmt;

use super::{ct_assign_bytes, ct_select_bytes, CtMask8};

/// Fixed-size byte container intended for secret-bearing values.
///
/// The container deliberately exposes no ordinary conditional-selection API.
/// Updates should use [`conditional_assign`](Self::conditional_assign) or
/// [`conditional_swap`](Self::conditional_swap).
#[derive(Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct SecretBytes<const LENGTH: usize> {
    bytes: [u8; LENGTH],
}

impl<const LENGTH: usize> SecretBytes<LENGTH> {
    /// Construct a secret container from a fixed-size byte array.
    #[must_use]
    #[inline(always)]
    pub const fn new(bytes: [u8; LENGTH]) -> Self {
        Self { bytes }
    }

    /// Borrow the contained bytes.
    #[must_use]
    #[inline(always)]
    pub const fn as_bytes(&self) -> &[u8; LENGTH] {
        &self.bytes
    }

    /// Mutably borrow the contained bytes.
    ///
    /// Callers remain responsible for avoiding secret-dependent indexing.
    #[must_use]
    #[inline(always)]
    pub fn as_mut_bytes(&mut self) -> &mut [u8; LENGTH] {
        &mut self.bytes
    }

    /// Consume the container and return the contained bytes.
    #[must_use]
    #[inline(always)]
    pub const fn into_bytes(self) -> [u8; LENGTH] {
        self.bytes
    }

    /// Conditionally assign `source` when `mask` is all ones.
    #[inline(always)]
    pub fn conditional_assign(&mut self, mask: CtMask8, source: &Self) {
        ct_assign_bytes(mask, &mut self.bytes, &source.bytes);
    }

    /// Return a conditionally selected secret container.
    #[must_use]
    #[inline(always)]
    pub fn conditional_select(mask: CtMask8, when_true: &Self, when_false: &Self) -> Self {
        Self::new(ct_select_bytes(mask, &when_true.bytes, &when_false.bytes))
    }

    /// Conditionally swap two secret containers.
    #[inline(always)]
    pub fn conditional_swap(mask: CtMask8, left: &mut Self, right: &mut Self) {
        for (left_byte, right_byte) in left.bytes.iter_mut().zip(right.bytes.iter_mut()) {
            let difference = (*left_byte ^ *right_byte) & mask.raw();
            *left_byte ^= difference;
            *right_byte ^= difference;
        }
    }
}

impl<const LENGTH: usize> From<[u8; LENGTH]> for SecretBytes<LENGTH> {
    #[inline(always)]
    fn from(bytes: [u8; LENGTH]) -> Self {
        Self::new(bytes)
    }
}

impl<const LENGTH: usize> AsRef<[u8]> for SecretBytes<LENGTH> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const LENGTH: usize> fmt::Debug for SecretBytes<LENGTH> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("length", &LENGTH)
            .field("contents", &"<redacted>")
            .finish()
    }
}
