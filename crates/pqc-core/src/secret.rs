//! Secret-bearing byte containers.
//!
//! These wrappers reduce accidental exposure by omitting `Debug`, zeroizing
//! their contents on drop, and exposing only explicit byte accessors.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed-size secret byte array.
///
/// This type intentionally does not implement `Debug`, `Display`, `Serialize`,
/// or `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    /// Construct a secret container from a fixed-size byte array.
    pub const fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Borrow the contained secret bytes.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Mutably borrow the contained secret bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    /// Consume the wrapper and return a copy of the secret bytes.
    ///
    /// The wrapper's internal storage is still zeroized when dropped.
    pub fn expose_copy(&self) -> [u8; N] {
        self.bytes
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Heap-allocated secret bytes.
///
/// This type intentionally does not implement `Debug`, `Display`, `Serialize`,
/// or `Clone`.
#[cfg(feature = "alloc")]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretVec {
    bytes: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl SecretVec {
    /// Construct a heap-allocated secret container.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the contained secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Mutably borrow the contained secret bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

#[cfg(feature = "alloc")]
impl AsRef<[u8]> for SecretVec {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_secret_round_trip() {
        let secret = SecretBytes::new([7u8; 32]);
        assert_eq!(secret.as_bytes(), &[7u8; 32]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn heap_secret_round_trip() {
        let secret = SecretVec::new(alloc::vec![3u8; 48]);
        assert_eq!(secret.as_bytes(), &[3u8; 48]);
    }
}
