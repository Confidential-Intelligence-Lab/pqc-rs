//! Minimal encoding and decoding traits.

use crate::error::PqcResult;

/// Types that can be encoded into an owned byte vector when `alloc` is enabled.
#[cfg(feature = "alloc")]
pub trait Encode {
    /// Return the canonical byte encoding of `self`.
    fn encode(&self) -> alloc::vec::Vec<u8>;
}

/// Types that can be decoded from canonical bytes.
pub trait Decode: Sized {
    /// Decode an object from canonical bytes.
    fn decode(input: &[u8]) -> PqcResult<Self>;
}
