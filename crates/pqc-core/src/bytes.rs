//! Typed byte containers for PQC objects.

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "alloc")]
use crate::codec::Encode;
use crate::codec::Decode;
use crate::error::{PqcError, PqcResult};

/// Public-key bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicKeyBytes<const N: usize>(pub [u8; N]);

/// Secret-key bytes. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKeyBytes<const N: usize>(pub [u8; N]);

/// Ciphertext bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct CiphertextBytes<const N: usize>(pub [u8; N]);

/// Shared-secret bytes. Zeroized on drop and compared in constant time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecretBytes<const N: usize>(pub [u8; N]);

/// Signature bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct SignatureBytes<const N: usize>(pub [u8; N]);

/// Signature or protocol context bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct ContextBytes<const N: usize>(pub [u8; N]);

macro_rules! impl_public_like {
    ($name:ident) => {
        impl<const N: usize> $name<N> {
            /// Construct from an exact-size array.
            pub const fn new(bytes: [u8; N]) -> Self {
                Self(bytes)
            }

            /// Borrow the canonical bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl<const N: usize> Decode for $name<N> {
            fn decode(input: &[u8]) -> PqcResult<Self> {
                if input.len() != N {
                    return Err(PqcError::InvalidLength {
                        expected: N,
                        actual: input.len(),
                    });
                }
                let mut out = [0u8; N];
                out.copy_from_slice(input);
                Ok(Self(out))
            }
        }

        #[cfg(feature = "alloc")]
        impl<const N: usize> Encode for $name<N> {
            fn encode(&self) -> alloc::vec::Vec<u8> {
                self.0.to_vec()
            }
        }

        impl<const N: usize> fmt::Debug for $name<N> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}<{} bytes>", stringify!($name), N)
            }
        }
    };
}

macro_rules! impl_secret_like {
    ($name:ident) => {
        impl<const N: usize> $name<N> {
            /// Construct from an exact-size array.
            pub const fn new(bytes: [u8; N]) -> Self {
                Self(bytes)
            }

            /// Borrow the canonical bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl<const N: usize> Decode for $name<N> {
            fn decode(input: &[u8]) -> PqcResult<Self> {
                if input.len() != N {
                    return Err(PqcError::InvalidLength {
                        expected: N,
                        actual: input.len(),
                    });
                }
                let mut out = [0u8; N];
                out.copy_from_slice(input);
                Ok(Self(out))
            }
        }

        #[cfg(feature = "alloc")]
        impl<const N: usize> Encode for $name<N> {
            fn encode(&self) -> alloc::vec::Vec<u8> {
                self.0.to_vec()
            }
        }

        impl<const N: usize> ConstantTimeEq for $name<N> {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl<const N: usize> fmt::Debug for $name<N> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}<{} bytes, redacted>", stringify!($name), N)
            }
        }
    };
}

impl_public_like!(PublicKeyBytes);
impl_public_like!(CiphertextBytes);
impl_public_like!(SignatureBytes);
impl_public_like!(ContextBytes);
impl_secret_like!(SecretKeyBytes);
impl_secret_like!(SharedSecretBytes);
