//! Constant-time masks and equality predicates.

use core::ops::{BitAnd, BitOr, BitXor, Not};

macro_rules! define_mask {
    (
        $name:ident,
        $integer:ty,
        $bits:expr,
        $is_zero:ident,
        $is_nonzero:ident,
        $eq:ident
    ) => {
        #[doc = "Canonical all-zero or all-one constant-time mask."]
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
        #[repr(transparent)]
        pub struct $name($integer);

        impl $name {
            #[doc = "All-zero mask representing false."]
            pub const FALSE: Self = Self(0);

            #[doc = "All-one mask representing true."]
            pub const TRUE: Self = Self(<$integer>::MAX);

            #[doc = "Construct a mask from a canonical raw value."]
            #[must_use]
            #[inline(always)]
            pub const fn from_raw(value: $integer) -> Self {
                debug_assert!(
                    value == 0 || value == <$integer>::MAX,
                    "constant-time mask must be all-zero or all-one",
                );
                Self(value)
            }

            #[doc = "Return the canonical raw all-zero or all-one value."]
            #[must_use]
            #[inline(always)]
            pub const fn raw(self) -> $integer {
                self.0
            }

            #[doc = "Return true when the mask is canonical."]
            #[must_use]
            #[inline(always)]
            pub const fn is_canonical(self) -> bool {
                self.0 == 0 || self.0 == <$integer>::MAX
            }
        }

        impl Not for $name {
            type Output = Self;

            #[doc = "Invert the mask."]
            #[inline(always)]
            fn not(self) -> Self::Output {
                Self(!self.0)
            }
        }

        impl BitAnd for $name {
            type Output = Self;

            #[doc = "Bitwise AND two canonical masks."]
            #[inline(always)]
            fn bitand(self, rhs: Self) -> Self::Output {
                Self(self.0 & rhs.0)
            }
        }

        impl BitOr for $name {
            type Output = Self;

            #[doc = "Bitwise OR two canonical masks."]
            #[inline(always)]
            fn bitor(self, rhs: Self) -> Self::Output {
                Self(self.0 | rhs.0)
            }
        }

        impl BitXor for $name {
            type Output = Self;

            #[doc = "Bitwise XOR two canonical masks."]
            #[inline(always)]
            fn bitxor(self, rhs: Self) -> Self::Output {
                Self(self.0 ^ rhs.0)
            }
        }

        #[doc = "Return an all-one mask when the input equals zero."]
        #[must_use]
        #[inline(always)]
        pub const fn $is_zero(value: $integer) -> $name {
            let nonzero = value | value.wrapping_neg();
            let bit = nonzero >> ($bits - 1);
            $name::from_raw(bit.wrapping_sub(1))
        }

        #[doc = "Return an all-one mask when the input is nonzero."]
        #[must_use]
        #[inline(always)]
        pub const fn $is_nonzero(value: $integer) -> $name {
            $name::from_raw(!$is_zero(value).raw())
        }

        #[doc = "Return an all-one mask when both inputs are equal."]
        #[must_use]
        #[inline(always)]
        pub const fn $eq(left: $integer, right: $integer) -> $name {
            $is_zero(left ^ right)
        }
    };
}

define_mask!(CtMask8, u8, 8, ct_is_zero_u8, ct_is_nonzero_u8, ct_eq_u8);
define_mask!(
    CtMask16,
    u16,
    16,
    ct_is_zero_u16,
    ct_is_nonzero_u16,
    ct_eq_u16
);
define_mask!(
    CtMask32,
    u32,
    32,
    ct_is_zero_u32,
    ct_is_nonzero_u32,
    ct_eq_u32
);
define_mask!(
    CtMask64,
    u64,
    64,
    ct_is_zero_u64,
    ct_is_nonzero_u64,
    ct_eq_u64
);
