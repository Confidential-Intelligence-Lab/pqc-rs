//! Fixed-size polynomial vectors for HAETAE 1.2.0.

use crate::decompose::{decompose_hint, decompose_vk};
use crate::montgomery::{montgomery_reduce, MONT, MONT_SQUARED};
use crate::params::ParameterSet;
use crate::poly::Poly;
use crate::sampling::{uniform, uniform_eta};

/// A fixed-size vector of HAETAE polynomials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolyVec<const LEN: usize> {
    /// Polynomial components.
    pub vec: [Poly; LEN],
}

impl<const LEN: usize> PolyVec<LEN> {
    /// Construct a vector from its polynomial components.
    pub const fn new(vec: [Poly; LEN]) -> Self {
        Self { vec }
    }

    /// Number of polynomial components.
    pub const fn len(&self) -> usize {
        LEN
    }

    /// Whether this vector has no components.
    pub const fn is_empty(&self) -> bool {
        LEN == 0
    }
}

impl<const LEN: usize> Default for PolyVec<LEN> {
    fn default() -> Self {
        Self {
            vec: std::array::from_fn(|_| Poly::default()),
        }
    }
}

/// K-dimensional polynomial vector.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolyVecK<const K: usize>(pub PolyVec<K>);

/// L-dimensional polynomial vector.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolyVecL<const L: usize>(pub PolyVec<L>);

/// M-dimensional polynomial vector.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolyVecM<const M: usize>(pub PolyVec<M>);

// HAETAE_10K_7D_3B_VECTOR_ZEROIZE
impl<const LEN: usize> zeroize::Zeroize for PolyVec<LEN> {
    fn zeroize(&mut self) {
        for poly in &mut self.vec {
            poly.zeroize();
        }
    }
}

impl<const K: usize> zeroize::Zeroize for PolyVecK<K> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const M: usize> zeroize::Zeroize for PolyVecM<M> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// HAETAE_10K_7D_4B_2_POLYVECL_ZEROIZE
impl<const L: usize> zeroize::Zeroize for PolyVecL<L> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

macro_rules! impl_vector_construction {
    ($name:ident, $length:ident) => {
        impl<const $length: usize> $name<$length> {
            /// Construct from an array of polynomials.
            pub const fn new(vec: [Poly; $length]) -> Self {
                Self(PolyVec::new(vec))
            }

            /// Return the number of polynomial components.
            pub const fn len(&self) -> usize {
                self.0.len()
            }

            /// Whether the vector has no components.
            pub const fn is_empty(&self) -> bool {
                self.0.is_empty()
            }

            /// Borrow the polynomial components.
            pub fn as_slice(&self) -> &[Poly] {
                &self.0.vec
            }
        }
    };
}

impl_vector_construction!(PolyVecK, K);
impl_vector_construction!(PolyVecL, L);
impl_vector_construction!(PolyVecM, M);

/// Reference-compatible pointwise Montgomery accumulation.
///
/// Products are accumulated without intermediate modular reduction.
/// Inputs are expected to be in the NTT domain.
fn pointwise_accumulate<const D: usize>(lhs: &[Poly; D], rhs: &[Poly; D]) -> Poly {
    assert!(D > 0, "HAETAE accumulation requires a nonempty vector");

    let mut result = lhs[0].pointwise_montgomery(&rhs[0]);

    for i in 1..D {
        let product = lhs[i].pointwise_montgomery(&rhs[i]);
        result = result.add(&product);
    }

    result
}

impl<const L: usize> PolyVecL<L> {
    /// Forward NTT of every L-vector component.
    pub fn ntt(&mut self) {
        for poly in &mut self.0.vec {
            poly.ntt();
        }
    }

    /// Conditionally negate coefficients; selector must be zero or one.
    pub fn cneg(&mut self, b: u8) {
        assert!(b <= 1, "HAETAE L-vector cneg requires b in {{0,1}}");

        if b == 1 {
            for poly in &mut self.0.vec {
                for coefficient in &mut poly.coeffs {
                    *coefficient = coefficient
                        .checked_neg()
                        .expect("HAETAE L-vector negation overflow");
                }
            }
        }
    }

    /// Reference-compatible coefficientwise highbits.
    pub fn highbits(&self) -> Self {
        Self::new(std::array::from_fn(|i| self.0.vec[i].highbits()))
    }

    /// Reference-compatible coefficientwise lowbits.
    pub fn lowbits(&self) -> Self {
        Self::new(std::array::from_fn(|i| self.0.vec[i].lowbits()))
    }

    /// Exact squared coefficient norm, with overflow detection.
    pub fn sqnorm2(&self) -> u64 {
        let mut result = 0_u64;

        for poly in &self.0.vec {
            for &coefficient in &poly.coeffs {
                let x = i64::from(coefficient);
                let square = (x * x) as u64;

                result = result
                    .checked_add(square)
                    .expect("HAETAE L-vector squared norm overflow");
            }
        }

        result
    }

    /// Accumulate L componentwise Montgomery products.
    pub fn pointwise_acc_montgomery(&self, other: &Self) -> Poly {
        pointwise_accumulate(&self.0.vec, &other.0.vec)
    }
}

impl<const M: usize> PolyVecM<M> {
    /// Expand secret M- and K-vectors using consecutive nonces.
    ///
    /// The reference samples all M components before the K components.
    pub fn expand_s_with_k<const K: usize>(
        seed: &[u8; 64],
        nonce: u16,
        mode: ParameterSet,
    ) -> (Self, PolyVecK<K>) {
        let params = mode.parameters();
        assert_eq!(M, params.l - 1, "HAETAE M-vector dimension mismatch");
        assert_eq!(K, params.k, "HAETAE K-vector dimension mismatch");

        let total = M + K;
        assert!(usize::from(nonce) + total <= usize::from(u16::MAX) + 1);

        let m = Self(PolyVec::new(std::array::from_fn(|i| {
            uniform_eta(
                seed,
                u16::try_from(usize::from(nonce) + i).expect("nonce range"),
            )
        })));

        let k = PolyVecK(PolyVec::new(std::array::from_fn(|i| {
            uniform_eta(
                seed,
                u16::try_from(usize::from(nonce) + M + i).expect("nonce range"),
            )
        })));

        (m, k)
    }

    /// Forward NTT of every M-vector component.
    pub fn ntt(&mut self) {
        for poly in &mut self.0.vec {
            poly.ntt();
        }
    }

    /// Accumulate M componentwise Montgomery products.
    pub fn pointwise_acc_montgomery(&self, other: &Self) -> Poly {
        pointwise_accumulate(&self.0.vec, &other.0.vec)
    }
}

impl<const K: usize> PolyVecK<K> {
    /// Expand the public K-vector from a 32-byte seed.
    ///
    /// Reference nonce sequence starts at (K << 8) + M.
    pub fn expand_vec_a(seed: &[u8; 32], mode: ParameterSet) -> Self {
        let params = mode.parameters();
        assert_eq!(K, params.k, "HAETAE K-vector dimension mismatch");

        let start = (K << 8) + (params.l - 1);
        assert!(start + K <= usize::from(u16::MAX) + 1);

        Self(PolyVec::new(std::array::from_fn(|i| {
            uniform(seed, u16::try_from(start + i).expect("nonce range"))
        })))
    }

    /// Conditionally add Q to negative coefficients.
    ///
    /// Matches the authenticated C polyveck_caddq operation.
    /// This is not a general modular reduction.
    pub fn caddq(&mut self) {
        for poly in &mut self.0.vec {
            for coefficient in &mut poly.coeffs {
                let adjustment = (*coefficient >> 31) & crate::params::Q;

                *coefficient = coefficient
                    .checked_add(adjustment)
                    .expect("HAETAE K-vector caddq overflow");
            }
        }
    }

    /// Sum squared coefficients without modular reduction.
    ///
    /// Uses signed i64 intermediates so negative coefficients
    /// are squared correctly, then checked u64 accumulation.
    pub fn sqnorm2(&self) -> u64 {
        let mut result = 0_u64;

        for poly in &self.0.vec {
            for &coefficient in &poly.coeffs {
                let x = i64::from(coefficient);
                let square = (x * x) as u64;

                result = result
                    .checked_add(square)
                    .expect("HAETAE K-vector squared norm overflow");
            }
        }

        result
    }

    /// Add (2Q-2)/alpha to negative coefficients.
    ///
    /// Matches the authenticated C polyveck_caddDQ2ALPHA.
    pub fn cadd_dq2alpha(&mut self, mode: ParameterSet) {
        assert_eq!(K, mode.parameters().k, "HAETAE dimension mismatch");

        let alpha = match mode {
            ParameterSet::Haetae2 | ParameterSet::Haetae3 => 512,
            ParameterSet::Haetae5 => 256,
        };

        let correction = (2 * crate::params::Q - 2) / alpha;

        for poly in &mut self.0.vec {
            for coefficient in &mut poly.coeffs {
                let adjustment = (*coefficient >> 31) & correction;
                *coefficient = coefficient
                    .checked_add(adjustment)
                    .expect("HAETAE caddDQ2ALPHA overflow");
            }
        }
    }

    /// Subtract (2Q-2)/alpha from coefficients at or above that value.
    ///
    /// Matches the authenticated C polyveck_csubDQ2ALPHA.
    pub fn csub_dq2alpha(&mut self, mode: ParameterSet) {
        assert_eq!(K, mode.parameters().k, "HAETAE dimension mismatch");

        let alpha = match mode {
            ParameterSet::Haetae2 | ParameterSet::Haetae3 => 512,
            ParameterSet::Haetae5 => 256,
        };

        let correction = (2 * crate::params::Q - 2) / alpha;

        for poly in &mut self.0.vec {
            for coefficient in &mut poly.coeffs {
                let adjustment = if *coefficient >= correction {
                    correction
                } else {
                    0
                };

                *coefficient = coefficient
                    .checked_sub(adjustment)
                    .expect("HAETAE csubDQ2ALPHA overflow");
            }
        }
    }

    /// Multiply coefficients by the mode-specific hint alpha.
    ///
    /// Returns a new vector, preserving the source.
    pub fn mul_alpha(&self, mode: ParameterSet) -> Self {
        assert_eq!(K, mode.parameters().k, "HAETAE dimension mismatch");

        let alpha = match mode {
            ParameterSet::Haetae2 | ParameterSet::Haetae3 => 512,
            ParameterSet::Haetae5 => 256,
        };

        Self::new(std::array::from_fn(|i| {
            Poly::new(std::array::from_fn(|j| {
                self.0.vec[i].coeffs[j]
                    .checked_mul(alpha)
                    .expect("HAETAE mul_alpha overflow")
            }))
        }))
    }

    /// Decompose verification-key coefficients into high and low parts.
    ///
    /// Replaces self with the high components and returns the low
    /// components, matching the authenticated C reference semantics.
    pub fn decompose_vk(&mut self) -> Self {
        let low = std::array::from_fn(|i| {
            Poly::new(std::array::from_fn(|j| {
                let (high, low) = decompose_vk(self.0.vec[i].coeffs[j]);
                self.0.vec[i].coeffs[j] = high;
                low
            }))
        });

        Self::new(low)
    }

    /// Compute reference-compatible highbits hints coefficientwise.
    ///
    /// The parameter set must match the vector's K dimension.
    pub fn highbits_hint(&self, mode: ParameterSet) -> Self {
        assert_eq!(
            K,
            mode.parameters().k,
            "HAETAE highbits hint parameter-set dimension mismatch"
        );

        Self::new(std::array::from_fn(|i| {
            Poly::new(std::array::from_fn(|j| {
                decompose_hint(self.0.vec[i].coeffs[j], mode)
            }))
        }))
    }

    /// Reconstruct CRT coefficients using the parity polynomial
    /// for component zero and zero parity for all remaining components.
    ///
    /// Inputs must satisfy the scalar CRT preconditions.
    pub fn poly_fromcrt(&self, parity: &Poly) -> Self {
        assert!(K > 0, "HAETAE CRT reconstruction requires K > 0");

        Self::new(std::array::from_fn(|i| {
            if i == 0 {
                self.0.vec[i].fromcrt(parity)
            } else {
                self.0.vec[i].fromcrt0()
            }
        }))
    }

    /// Apply the authenticated reference's Montgomery-scaled
    /// doubling and negation to every coefficient.
    pub fn double_negate(&mut self) {
        for poly in &mut self.0.vec {
            for coefficient in &mut poly.coeffs {
                let product = i64::from(*coefficient) * i64::from(MONT) * -2;
                *coefficient = montgomery_reduce(product);
            }
        }
    }

    /// Convert coefficients into Montgomery representation using
    /// the authenticated reference's squared-radix constant.
    pub fn frommont(&mut self) {
        for poly in &mut self.0.vec {
            for coefficient in &mut poly.coeffs {
                let product = i64::from(*coefficient) * i64::from(MONT_SQUARED);
                *coefficient = montgomery_reduce(product);
            }
        }
    }

    /// Double every coefficient without modular reduction.
    pub fn double(&mut self) {
        for poly in &mut self.0.vec {
            for coefficient in &mut poly.coeffs {
                *coefficient = coefficient
                    .checked_mul(2)
                    .expect("HAETAE K-vector doubling overflow");
            }
        }
    }

    /// Conditionally negate every coefficient, with b restricted to 0 or 1.
    pub fn cneg(&mut self, b: u8) {
        assert!(b <= 1, "HAETAE conditional negation requires b in {{0,1}}");

        if b == 1 {
            for poly in &mut self.0.vec {
                for coefficient in &mut poly.coeffs {
                    *coefficient = coefficient
                        .checked_neg()
                        .expect("HAETAE K-vector negation overflow");
                }
            }
        }
    }

    /// Divide every coefficient by two using arithmetic right shift.
    pub fn div2(&mut self) {
        for poly in &mut self.0.vec {
            for coefficient in &mut poly.coeffs {
                *coefficient >>= 1;
            }
        }
    }

    /// Multiply each component pointwise by a polynomial using Montgomery reduction.
    ///
    /// Inputs are expected to be in the NTT domain, matching the HAETAE reference.
    pub fn pointwise_montgomery(&self, polynomial: &Poly) -> Self {
        Self::new(std::array::from_fn(|i| {
            self.0.vec[i].pointwise_montgomery(polynomial)
        }))
    }

    /// Apply the forward NTT independently to each polynomial.
    pub fn ntt(&mut self) {
        for poly in &mut self.0.vec {
            poly.ntt();
        }
    }

    /// Apply the inverse NTT with Montgomery scaling to each polynomial.
    pub fn invntt_tomont(&mut self) {
        for poly in &mut self.0.vec {
            poly.invntt_tomont();
        }
    }

    /// Add two K-vectors without modular reduction.
    pub fn add(&self, other: &Self) -> Self {
        Self::new(std::array::from_fn(|i| self.0.vec[i].add(&other.0.vec[i])))
    }

    /// Subtract two K-vectors without modular reduction.
    pub fn sub(&self, other: &Self) -> Self {
        Self::new(std::array::from_fn(|i| self.0.vec[i].sub(&other.0.vec[i])))
    }

    /// Canonically reduce every coefficient modulo q.
    pub fn freeze(&mut self) {
        for poly in &mut self.0.vec {
            poly.freeze();
        }
    }

    /// Canonically reduce every coefficient modulo 2q.
    pub fn freeze2q(&mut self) {
        for poly in &mut self.0.vec {
            poly.freeze2q();
        }
    }

    /// Apply the reference centered reduction modulo 2q.
    pub fn reduce2q(&mut self) {
        for poly in &mut self.0.vec {
            poly.reduce2q();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ParameterSet;

    #[test]
    fn reference_dimensions() {
        for variant in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let params = variant.parameters();

            assert_eq!(
                params.l - 1,
                match variant {
                    ParameterSet::Haetae2 => 3,
                    ParameterSet::Haetae3 => 5,
                    ParameterSet::Haetae5 => 6,
                }
            );
        }

        assert_eq!(PolyVecK::<2>::default().len(), 2);
        assert_eq!(PolyVecK::<3>::default().len(), 3);
        assert_eq!(PolyVecK::<4>::default().len(), 4);

        assert_eq!(PolyVecL::<4>::default().len(), 4);
        assert_eq!(PolyVecL::<6>::default().len(), 6);
        assert_eq!(PolyVecL::<7>::default().len(), 7);

        assert_eq!(PolyVecM::<3>::default().len(), 3);
        assert_eq!(PolyVecM::<5>::default().len(), 5);
        assert_eq!(PolyVecM::<6>::default().len(), 6);
    }

    #[test]
    fn l_vector_pointwise_accumulation_all_modes() {
        fn check<const L: usize>() {
            let lhs = PolyVecL::<L>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    ((i * 127 + j * 17 + 3) % 64513) as i32
                }))
            }));

            let rhs = PolyVecL::<L>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    ((i * 71 + j * 29 + 5) % 64513) as i32
                }))
            }));

            let actual = lhs.pointwise_acc_montgomery(&rhs);

            let mut expected = lhs.as_slice()[0].pointwise_montgomery(&rhs.as_slice()[0]);

            for i in 1..L {
                let product = lhs.as_slice()[i].pointwise_montgomery(&rhs.as_slice()[i]);
                expected = expected.add(&product);
            }

            assert_eq!(actual, expected);
        }

        check::<4>();
        check::<6>();
        check::<7>();
    }

    #[test]
    fn m_vector_pointwise_accumulation_all_modes() {
        fn check<const M: usize>() {
            let lhs = PolyVecM::<M>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    ((i * 97 + j * 13 + 7) % 64513) as i32
                }))
            }));

            let rhs = PolyVecM::<M>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    ((i * 53 + j * 31 + 11) % 64513) as i32
                }))
            }));

            let actual = lhs.pointwise_acc_montgomery(&rhs);

            let mut expected = lhs.as_slice()[0].pointwise_montgomery(&rhs.as_slice()[0]);

            for i in 1..M {
                let product = lhs.as_slice()[i].pointwise_montgomery(&rhs.as_slice()[i]);
                expected = expected.add(&product);
            }

            assert_eq!(actual, expected);
        }

        check::<3>();
        check::<5>();
        check::<6>();
    }

    #[test]
    fn k_vector_caddq_all_modes() {
        fn check<const K: usize>() {
            let values = [
                -2 * crate::params::Q,
                -crate::params::Q,
                -1,
                0,
                1,
                crate::params::Q - 1,
                crate::params::Q,
                2 * crate::params::Q,
            ];

            let mut vector = PolyVecK::<K>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| values[(i * 7 + j) % values.len()]))
            }));

            let original = vector.clone();
            vector.caddq();

            for i in 0..K {
                for j in 0..256 {
                    let x = original.as_slice()[i].coeffs[j];
                    let expected = x + if x < 0 { crate::params::Q } else { 0 };

                    assert_eq!(vector.as_slice()[i].coeffs[j], expected);
                }
            }
        }

        check::<2>();
        check::<3>();
        check::<4>();
    }

    #[test]
    fn k_vector_sqnorm2_all_modes() {
        fn check<const K: usize>() {
            let vector = PolyVecK::<K>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    ((i * 17 + j * 31) % 2001) as i32 - 1000
                }))
            }));

            let expected: u64 = vector
                .as_slice()
                .iter()
                .flat_map(|poly| poly.coeffs.iter())
                .map(|&x| {
                    let x = i64::from(x);
                    (x * x) as u64
                })
                .sum();

            assert_eq!(vector.sqnorm2(), expected);
        }

        check::<2>();
        check::<3>();
        check::<4>();
    }

    #[test]
    fn k_vector_sqnorm2_large_representable_coefficients() {
        const MAGNITUDE: i32 = 1_000_000;

        let vector = PolyVecK::<4>::new(std::array::from_fn(|i| {
            Poly::new(std::array::from_fn(|j| {
                if (i + j) % 2 == 0 {
                    -MAGNITUDE
                } else {
                    MAGNITUDE
                }
            }))
        }));

        let expected = 1024_u64 * (MAGNITUDE as u64) * (MAGNITUDE as u64);

        assert_eq!(vector.sqnorm2(), expected);
    }

    #[test]
    #[should_panic(expected = "HAETAE K-vector squared norm overflow")]
    fn k_vector_sqnorm2_rejects_overflow() {
        let vector = PolyVecK::<4>::new(std::array::from_fn(|i| {
            Poly::new(std::array::from_fn(|j| {
                if (i + j) % 2 == 0 {
                    i32::MIN
                } else {
                    i32::MAX
                }
            }))
        }));

        let _ = vector.sqnorm2();
    }

    #[test]
    fn k_vector_caddq_zero_preservation() {
        let mut vector = PolyVecK::<2>::default();
        vector.caddq();

        assert_eq!(vector, PolyVecK::<2>::default());
        assert_eq!(vector.sqnorm2(), 0);
    }

    #[test]
    fn l_m_vector_ntt_all_modes() {
        fn check_l<const L: usize>() {
            let mut vector = PolyVecL::<L>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    ((i * 19 + j * 13) % 257) as i32 - 128
                }))
            }));

            let mut expected = vector.clone();
            for poly in &mut expected.0.vec {
                poly.ntt();
            }

            vector.ntt();
            assert_eq!(vector, expected);
        }

        fn check_m<const M: usize>() {
            let mut vector = PolyVecM::<M>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    ((i * 23 + j * 11) % 257) as i32 - 128
                }))
            }));

            let mut expected = vector.clone();
            for poly in &mut expected.0.vec {
                poly.ntt();
            }

            vector.ntt();
            assert_eq!(vector, expected);
        }

        check_l::<4>();
        check_l::<6>();
        check_l::<7>();
        check_m::<3>();
        check_m::<5>();
        check_m::<6>();
    }

    #[test]
    fn l_vector_decomposition_and_negation() {
        for b in [0_u8, 1] {
            let mut vector = PolyVecL::<4>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    ((i * 37 + j * 29) % 2001) as i32 - 1000
                }))
            }));

            let original = vector.clone();
            let high = vector.highbits();
            let low = vector.lowbits();

            for i in 0..4 {
                for j in 0..256 {
                    assert_eq!(
                        high.as_slice()[i].coeffs[j] * 256 + low.as_slice()[i].coeffs[j],
                        original.as_slice()[i].coeffs[j]
                    );
                }
            }

            vector.cneg(b);

            for i in 0..4 {
                for j in 0..256 {
                    let x = original.as_slice()[i].coeffs[j];
                    assert_eq!(vector.as_slice()[i].coeffs[j], if b == 0 { x } else { -x });
                }
            }
        }
    }

    #[test]
    fn l_vector_sqnorm2_all_modes() {
        fn check<const L: usize>() {
            let vector = PolyVecL::<L>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    ((i * 17 + j * 31) % 2001) as i32 - 1000
                }))
            }));

            let expected: u64 = vector
                .as_slice()
                .iter()
                .flat_map(|poly| poly.coeffs.iter())
                .map(|&x| {
                    let x = i64::from(x);
                    (x * x) as u64
                })
                .sum();

            assert_eq!(vector.sqnorm2(), expected);
        }

        check::<4>();
        check::<6>();
        check::<7>();
    }

    #[test]
    #[should_panic(expected = "HAETAE L-vector cneg requires")]
    fn l_vector_cneg_rejects_invalid_selector() {
        let mut vector = PolyVecL::<4>::default();
        vector.cneg(2);
    }

    #[test]
    fn k_vector_alpha_corrections_all_modes() {
        fn check<const K: usize>(mode: ParameterSet) {
            let alpha = match mode {
                ParameterSet::Haetae2 | ParameterSet::Haetae3 => 512,
                ParameterSet::Haetae5 => 256,
            };

            let correction = (2 * crate::params::Q - 2) / alpha;

            let boundaries = [
                -correction - 1,
                -correction,
                -1,
                0,
                1,
                correction - 1,
                correction,
                correction + 1,
                2 * correction,
            ];

            let original = PolyVecK::<K>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    boundaries[(i * 7 + j) % boundaries.len()]
                }))
            }));

            let mut added = original.clone();
            added.cadd_dq2alpha(mode);

            let mut subtracted = original.clone();
            subtracted.csub_dq2alpha(mode);

            let multiplied = original.mul_alpha(mode);

            for i in 0..K {
                for j in 0..256 {
                    let x = original.as_slice()[i].coeffs[j];

                    assert_eq!(
                        added.as_slice()[i].coeffs[j],
                        x + if x < 0 { correction } else { 0 }
                    );

                    assert_eq!(
                        subtracted.as_slice()[i].coeffs[j],
                        x - if x >= correction { correction } else { 0 }
                    );

                    assert_eq!(multiplied.as_slice()[i].coeffs[j], x * alpha);
                }
            }
        }

        check::<2>(ParameterSet::Haetae2);
        check::<3>(ParameterSet::Haetae3);
        check::<4>(ParameterSet::Haetae5);
    }

    #[test]
    fn k_vector_alpha_correction_zero_behavior() {
        let mut vector = PolyVecK::<2>::default();

        vector.cadd_dq2alpha(ParameterSet::Haetae2);
        vector.csub_dq2alpha(ParameterSet::Haetae2);

        assert_eq!(vector, PolyVecK::<2>::default());

        assert_eq!(
            vector.mul_alpha(ParameterSet::Haetae2),
            PolyVecK::<2>::default()
        );
    }

    #[test]
    #[should_panic(expected = "dimension mismatch")]
    fn k_vector_alpha_correction_rejects_mode_mismatch() {
        let mut vector = PolyVecK::<2>::default();
        vector.cadd_dq2alpha(ParameterSet::Haetae5);
    }

    #[test]
    fn k_vector_decompose_vk_all_modes() {
        fn check<const K: usize>() {
            let mut vector = PolyVecK::<K>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    let boundaries = [
                        -129026, -64513, -3, -2, -1, 0, 1, 2, 3, 64512, 64513, 129025,
                    ];
                    boundaries[(i * 7 + j) % boundaries.len()]
                }))
            }));

            let original = vector.clone();
            let low = vector.decompose_vk();

            for i in 0..K {
                for j in 0..256 {
                    let input = original.as_slice()[i].coeffs[j];
                    let high = vector.as_slice()[i].coeffs[j];
                    let remainder = low.as_slice()[i].coeffs[j];

                    let (expected_high, expected_low) = decompose_vk(input);

                    assert_eq!(high, expected_high);
                    assert_eq!(remainder, expected_low);
                    assert!((-1..=1).contains(&remainder));
                    assert_eq!(high * 2 + remainder, input);
                }
            }
        }

        check::<2>();
        check::<3>();
        check::<4>();
    }

    #[test]
    fn k_vector_decompose_vk_zero_preservation() {
        fn check<const K: usize>() {
            let mut vector = PolyVecK::<K>::default();
            let low = vector.decompose_vk();

            assert_eq!(vector, PolyVecK::<K>::default());
            assert_eq!(low, PolyVecK::<K>::default());
        }

        check::<2>();
        check::<3>();
        check::<4>();
    }

    #[test]
    fn k_vector_decompose_vk_recomposition() {
        let mut vector = PolyVecK::<4>::new(std::array::from_fn(|i| {
            Poly::new(std::array::from_fn(|j| {
                ((i * 257 + j * 31) % 129026) as i32
            }))
        }));

        let original = vector.clone();
        let low = vector.decompose_vk();

        for i in 0..4 {
            for j in 0..256 {
                assert_eq!(
                    2 * vector.as_slice()[i].coeffs[j] + low.as_slice()[i].coeffs[j],
                    original.as_slice()[i].coeffs[j]
                );
            }
        }
    }

    #[test]
    fn k_vector_highbits_hint_all_modes() {
        fn check<const K: usize>(mode: ParameterSet) {
            assert_eq!(K, mode.parameters().k);

            let alpha = match mode {
                ParameterSet::Haetae5 => 256,
                ParameterSet::Haetae2 | ParameterSet::Haetae3 => 512,
            };

            let source = PolyVecK::<K>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    let boundaries = [
                        0,
                        1,
                        -1,
                        alpha / 2 - 1,
                        alpha / 2,
                        alpha / 2 + 1,
                        -alpha / 2,
                        -alpha / 2 - 1,
                        64512,
                        64513,
                        129024,
                        129025,
                    ];

                    boundaries[(i * 7 + j) % boundaries.len()]
                }))
            }));

            let original = source.clone();
            let result = source.highbits_hint(mode);

            assert_eq!(source, original);

            for i in 0..K {
                for j in 0..256 {
                    assert_eq!(
                        result.as_slice()[i].coeffs[j],
                        decompose_hint(source.as_slice()[i].coeffs[j], mode)
                    );
                }
            }
        }

        check::<2>(ParameterSet::Haetae2);
        check::<3>(ParameterSet::Haetae3);
        check::<4>(ParameterSet::Haetae5);
    }

    #[test]
    fn k_vector_highbits_hint_zero_preservation() {
        assert_eq!(
            PolyVecK::<2>::default().highbits_hint(ParameterSet::Haetae2),
            PolyVecK::<2>::default()
        );

        assert_eq!(
            PolyVecK::<3>::default().highbits_hint(ParameterSet::Haetae3),
            PolyVecK::<3>::default()
        );

        assert_eq!(
            PolyVecK::<4>::default().highbits_hint(ParameterSet::Haetae5),
            PolyVecK::<4>::default()
        );
    }

    #[test]
    #[should_panic(expected = "dimension mismatch")]
    fn k_vector_highbits_hint_rejects_mode_mismatch() {
        let v = PolyVecK::<2>::default();
        let _ = v.highbits_hint(ParameterSet::Haetae5);
    }

    #[test]
    fn k_vector_crt_reconstruction_all_modes() {
        fn check<const K: usize>() {
            let source = PolyVecK::<K>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| ((i * 257 + j * 31) % 64513) as i32))
            }));

            let parity = Poly::new(std::array::from_fn(|j| (j % 2) as i32));

            let original = source.clone();
            let result = source.poly_fromcrt(&parity);

            assert_eq!(source, original);

            for i in 0..K {
                let expected = if i == 0 {
                    source.as_slice()[i].fromcrt(&parity)
                } else {
                    source.as_slice()[i].fromcrt0()
                };

                assert_eq!(result.as_slice()[i], expected);
            }
        }

        check::<2>();
        check::<3>();
        check::<4>();
    }

    #[test]
    fn k_vector_crt_parity_only_affects_first_component() {
        let source = PolyVecK::<4>::new(std::array::from_fn(|i| {
            Poly::new(std::array::from_fn(|j| ((i * 101 + j * 17) % 64513) as i32))
        }));

        let zero = Poly::default();
        let one = Poly::new([1; 256]);

        let a = source.poly_fromcrt(&zero);
        let b = source.poly_fromcrt(&one);

        for i in 1..4 {
            assert_eq!(a.as_slice()[i], b.as_slice()[i]);
        }

        assert_ne!(a.as_slice()[0], b.as_slice()[0]);
    }

    #[test]
    fn k_vector_montgomery_transformations_all_modes() {
        fn check<const K: usize>() {
            let original = PolyVecK::<K>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    let magnitude = ((i * 127 + j * 31 + 1) % 64514) as i32;
                    if j % 2 == 0 {
                        magnitude
                    } else {
                        -magnitude
                    }
                }))
            }));

            let mut negated = original.clone();
            negated.double_negate();

            let mut encoded = original.clone();
            encoded.frommont();

            let mut composed = original.clone();
            composed.frommont();
            composed.double_negate();

            for i in 0..K {
                for j in 0..256 {
                    let x = original.as_slice()[i].coeffs[j];

                    let expected_negated = montgomery_reduce(i64::from(x) * i64::from(MONT) * -2);

                    let expected_encoded =
                        montgomery_reduce(i64::from(x) * i64::from(MONT_SQUARED));

                    let expected_composed =
                        montgomery_reduce(i64::from(expected_encoded) * i64::from(MONT) * -2);

                    assert_eq!(negated.as_slice()[i].coeffs[j], expected_negated);
                    assert_eq!(encoded.as_slice()[i].coeffs[j], expected_encoded);
                    assert_eq!(composed.as_slice()[i].coeffs[j], expected_composed);
                }
            }
        }

        check::<2>();
        check::<3>();
        check::<4>();
    }

    #[test]
    fn k_vector_montgomery_zero_preservation() {
        for k in [2, 3, 4] {
            match k {
                2 => {
                    let mut v = PolyVecK::<2>::default();
                    v.frommont();
                    v.double_negate();
                    assert_eq!(v, PolyVecK::<2>::default());
                }
                3 => {
                    let mut v = PolyVecK::<3>::default();
                    v.frommont();
                    v.double_negate();
                    assert_eq!(v, PolyVecK::<3>::default());
                }
                4 => {
                    let mut v = PolyVecK::<4>::default();
                    v.frommont();
                    v.double_negate();
                    assert_eq!(v, PolyVecK::<4>::default());
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn k_vector_basic_transformations_all_modes() {
        fn check<const K: usize>() {
            let original = PolyVecK::<K>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    let magnitude = ((i * 101 + j * 17 + 1) % 64513) as i32;
                    if j % 2 == 0 {
                        magnitude
                    } else {
                        -magnitude
                    }
                }))
            }));

            let mut doubled = original.clone();
            doubled.double();

            for (before, after) in original.as_slice().iter().zip(doubled.as_slice()) {
                for (&x, &y) in before.coeffs.iter().zip(&after.coeffs) {
                    assert_eq!(y, 2 * x);
                }
            }

            let mut unchanged = original.clone();
            unchanged.cneg(0);
            assert_eq!(unchanged, original);

            let mut negated = original.clone();
            negated.cneg(1);

            for (before, after) in original.as_slice().iter().zip(negated.as_slice()) {
                for (&x, &y) in before.coeffs.iter().zip(&after.coeffs) {
                    assert_eq!(y, -x);
                }
            }

            let mut halved = original.clone();
            halved.div2();

            for (before, after) in original.as_slice().iter().zip(halved.as_slice()) {
                for (&x, &y) in before.coeffs.iter().zip(&after.coeffs) {
                    assert_eq!(y, x >> 1);
                }
            }

            let mut restored = original.clone();
            restored.cneg(1);
            restored.cneg(1);
            assert_eq!(restored, original);
        }

        check::<2>();
        check::<3>();
        check::<4>();
    }

    #[test]
    #[should_panic(expected = "HAETAE conditional negation requires")]
    fn k_vector_cneg_rejects_invalid_selector() {
        let mut vector = PolyVecK::<2>::default();
        vector.cneg(2);
    }

    #[test]
    #[should_panic(expected = "HAETAE K-vector doubling overflow")]
    fn k_vector_double_rejects_overflow() {
        let mut vector = PolyVecK::<2>::default();
        vector.0.vec[0].coeffs[0] = i32::MAX;
        vector.double();
    }

    #[test]
    fn k_vector_pointwise_montgomery_all_modes() {
        fn check<const K: usize>() {
            let vector = PolyVecK::<K>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    ((i * 131 + j * 17 + 7) % 64513) as i32
                }))
            }));

            let multiplier = Poly::new(std::array::from_fn(|j| ((j * 29 + 3) % 64513) as i32));

            let actual = vector.pointwise_montgomery(&multiplier);

            let expected = PolyVecK::<K>::new(std::array::from_fn(|i| {
                vector.as_slice()[i].pointwise_montgomery(&multiplier)
            }));

            assert_eq!(actual, expected);

            let zero = Poly::default();
            let result = vector.pointwise_montgomery(&zero);

            assert_eq!(result, PolyVecK::<K>::default());
        }

        check::<2>();
        check::<3>();
        check::<4>();
    }

    #[test]
    fn k_vector_ntt_matches_individual_polynomials() {
        fn check<const K: usize>() {
            let original = PolyVecK::<K>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    ((i * 257 + j * 37 + 11) % 64513) as i32
                }))
            }));

            let mut expected_forward = original.clone();
            for poly in &mut expected_forward.0.vec {
                poly.ntt();
            }

            let mut actual = original.clone();
            actual.ntt();

            assert_eq!(actual, expected_forward);

            let mut expected_inverse = expected_forward.clone();
            for poly in &mut expected_inverse.0.vec {
                poly.invntt_tomont();
            }

            actual.invntt_tomont();

            assert_eq!(actual, expected_inverse);
        }

        check::<2>();
        check::<3>();
        check::<4>();
    }

    #[test]
    fn k_vector_ntt_zero_preservation() {
        fn check<const K: usize>() {
            let mut vector = PolyVecK::<K>::default();

            vector.ntt();
            assert_eq!(vector, PolyVecK::<K>::default());

            vector.invntt_tomont();
            assert_eq!(vector, PolyVecK::<K>::default());
        }

        check::<2>();
        check::<3>();
        check::<4>();
    }

    #[test]
    fn k_vector_arithmetic_all_modes() {
        for k in [2_usize, 3, 4] {
            fn check<const K: usize>() {
                let a = PolyVecK::<K>::new(std::array::from_fn(|i| {
                    Poly::new([i as i32 * 1000 + 257; 256])
                }));
                let b = PolyVecK::<K>::new(std::array::from_fn(|i| {
                    Poly::new([i as i32 * 100 + 17; 256])
                }));

                let sum = a.add(&b);
                let recovered = sum.sub(&b);
                assert_eq!(recovered, a);

                for (i, poly) in sum.as_slice().iter().enumerate() {
                    assert_eq!(poly.coeffs[0], i as i32 * 1100 + 274);
                }

                let mut frozen = sum.clone();
                frozen.freeze();
                for poly in frozen.as_slice() {
                    assert!(poly.coeffs.iter().all(|&x| (0..64513).contains(&x)));
                }

                let mut frozen2q = sum.clone();
                frozen2q.freeze2q();
                for poly in frozen2q.as_slice() {
                    assert!(poly.coeffs.iter().all(|&x| (0..129026).contains(&x)));
                }

                let mut reduced = sum.clone();
                reduced.reduce2q();
                for (original, actual) in sum.as_slice().iter().zip(reduced.as_slice()) {
                    for (&x, &y) in original.coeffs.iter().zip(&actual.coeffs) {
                        assert_eq!((x - y).rem_euclid(129026), 0);
                    }
                }
            }

            match k {
                2 => check::<2>(),
                3 => check::<3>(),
                4 => check::<4>(),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn vector_roles_are_distinct() {
        use std::any::TypeId;

        assert_ne!(TypeId::of::<PolyVecK<3>>(), TypeId::of::<PolyVecM<3>>());
        assert_ne!(TypeId::of::<PolyVecK<4>>(), TypeId::of::<PolyVecL<4>>());
    }

    #[test]
    fn construction_and_zero() {
        let vector = PolyVecK::<2>::default();
        assert!(vector
            .as_slice()
            .iter()
            .all(|poly| { poly.coeffs.iter().all(|&coefficient| coefficient == 0) }));

        let constructed = PolyVecK::new(vector.as_slice().to_vec().try_into().unwrap());
        assert_eq!(constructed, vector);
        assert!(!constructed.is_empty());
    }
}

// HAETAE_10K_7D_3C_VECTOR_TEST
#[cfg(test)]
mod secret_zeroization_tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn k_vector_coefficients_are_cleared() {
        let mut vector = PolyVecK::<2>::new([
            Poly::new([0x1234_i32; crate::params::N]),
            Poly::new([-0x2345_i32; crate::params::N]),
        ]);

        assert!(vector
            .as_slice()
            .iter()
            .any(|poly| poly.coeffs.iter().any(|&x| x != 0)));

        vector.zeroize();

        assert!(vector
            .as_slice()
            .iter()
            .all(|poly| poly.coeffs.iter().all(|&x| x == 0)));
    }

    #[test]
    fn m_vector_coefficients_are_cleared() {
        let mut vector = PolyVecM::<3>::new([
            Poly::new([0x1234_i32; crate::params::N]),
            Poly::new([-0x2345_i32; crate::params::N]),
            Poly::new([0x3456_i32; crate::params::N]),
        ]);

        assert!(vector
            .as_slice()
            .iter()
            .any(|poly| poly.coeffs.iter().any(|&x| x != 0)));

        vector.zeroize();

        assert!(vector
            .as_slice()
            .iter()
            .all(|poly| poly.coeffs.iter().all(|&x| x == 0)));
    }
}
