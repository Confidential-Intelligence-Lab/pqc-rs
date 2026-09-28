//! Polynomial-vector helpers for ML-KEM K-PKE scaffolding.

use crate::poly::Poly;

/// Maximum ML-KEM module rank.
pub const MAX_K: usize = 4;

/// Polynomial vector with runtime rank constrained to `1..=4`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolyVec {
    rank: usize,
    polys: [Poly; MAX_K],
}

impl PolyVec {
    /// Construct a zero polynomial vector.
    pub fn zero(rank: usize) -> Self {
        assert!((1..=MAX_K).contains(&rank));
        Self {
            rank,
            polys: core::array::from_fn(|_| Poly::zero()),
        }
    }

    /// Construct from a slice of polynomials.
    pub fn from_slice(input: &[Poly]) -> Self {
        assert!((1..=MAX_K).contains(&input.len()));

        let mut out = Self::zero(input.len());
        let mut i = 0;
        while i < input.len() {
            out.polys[i] = input[i].clone();
            i += 1;
        }

        out
    }

    /// Return rank.
    pub fn rank(&self) -> usize {
        self.rank
    }

    /// Borrow the active polynomial slice.
    pub fn as_slice(&self) -> &[Poly] {
        &self.polys[..self.rank]
    }

    /// Add two polynomial vectors of equal rank.
    #[cfg(test)]
    pub fn add(&self, rhs: &Self) -> Self {
        assert_eq!(self.rank, rhs.rank);

        let mut out = Self::zero(self.rank);
        let mut i = 0;
        while i < self.rank {
            out.polys[i] = self.polys[i].add(&rhs.polys[i]);
            i += 1;
        }
        out
    }

    /// Dot product using schoolbook polynomial multiplication.
    #[cfg(test)]
    pub fn dot_schoolbook(&self, rhs: &Self) -> Poly {
        assert_eq!(self.rank, rhs.rank);

        let mut acc = Poly::zero();
        let mut i = 0;
        while i < self.rank {
            acc = acc.add(&self.polys[i].mul_schoolbook(&rhs.polys[i]));
            i += 1;
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::N;

    #[test]
    fn polyvec_tracks_rank() {
        let v = PolyVec::zero(3);
        assert_eq!(v.rank(), 3);
        assert_eq!(v.as_slice().len(), 3);
    }

    #[test]
    fn dot_product_with_identity_vector_works() {
        let mut one = [0i16; N];
        one[0] = 1;

        let mut p = [0i16; N];
        p[0] = 4;
        p[1] = 9;

        let a = Poly::from_coefficients(p);
        let id = Poly::from_coefficients(one);

        let va = PolyVec::from_slice(core::slice::from_ref(&a));
        let vi = PolyVec::from_slice(core::slice::from_ref(&id));

        assert_eq!(va.dot_schoolbook(&vi), a);
    }
}
