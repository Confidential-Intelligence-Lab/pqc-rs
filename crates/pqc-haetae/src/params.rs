//! HAETAE 1.2.0 parameter definitions.

/// Polynomial degree.
pub const N: usize = 256;

/// HAETAE polynomial modulus.
pub const Q: i32 = 64_513;

/// Twice the polynomial modulus.
pub const DQ: i32 = 129_026;

/// Seed length in bytes.
pub const SEED_BYTES: usize = 32;

/// Extended hash output length in bytes.
pub const CRH_BYTES: usize = 64;

/// Squared-norm rejection thresholds for HAETAE signing.
///
/// HAETAE 1.2.0 converts B0^2 and B1^2 to unsigned integers
/// before multiplying by LN^2, where LN = 8192.
///
/// Returns (threshold1, threshold0).
pub const fn signing_rejection_thresholds(mode: ParameterSet) -> (u64, u64) {
    let (b0, b1): (f64, f64) = match mode {
        ParameterSet::Haetae2 => (9846.02, 9838.98),
        ParameterSet::Haetae3 => (18314.98, 18307.70),
        ParameterSet::Haetae5 => (22343.66, 22334.95),
    };

    let ln_squared = 8192_u64 * 8192_u64;

    let b0_squared = (b0 * b0) as u64;
    let b1_squared = (b1 * b1) as u64;

    (b1_squared * ln_squared, b0_squared * ln_squared)
}

/// Supported HAETAE parameter sets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterSet {
    Haetae2,
    Haetae3,
    Haetae5,
}

/// Parameters associated with a HAETAE variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameters {
    pub k: usize,
    pub l: usize,
    pub tau: usize,
    pub signature_bytes: usize,
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
}

impl ParameterSet {
    /// Returns the parameters for this variant.
    pub const fn parameters(self) -> Parameters {
        match self {
            Self::Haetae2 => Parameters {
                k: 2,
                l: 4,
                tau: 58,
                signature_bytes: 1474,
                public_key_bytes: 992,
                secret_key_bytes: 1408,
            },
            Self::Haetae3 => Parameters {
                k: 3,
                l: 6,
                tau: 80,
                signature_bytes: 2349,
                public_key_bytes: 1472,
                secret_key_bytes: 2112,
            },
            Self::Haetae5 => Parameters {
                k: 4,
                l: 7,
                tau: 128,
                signature_bytes: 2948,
                public_key_bytes: 2080,
                secret_key_bytes: 2752,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_constants_match_reference() {
        assert_eq!(N, 256);
        assert_eq!(Q, 64_513);
        assert_eq!(DQ, 2 * Q);
        assert_eq!(SEED_BYTES, 32);
        assert_eq!(CRH_BYTES, 64);
    }

    #[test]
    fn parameter_sets_match_reference() {
        let cases = [
            (ParameterSet::Haetae2, 2, 4, 58, 1474, 992, 1408),
            (ParameterSet::Haetae3, 3, 6, 80, 2349, 1472, 2112),
            (ParameterSet::Haetae5, 4, 7, 128, 2948, 2080, 2752),
        ];

        for (variant, k, l, tau, sig, pk, sk) in cases {
            let p = variant.parameters();

            assert_eq!(p.k, k);
            assert_eq!(p.l, l);
            assert_eq!(p.tau, tau);
            assert_eq!(p.signature_bytes, sig);
            assert_eq!(p.public_key_bytes, pk);
            assert_eq!(p.secret_key_bytes, sk);
        }
    }
}
