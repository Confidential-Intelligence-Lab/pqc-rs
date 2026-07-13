//! ML-DSA parameter-set definitions.

/// Supported ML-DSA parameter set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlDsaParameterSet {
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
}

/// Immutable parameter values for one ML-DSA instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlDsaParameters {
    /// Module rank `k`.
    pub k: usize,
    /// Module rank `l`.
    pub l: usize,
    /// Secret coefficient bound `eta`.
    pub eta: i32,
    /// Challenge weight `tau`.
    pub tau: usize,
    /// Rejection bound exponent `gamma1`.
    pub gamma1: i32,
    /// Low-bit rounding bound `gamma2`.
    pub gamma2: i32,
    /// Hint-weight bound `omega`.
    pub omega: usize,
    /// Public-key length in bytes.
    pub public_key_bytes: usize,
    /// Private-key length in bytes.
    pub private_key_bytes: usize,
    /// Signature length in bytes.
    pub signature_bytes: usize,
}

impl MlDsaParameterSet {
    /// Return the FIPS 204 parameters for this instance.
    pub const fn parameters(self) -> MlDsaParameters {
        match self {
            Self::MlDsa44 => MlDsaParameters {
                k: 4,
                l: 4,
                eta: 2,
                tau: 39,
                gamma1: 1 << 17,
                gamma2: (8_380_417 - 1) / 88,
                omega: 80,
                public_key_bytes: 1_312,
                private_key_bytes: 2_560,
                signature_bytes: 2_420,
            },
            Self::MlDsa65 => MlDsaParameters {
                k: 6,
                l: 5,
                eta: 4,
                tau: 49,
                gamma1: 1 << 19,
                gamma2: (8_380_417 - 1) / 32,
                omega: 55,
                public_key_bytes: 1_952,
                private_key_bytes: 4_032,
                signature_bytes: 3_309,
            },
            Self::MlDsa87 => MlDsaParameters {
                k: 8,
                l: 7,
                eta: 2,
                tau: 60,
                gamma1: 1 << 19,
                gamma2: (8_380_417 - 1) / 32,
                omega: 75,
                public_key_bytes: 2_592,
                private_key_bytes: 4_896,
                signature_bytes: 4_627,
            },
        }
    }

    /// Return the canonical display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }
}
