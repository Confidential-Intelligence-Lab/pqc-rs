//! Unstable engineering and assurance API.
//!
//! This module exposes implementation-level ML-DSA functionality required by
//! repository conformance tests, ACVP tooling, benchmarks, profiling, timing
//! analysis, and assurance experiments.
//!
//! It is available only with the `internal-api` feature and is explicitly
//! excluded from the crate's SemVer compatibility commitment.

/// Audit and operation-counting instrumentation.
pub mod audit {
    pub use crate::audit::*;
}

/// Challenge sampling and validation primitives.
pub mod challenge {
    pub use crate::challenge::*;
}

/// ML-DSA implementation constants.
pub mod constants {
    pub use crate::constants::*;
}

/// Coefficient and polynomial encoding primitives.
pub mod encoding {
    pub use crate::encoding::*;
}

/// Matrix expansion primitives.
pub mod expand_a {
    pub use crate::expand_a::*;
}

/// HashML-DSA implementation primitives.
pub mod hash_mldsa {
    pub use crate::hash_mldsa::*;
}

/// Hint-generation and hint-use primitives.
pub mod hint {
    pub use crate::hint::*;
}

/// Deterministic key-generation primitives.
pub mod keygen {
    pub use crate::keygen::*;
}

/// Number-theoretic transform primitives.
pub mod ntt {
    pub use crate::ntt::*;
}

/// Polynomial representation and operations.
pub mod poly {
    pub use crate::poly::*;
}

/// Modular reduction primitives.
pub mod reduce {
    pub use crate::reduce::*;
}

/// Rounding and decomposition primitives.
pub mod rounding {
    pub use crate::rounding::*;
}

/// Secret and rejection-sampling primitives.
pub mod sample {
    pub use crate::sample::*;
}

/// Signature-generation implementation primitives.
pub mod signature {
    pub use crate::signature::*;
}

/// Signing preparation primitives.
pub mod signing {
    pub use crate::signing::*;
}

/// Shared signing-core primitives.
pub mod signing_core {
    pub use crate::signing_core::*;
}

/// Verification implementation primitives.
pub mod verification {
    pub use crate::verification::*;
}

/// Extendable-output-function primitives.
pub mod xof {
    pub use crate::xof::*;
}
