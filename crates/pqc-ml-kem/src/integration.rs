//! Deterministic ML-KEM primitives for protocol integration.
//!
//! These operations expose the deterministic FIPS 203 boundaries required by
//! higher-level protocol constructions such as HPKE. Ordinary applications
//! should use the randomized high-level ML-KEM API instead.

pub use crate::ml_kem_decaps::{decaps_internal as decaps, MlKemDecapsulationOutput};
pub use crate::ml_kem_encaps::{encaps_internal as encaps, MlKemEncapsulationOutput};
pub use crate::ml_kem_key_check::{decapsulation_key_is_valid, encapsulation_key_is_valid};
pub use crate::ml_kem_keygen::{
    ml_kem_1024_keygen_internal as keygen_1024, ml_kem_512_keygen_internal as keygen_512,
    ml_kem_768_keygen_internal as keygen_768, MlKemKeygenOutput,
};
