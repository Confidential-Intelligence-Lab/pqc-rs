//! Protocol capability registry.
//!
//! Capability identifiers are protocol-layer names for complete cryptographic
//! profiles. They are intentionally opaque at this layer: `pqc-protocol`
//! negotiates and binds identifiers but does not resolve them to cryptographic
//! implementations.
//!
//! The corresponding cryptographic profile resolution is performed outside
//! this crate so that the protocol framework remains independent of concrete
//! KEM, KDF, AEAD, and provider implementations.

use crate::CapabilityId;

/// HPKE with ML-KEM-768.
///
/// Cryptographic resolution of this capability is defined by the integration
/// layer rather than by `pqc-protocol`.
pub const HPKE_ML_KEM_768: CapabilityId = CapabilityId::new(0x0101);

/// HPKE with ML-KEM-1024.
///
/// Cryptographic resolution of this capability is defined by the integration
/// layer rather than by `pqc-protocol`.
pub const HPKE_ML_KEM_1024: CapabilityId = CapabilityId::new(0x0102);

/// HPKE using ML-KEM-768, HKDF-SHA256, and ChaCha20-Poly1305.
///
/// This profile reuses cryptographic components already supported by the
/// implementation and is registered as a complete protocol capability.
pub const HPKE_ML_KEM_768_CHACHA20: CapabilityId = CapabilityId::new(0x0103);

/// HPKE with the ML-KEM-768 + X25519 hybrid KEM.
///
/// Cryptographic resolution of this capability is defined by the integration
/// layer rather than by `pqc-protocol`.
pub const HPKE_ML_KEM_768_X25519: CapabilityId = CapabilityId::new(0x0111);

/// Capability identifiers currently assigned by the PQC-rs protocol registry.
pub const REGISTERED_CAPABILITIES: [CapabilityId; 4] = [
    HPKE_ML_KEM_768,
    HPKE_ML_KEM_1024,
    HPKE_ML_KEM_768_CHACHA20,
    HPKE_ML_KEM_768_X25519,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_capability_ids_are_stable() {
        assert_eq!(HPKE_ML_KEM_768.value(), 0x0101);
        assert_eq!(HPKE_ML_KEM_1024.value(), 0x0102);
        assert_eq!(HPKE_ML_KEM_768_CHACHA20.value(), 0x0103);
        assert_eq!(HPKE_ML_KEM_768_X25519.value(), 0x0111);
    }

    #[test]
    fn registered_capability_ids_are_unique() {
        let mut left = 0;
        while left < REGISTERED_CAPABILITIES.len() {
            let mut right = left + 1;
            while right < REGISTERED_CAPABILITIES.len() {
                assert_ne!(
                    REGISTERED_CAPABILITIES[left],
                    REGISTERED_CAPABILITIES[right]
                );
                right += 1;
            }
            left += 1;
        }
    }
}
