//! HPKE algorithm identifiers and suite identifiers.

/// HPKE KEM identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KemId(pub u16);

/// HPKE KDF identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfId(pub u16);

impl KdfId {
    /// HKDF-SHA256.
    pub const HKDF_SHA256: Self = Self(0x0001);
    /// HKDF-SHA384.
    pub const HKDF_SHA384: Self = Self(0x0002);
    /// HKDF-SHA512.
    pub const HKDF_SHA512: Self = Self(0x0003);
}

/// HPKE AEAD identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AeadId(pub u16);

impl AeadId {
    /// AES-128-GCM.
    pub const AES_128_GCM: Self = Self(0x0001);
    /// AES-256-GCM.
    pub const AES_256_GCM: Self = Self(0x0002);
    /// ChaCha20Poly1305.
    pub const CHACHA20_POLY1305: Self = Self(0x0003);
    /// Export-only AEAD.
    pub const EXPORT_ONLY: Self = Self(0xffff);
}

/// RFC 9180 HPKE ciphersuite identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpkeSuiteId {
    /// KEM identifier.
    pub kem_id: KemId,
    /// KDF identifier.
    pub kdf_id: KdfId,
    /// AEAD identifier.
    pub aead_id: AeadId,
}

impl HpkeSuiteId {
    /// Serialize as `"HPKE" || kem_id || kdf_id || aead_id`.
    pub const fn to_bytes(self) -> [u8; 10] {
        let kem = self.kem_id.0.to_be_bytes();
        let kdf = self.kdf_id.0.to_be_bytes();
        let aead = self.aead_id.0.to_be_bytes();

        [
            b'H', b'P', b'K', b'E', kem[0], kem[1], kdf[0], kdf[1], aead[0], aead[1],
        ]
    }
}

/// KEM-local suite identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KemSuiteId {
    /// KEM identifier.
    pub kem_id: KemId,
}

impl KemSuiteId {
    /// Serialize as `"KEM" || kem_id`.
    pub const fn to_bytes(self) -> [u8; 5] {
        let kem = self.kem_id.0.to_be_bytes();
        [b'K', b'E', b'M', kem[0], kem[1]]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpke_suite_id_matches_rfc_encoding() {
        let suite = HpkeSuiteId {
            kem_id: KemId(0x0020),
            kdf_id: KdfId::HKDF_SHA256,
            aead_id: AeadId::AES_128_GCM,
        };

        assert_eq!(
            suite.to_bytes(),
            [0x48, 0x50, 0x4b, 0x45, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01]
        );
    }

    #[test]
    fn kem_suite_id_matches_rfc_encoding() {
        assert_eq!(
            KemSuiteId {
                kem_id: KemId(0x0020)
            }
            .to_bytes(),
            [0x4b, 0x45, 0x4d, 0x00, 0x20]
        );
    }
}
