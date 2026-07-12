//! RFC 9180 HPKE key schedule.

use crate::identifiers::{AeadId, HpkeSuiteId};
use crate::kdf::KdfAlgorithm;
use crate::HpkeError;

/// HPKE mode value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HpkeMode {
    /// Base mode.
    Base = 0x00,
    /// PSK mode.
    Psk = 0x01,
    /// Auth mode.
    Auth = 0x02,
    /// AuthPSK mode.
    AuthPsk = 0x03,
}

impl HpkeMode {
    /// Return the serialized one-byte mode value.
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    const fn requires_psk(self) -> bool {
        matches!(self, Self::Psk | Self::AuthPsk)
    }
}

/// AEAD key and nonce dimensions required by the key schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AeadParameters {
    /// AEAD key length `Nk`.
    pub key_length: usize,
    /// AEAD nonce length `Nn`.
    pub nonce_length: usize,
}

impl AeadParameters {
    /// Return RFC 9180 parameters for an AEAD identifier.
    pub const fn for_id(aead_id: AeadId) -> Option<Self> {
        match aead_id.0 {
            0x0001 => Some(Self {
                key_length: 16,
                nonce_length: 12,
            }),
            0x0002 => Some(Self {
                key_length: 32,
                nonce_length: 12,
            }),
            0x0003 => Some(Self {
                key_length: 32,
                nonce_length: 12,
            }),
            0xffff => Some(Self {
                key_length: 0,
                nonce_length: 0,
            }),
            _ => None,
        }
    }
}

/// RFC 9180 key-schedule inputs.
pub struct KeyScheduleInputs<'a> {
    /// HPKE mode.
    pub mode: HpkeMode,
    /// KEM shared secret.
    pub shared_secret: &'a [u8],
    /// Application-supplied HPKE `info`.
    pub info: &'a [u8],
    /// Optional pre-shared key.
    pub psk: &'a [u8],
    /// Optional pre-shared-key identifier.
    pub psk_id: &'a [u8],
}

/// RFC 9180 key-schedule output.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyScheduleOutput {
    /// AEAD key.
    pub key: Vec<u8>,
    /// Base nonce.
    pub base_nonce: Vec<u8>,
    /// Initial sequence number.
    pub sequence_number: u64,
    /// Exporter secret.
    pub exporter_secret: Vec<u8>,
    /// Serialized key-schedule context.
    pub key_schedule_context: Vec<u8>,
    /// Intermediate secret retained for validation.
    pub secret: Vec<u8>,
}

/// Verify RFC 9180 PSK input consistency.
pub fn verify_psk_inputs(mode: HpkeMode, psk: &[u8], psk_id: &[u8]) -> Result<(), HpkeError> {
    let got_psk = !psk.is_empty();
    let got_psk_id = !psk_id.is_empty();

    if got_psk != got_psk_id {
        return Err(HpkeError::InconsistentPskInputs);
    }

    if got_psk && !mode.requires_psk() {
        return Err(HpkeError::UnexpectedPsk);
    }

    if !got_psk && mode.requires_psk() {
        return Err(HpkeError::MissingPsk);
    }

    Ok(())
}

/// Execute the RFC 9180 HPKE key schedule.
pub fn key_schedule(
    suite: HpkeSuiteId,
    kdf: KdfAlgorithm,
    aead: AeadParameters,
    inputs: KeyScheduleInputs<'_>,
) -> Result<KeyScheduleOutput, HpkeError> {
    if suite.kdf_id != kdf.id() {
        return Err(HpkeError::KdfIdentifierMismatch);
    }

    verify_psk_inputs(inputs.mode, inputs.psk, inputs.psk_id)?;

    let suite_id = suite.to_bytes();
    let psk_id_hash = kdf.labeled_extract(&suite_id, b"", b"psk_id_hash", inputs.psk_id);
    let info_hash = kdf.labeled_extract(&suite_id, b"", b"info_hash", inputs.info);

    let mut key_schedule_context = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
    key_schedule_context.push(inputs.mode.as_byte());
    key_schedule_context.extend_from_slice(&psk_id_hash);
    key_schedule_context.extend_from_slice(&info_hash);

    let secret = kdf.labeled_extract(&suite_id, inputs.shared_secret, b"secret", inputs.psk);

    let key = kdf.labeled_expand(
        &suite_id,
        &secret,
        b"key",
        &key_schedule_context,
        aead.key_length,
    )?;
    let base_nonce = kdf.labeled_expand(
        &suite_id,
        &secret,
        b"base_nonce",
        &key_schedule_context,
        aead.nonce_length,
    )?;
    let exporter_secret = kdf.labeled_expand(
        &suite_id,
        &secret,
        b"exp",
        &key_schedule_context,
        kdf.hash_length(),
    )?;

    Ok(KeyScheduleOutput {
        key,
        base_nonce,
        sequence_number: 0,
        exporter_secret,
        key_schedule_context,
        secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifiers::{KdfId, KemId};

    fn suite() -> HpkeSuiteId {
        HpkeSuiteId {
            kem_id: KemId(0x0020),
            kdf_id: KdfId::HKDF_SHA256,
            aead_id: AeadId::AES_128_GCM,
        }
    }

    #[test]
    fn psk_inputs_follow_rfc_mode_rules() {
        assert_eq!(
            verify_psk_inputs(HpkeMode::Base, b"psk", b"id"),
            Err(HpkeError::UnexpectedPsk),
        );
        assert_eq!(
            verify_psk_inputs(HpkeMode::Psk, b"", b""),
            Err(HpkeError::MissingPsk),
        );
        assert_eq!(
            verify_psk_inputs(HpkeMode::Psk, b"psk", b""),
            Err(HpkeError::InconsistentPskInputs),
        );
        assert!(verify_psk_inputs(HpkeMode::Psk, b"psk", b"id").is_ok());
    }

    #[test]
    fn base_mode_known_answer() {
        let shared_secret: Vec<u8> = (0u8..32).collect();
        let output = key_schedule(
            suite(),
            KdfAlgorithm::HkdfSha256,
            AeadParameters::for_id(AeadId::AES_128_GCM).unwrap(),
            KeyScheduleInputs {
                mode: HpkeMode::Base,
                shared_secret: &shared_secret,
                info: b"stage7b1",
                psk: b"",
                psk_id: b"",
            },
        )
        .unwrap();

        assert_eq!(
            hex::encode(output.key_schedule_context),
            "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d079f23913be9bd9302a41f2a8797bcd1b104775a54d5c1511abfbaf809a9a605b8"
        );
        assert_eq!(
            hex::encode(output.secret),
            "fd43c4edc16db3816528a0662f9be842770e242a35625fa4260c082ef44e5b2e"
        );
        assert_eq!(hex::encode(output.key), "d79b34deb1cc78754a35047534c80e51");
        assert_eq!(hex::encode(output.base_nonce), "a68368fd8b85a49a7462bb66");
        assert_eq!(
            hex::encode(output.exporter_secret),
            "de4e354b82c6e5db12d7a7e23cf6e3c9a7f8c79f01ed58ef867e8265bcea5ac9"
        );
        assert_eq!(output.sequence_number, 0);
    }
}
