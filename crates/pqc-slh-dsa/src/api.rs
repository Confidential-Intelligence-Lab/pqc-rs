//! Publication-facing SLH-DSA object model.

use core::fmt;

use pqc_core::secret::SecretVec;

use crate::{SlhDsaError, SlhDsaParameterSet};

/// Parameter-bound SLH-DSA key-generation seed.
pub struct SlhDsaKeyGenSeed {
    parameter_set: SlhDsaParameterSet,
    bytes: SecretVec,
}

impl SlhDsaKeyGenSeed {
    /// Validate and take protected ownership of key-generation seed bytes.
    pub fn from_bytes(
        parameter_set: SlhDsaParameterSet,
        bytes: &[u8],
    ) -> Result<Self, SlhDsaError> {
        if bytes.len() != parameter_set.parameters().keygen_seed_bytes {
            return Err(SlhDsaError::InvalidKeyGenSeed);
        }

        Ok(Self {
            parameter_set,
            bytes: SecretVec::new(bytes.to_vec()),
        })
    }

    /// Return the parameter set bound to this seed.
    pub const fn parameter_set(&self) -> SlhDsaParameterSet {
        self.parameter_set
    }

    /// Explicitly borrow the protected seed encoding.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
}

/// Encoded, parameter-bound SLH-DSA public key.
#[derive(Clone, Eq, PartialEq)]
pub struct SlhDsaPublicKey {
    parameter_set: SlhDsaParameterSet,
    bytes: Vec<u8>,
}

impl SlhDsaPublicKey {
    /// Validate and decode a public key.
    pub fn from_bytes(
        parameter_set: SlhDsaParameterSet,
        encoded: &[u8],
    ) -> Result<Self, SlhDsaError> {
        if encoded.len() != parameter_set.parameters().public_key_bytes {
            return Err(SlhDsaError::InvalidPublicKey);
        }

        Ok(Self {
            parameter_set,
            bytes: encoded.to_vec(),
        })
    }

    /// Return the parameter set bound to this key.
    pub const fn parameter_set(&self) -> SlhDsaParameterSet {
        self.parameter_set
    }

    /// Borrow the encoded public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the wrapper and return the encoding.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Debug for SlhDsaPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlhDsaPublicKey")
            .field("parameter_set", &self.parameter_set)
            .field("bytes", &format_args!("<{} bytes>", self.bytes.len()))
            .finish()
    }
}

/// Encoded, parameter-bound SLH-DSA private key.
pub struct SlhDsaPrivateKey {
    parameter_set: SlhDsaParameterSet,
    bytes: SecretVec,
}

impl SlhDsaPrivateKey {
    /// Validate and take protected ownership of a private key.
    pub fn from_bytes(
        parameter_set: SlhDsaParameterSet,
        encoded: &[u8],
    ) -> Result<Self, SlhDsaError> {
        if encoded.len() != parameter_set.parameters().private_key_bytes {
            return Err(SlhDsaError::InvalidPrivateKey);
        }

        Ok(Self {
            parameter_set,
            bytes: SecretVec::new(encoded.to_vec()),
        })
    }

    /// Return the parameter set bound to this key.
    pub const fn parameter_set(&self) -> SlhDsaParameterSet {
        self.parameter_set
    }

    /// Explicitly borrow the protected private-key encoding.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
}

/// Encoded, parameter-bound SLH-DSA signature.
#[derive(Clone, Eq, PartialEq)]
pub struct SlhDsaSignature {
    parameter_set: SlhDsaParameterSet,
    bytes: Vec<u8>,
}

impl SlhDsaSignature {
    /// Validate and decode a signature.
    pub fn from_bytes(
        parameter_set: SlhDsaParameterSet,
        encoded: &[u8],
    ) -> Result<Self, SlhDsaError> {
        if encoded.len() != parameter_set.parameters().signature_bytes {
            return Err(SlhDsaError::InvalidSignature);
        }

        Ok(Self {
            parameter_set,
            bytes: encoded.to_vec(),
        })
    }

    /// Return the parameter set bound to this signature.
    pub const fn parameter_set(&self) -> SlhDsaParameterSet {
        self.parameter_set
    }

    /// Borrow the encoded signature.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the wrapper and return the encoding.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Debug for SlhDsaSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlhDsaSignature")
            .field("parameter_set", &self.parameter_set)
            .field("bytes", &format_args!("<{} bytes>", self.bytes.len()))
            .finish()
    }
}

/// Parameter-bound SLH-DSA key pair.
pub struct SlhDsaKeyPair {
    public_key: SlhDsaPublicKey,
    private_key: SlhDsaPrivateKey,
}

impl SlhDsaKeyPair {
    /// Borrow the public verification key.
    pub const fn public_key(&self) -> &SlhDsaPublicKey {
        &self.public_key
    }

    /// Borrow the protected private signing key.
    pub const fn private_key(&self) -> &SlhDsaPrivateKey {
        &self.private_key
    }

    /// Consume the pair and return its typed keys.
    pub fn into_parts(self) -> (SlhDsaPublicKey, SlhDsaPrivateKey) {
        (self.public_key, self.private_key)
    }
}

/// SLH-DSA implementation selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlhDsa {
    parameter_set: SlhDsaParameterSet,
}

impl SlhDsa {
    /// Construct an SLH-DSA instance.
    pub const fn new(parameter_set: SlhDsaParameterSet) -> Self {
        Self { parameter_set }
    }

    /// Return the selected parameter set.
    pub const fn parameter_set(self) -> SlhDsaParameterSet {
        self.parameter_set
    }

    /// Return the expected key-generation seed length.
    pub const fn keygen_seed_bytes(self) -> usize {
        self.parameter_set.parameters().keygen_seed_bytes
    }

    /// Return the expected public-key length.
    pub const fn public_key_bytes(self) -> usize {
        self.parameter_set.parameters().public_key_bytes
    }

    /// Return the expected private-key length.
    pub const fn private_key_bytes(self) -> usize {
        self.parameter_set.parameters().private_key_bytes
    }

    /// Return the expected signature length.
    pub const fn signature_bytes(self) -> usize {
        self.parameter_set.parameters().signature_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_objects_enforce_parameter_specific_lengths() {
        let parameter_set = SlhDsaParameterSet::Shake128s;
        let parameters = parameter_set.parameters();

        assert!(SlhDsaKeyGenSeed::from_bytes(
            parameter_set,
            &vec![0_u8; parameters.keygen_seed_bytes]
        )
        .is_ok());
        assert!(SlhDsaPublicKey::from_bytes(
            parameter_set,
            &vec![0_u8; parameters.public_key_bytes]
        )
        .is_ok());
        assert!(SlhDsaPrivateKey::from_bytes(
            parameter_set,
            &vec![0_u8; parameters.private_key_bytes]
        )
        .is_ok());
        assert!(SlhDsaSignature::from_bytes(
            parameter_set,
            &vec![0_u8; parameters.signature_bytes]
        )
        .is_ok());
    }

    #[test]
    fn typed_objects_reject_wrong_lengths() {
        let parameter_set = SlhDsaParameterSet::Sha2_256f;

        assert_eq!(
            SlhDsaKeyGenSeed::from_bytes(parameter_set, &[]).err(),
            Some(SlhDsaError::InvalidKeyGenSeed)
        );
        assert_eq!(
            SlhDsaPublicKey::from_bytes(parameter_set, &[]).err(),
            Some(SlhDsaError::InvalidPublicKey)
        );
        assert_eq!(
            SlhDsaPrivateKey::from_bytes(parameter_set, &[]).err(),
            Some(SlhDsaError::InvalidPrivateKey)
        );
        assert_eq!(
            SlhDsaSignature::from_bytes(parameter_set, &[]).err(),
            Some(SlhDsaError::InvalidSignature)
        );
    }

    #[test]
    fn selector_reports_parameter_lengths() {
        let slh_dsa = SlhDsa::new(SlhDsaParameterSet::Sha2_128s);

        assert_eq!(slh_dsa.keygen_seed_bytes(), 48);
        assert_eq!(slh_dsa.public_key_bytes(), 32);
        assert_eq!(slh_dsa.private_key_bytes(), 64);
        assert_eq!(slh_dsa.signature_bytes(), 7_856);
    }
}
