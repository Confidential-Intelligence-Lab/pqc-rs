//! Pure ML-KEM adapters for the HPKE KEM interface.
//!
//! This module follows `draft-ietf-hpke-pq-05` and keeps ML-KEM
//! decapsulation keys in the draft's 64-byte seed format.

use pqc_ml_kem::ml_kem_decaps::decaps_internal;
use pqc_ml_kem::ml_kem_encaps::encaps_internal;
use pqc_ml_kem::ml_kem_key_check::{decapsulation_key_is_valid, encapsulation_key_is_valid};
use pqc_ml_kem::ml_kem_keygen::{
    ml_kem_1024_keygen_internal, ml_kem_512_keygen_internal, ml_kem_768_keygen_internal,
};
use pqc_ml_kem::MlKemParameterSet;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::identifiers::{KemId, KemSuiteId};

const VERSION_LABEL: &[u8] = b"HPKE-v1";
const DERIVE_KEY_PAIR_LABEL: &[u8] = b"DeriveKeyPair";

/// ML-KEM KEM configuration for HPKE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlKemHpke {
    /// ML-KEM-512, KEM ID `0x0040`.
    MlKem512,
    /// ML-KEM-768, KEM ID `0x0041`.
    MlKem768,
    /// ML-KEM-1024, KEM ID `0x0042`.
    MlKem1024,
}

impl MlKemHpke {
    /// Return the HPKE KEM identifier.
    pub const fn kem_id(self) -> KemId {
        match self {
            Self::MlKem512 => KemId(0x0040),
            Self::MlKem768 => KemId(0x0041),
            Self::MlKem1024 => KemId(0x0042),
        }
    }

    /// Return the corresponding FIPS 203 parameter set.
    pub const fn parameter_set(self) -> MlKemParameterSet {
        match self {
            Self::MlKem512 => MlKemParameterSet::MlKem512,
            Self::MlKem768 => MlKemParameterSet::MlKem768,
            Self::MlKem1024 => MlKemParameterSet::MlKem1024,
        }
    }

    /// Return the HPKE KEM suite identifier.
    pub const fn suite_id(self) -> [u8; 5] {
        KemSuiteId {
            kem_id: self.kem_id(),
        }
        .to_bytes()
    }

    /// Return `Nsecret`.
    pub const fn shared_secret_length(self) -> usize {
        32
    }

    /// Return `Nenc`.
    pub const fn encapsulation_length(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// Return `Npk`.
    pub const fn public_key_length(self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Return `Nsk`.
    ///
    /// The HPKE adapter uses the 64-byte seed format `d || z`.
    pub const fn private_key_length(self) -> usize {
        64
    }

    /// Deterministically derive an HPKE ML-KEM key pair from `ikm`.
    pub fn derive_key_pair(self, ikm: &[u8]) -> Result<MlKemHpkeKeyPair, MlKemHpkeError> {
        let seed =
            self.labeled_derive(ikm, DERIVE_KEY_PAIR_LABEL, b"", self.private_key_length())?;
        let seed: [u8; 64] = seed
            .try_into()
            .map_err(|_| MlKemHpkeError::InternalLength)?;
        self.expand_seed_private_key(seed)
    }

    /// Expand a 64-byte seed-format private key into the public key and
    /// the FIPS 203 expanded decapsulation key.
    pub fn expand_seed_private_key(
        self,
        private_key_seed: [u8; 64],
    ) -> Result<MlKemHpkeKeyPair, MlKemHpkeError> {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&private_key_seed[..32]);
        z.copy_from_slice(&private_key_seed[32..]);

        let (public_key, expanded_private_key) = match self {
            Self::MlKem512 => {
                let output = ml_kem_512_keygen_internal(&d, &z)
                    .map_err(|_| MlKemHpkeError::KeyGeneration)?;
                (
                    output.encapsulation_key.to_vec(),
                    output.decapsulation_key.to_vec(),
                )
            }
            Self::MlKem768 => {
                let output = ml_kem_768_keygen_internal(&d, &z)
                    .map_err(|_| MlKemHpkeError::KeyGeneration)?;
                (
                    output.encapsulation_key.to_vec(),
                    output.decapsulation_key.to_vec(),
                )
            }
            Self::MlKem1024 => {
                let output = ml_kem_1024_keygen_internal(&d, &z)
                    .map_err(|_| MlKemHpkeError::KeyGeneration)?;
                (
                    output.encapsulation_key.to_vec(),
                    output.decapsulation_key.to_vec(),
                )
            }
        };

        Ok(MlKemHpkeKeyPair {
            private_key_seed,
            public_key,
            expanded_private_key,
        })
    }

    /// Deterministically encapsulate with the supplied 32-byte ML-KEM
    /// randomness input.
    ///
    /// A randomized HPKE `Encap` API can generate this input and then
    /// delegate to this function.
    pub fn encapsulate_deterministic(
        self,
        public_key: &[u8],
        randomness: &[u8; 32],
    ) -> Result<MlKemHpkeEncapsulation, MlKemHpkeError> {
        if !encapsulation_key_is_valid(self.parameter_set(), public_key) {
            return Err(MlKemHpkeError::EncapError);
        }

        let output = encaps_internal(self.parameter_set(), public_key, randomness)
            .map_err(|_| MlKemHpkeError::EncapError)?;

        Ok(MlKemHpkeEncapsulation {
            encapsulated_key: output.ciphertext,
            shared_secret: output.shared_secret.as_bytes().to_vec(),
        })
    }

    /// Decapsulate using the 64-byte seed-format HPKE private key.
    pub fn decapsulate(
        self,
        private_key_seed: &[u8],
        encapsulated_key: &[u8],
    ) -> Result<Vec<u8>, MlKemHpkeError> {
        if private_key_seed.len() != self.private_key_length() {
            return Err(MlKemHpkeError::InvalidPrivateKeyLength);
        }

        if encapsulated_key.len() != self.encapsulation_length() {
            return Err(MlKemHpkeError::InvalidEncapsulationLength);
        }

        let seed: [u8; 64] = private_key_seed
            .try_into()
            .map_err(|_| MlKemHpkeError::InvalidPrivateKeyLength)?;
        let key_pair = self.expand_seed_private_key(seed)?;

        if !decapsulation_key_is_valid(self.parameter_set(), &key_pair.expanded_private_key) {
            return Err(MlKemHpkeError::DecapError);
        }

        let output = decaps_internal(
            self.parameter_set(),
            &key_pair.expanded_private_key,
            encapsulated_key,
        )
        .map_err(|_| MlKemHpkeError::DecapError)?;

        Ok(output.shared_secret.as_bytes().to_vec())
    }

    /// Identity serialization for a public key.
    pub fn serialize_public_key(self, public_key: &[u8]) -> Result<&[u8], MlKemHpkeError> {
        if public_key.len() != self.public_key_length() {
            return Err(MlKemHpkeError::InvalidPublicKeyLength);
        }
        Ok(public_key)
    }

    /// Identity serialization for the 64-byte seed private key.
    pub fn serialize_private_key(self, private_key_seed: &[u8]) -> Result<&[u8], MlKemHpkeError> {
        if private_key_seed.len() != self.private_key_length() {
            return Err(MlKemHpkeError::InvalidPrivateKeyLength);
        }
        Ok(private_key_seed)
    }

    fn labeled_derive(
        self,
        ikm: &[u8],
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, MlKemHpkeError> {
        let label_length = u16::try_from(label.len()).map_err(|_| MlKemHpkeError::InputTooLong)?;
        let output_length = u16::try_from(length).map_err(|_| MlKemHpkeError::OutputTooLong)?;

        let suite_id = self.suite_id();
        let mut input = Vec::with_capacity(
            ikm.len() + VERSION_LABEL.len() + suite_id.len() + 2 + label.len() + 2 + context.len(),
        );
        input.extend_from_slice(ikm);
        input.extend_from_slice(VERSION_LABEL);
        input.extend_from_slice(&suite_id);
        input.extend_from_slice(&label_length.to_be_bytes());
        input.extend_from_slice(label);
        input.extend_from_slice(&output_length.to_be_bytes());
        input.extend_from_slice(context);

        let mut hasher = Shake256::default();
        hasher.update(&input);
        let mut reader = hasher.finalize_xof();
        let mut output = vec![0u8; length];
        reader.read(&mut output);
        Ok(output)
    }
}

/// ML-KEM HPKE key pair.
#[derive(Clone, Eq, PartialEq)]
pub struct MlKemHpkeKeyPair {
    /// HPKE private key in the 64-byte seed format `d || z`.
    pub private_key_seed: [u8; 64],
    /// Serialized ML-KEM encapsulation key.
    pub public_key: Vec<u8>,
    /// Expanded FIPS 203 decapsulation key, retained internally.
    pub expanded_private_key: Vec<u8>,
}

/// Deterministic ML-KEM HPKE encapsulation output.
#[derive(Clone, Eq, PartialEq)]
pub struct MlKemHpkeEncapsulation {
    /// HPKE `enc` value.
    pub encapsulated_key: Vec<u8>,
    /// HPKE KEM shared secret.
    pub shared_secret: Vec<u8>,
}

/// ML-KEM HPKE adapter error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlKemHpkeError {
    /// Public key length is invalid.
    InvalidPublicKeyLength,
    /// Private key length is invalid.
    InvalidPrivateKeyLength,
    /// Encapsulation length is invalid.
    InvalidEncapsulationLength,
    /// Input exceeds the labeled-derive encoding limit.
    InputTooLong,
    /// Output exceeds the labeled-derive encoding limit.
    OutputTooLong,
    /// Internal fixed-length conversion failed.
    InternalLength,
    /// ML-KEM key generation failed.
    KeyGeneration,
    /// HPKE encapsulation failed.
    EncapError,
    /// HPKE decapsulation failed.
    DecapError,
}

impl core::fmt::Display for MlKemHpkeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::InvalidPublicKeyLength => "invalid ML-KEM public key length",
            Self::InvalidPrivateKeyLength => "invalid ML-KEM private key length",
            Self::InvalidEncapsulationLength => "invalid ML-KEM encapsulation length",
            Self::InputTooLong => "labeled-derive input is too long",
            Self::OutputTooLong => "labeled-derive output is too long",
            Self::InternalLength => "internal fixed-length conversion failed",
            Self::KeyGeneration => "ML-KEM key generation failed",
            Self::EncapError => "ML-KEM HPKE encapsulation failed",
            Self::DecapError => "ML-KEM HPKE decapsulation failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for MlKemHpkeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_and_sizes_match_pinned_draft() {
        let cases = [
            (MlKemHpke::MlKem512, 0x0040, 768, 800),
            (MlKemHpke::MlKem768, 0x0041, 1088, 1184),
            (MlKemHpke::MlKem1024, 0x0042, 1568, 1568),
        ];

        for (kem, id, nenc, npk) in cases {
            assert_eq!(kem.kem_id(), KemId(id));
            assert_eq!(kem.shared_secret_length(), 32);
            assert_eq!(kem.encapsulation_length(), nenc);
            assert_eq!(kem.public_key_length(), npk);
            assert_eq!(kem.private_key_length(), 64);
        }
    }

    #[test]
    fn labeled_derive_known_answer() {
        let ikm: Vec<u8> = (0u8..64).collect();
        let key_pair = MlKemHpke::MlKem768.derive_key_pair(&ikm).unwrap();

        assert_eq!(
            hex::encode(key_pair.private_key_seed),
            "555f04d397d64a045cf078dbc8c403b1e576906ef3ec8f21fdd773a79f4cbb2e2c49fdc93efc5e57b42d4932ca4270041ccf255b1a25d21c01f89790ef04e091"
        );
    }

    #[test]
    fn deterministic_encapsulation_round_trips() {
        let ikm = [0x11u8; 64];
        let randomness = [0x22u8; 32];

        for kem in [
            MlKemHpke::MlKem512,
            MlKemHpke::MlKem768,
            MlKemHpke::MlKem1024,
        ] {
            let key_pair = kem.derive_key_pair(&ikm).unwrap();
            let encapsulation = kem
                .encapsulate_deterministic(&key_pair.public_key, &randomness)
                .unwrap();
            let recovered = kem
                .decapsulate(&key_pair.private_key_seed, &encapsulation.encapsulated_key)
                .unwrap();

            assert_eq!(recovered, encapsulation.shared_secret);
        }
    }

    #[test]
    fn serialization_is_identity_with_length_checks() {
        let key_pair = MlKemHpke::MlKem512.derive_key_pair(&[0x44u8; 64]).unwrap();

        assert_eq!(
            MlKemHpke::MlKem512
                .serialize_public_key(&key_pair.public_key)
                .unwrap(),
            key_pair.public_key
        );
        assert_eq!(
            MlKemHpke::MlKem512
                .serialize_private_key(&key_pair.private_key_seed)
                .unwrap(),
            key_pair.private_key_seed
        );
    }
}
