//! PQ/traditional hybrid KEMs for HPKE.

use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use pqc_core::secret::{SecretBytes, SecretVec};
use sha3::{
    digest::{Digest, ExtendableOutput, Update, XofReader},
    Sha3_256, Shake256,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use pqc_ml_kem::ml_kem_decaps::decaps_internal;
use pqc_ml_kem::ml_kem_encaps::encaps_internal;
use pqc_ml_kem::ml_kem_keygen::{ml_kem_1024_keygen_internal, ml_kem_768_keygen_internal};
use pqc_ml_kem::MlKemParameterSet;

use crate::identifiers::{KemId, KemSuiteId};

const VERSION_LABEL: &[u8] = b"HPKE-v1";
const DERIVE_KEY_PAIR_LABEL: &[u8] = b"DeriveKeyPair";

/// Supported PQ/traditional hybrid KEM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HybridKem {
    /// ML-KEM-768 combined with P-256.
    MlKem768P256,
    /// ML-KEM-768 combined with X25519.
    MlKem768X25519,
    /// ML-KEM-1024 combined with P-384.
    MlKem1024P384,
}

impl HybridKem {
    /// Return the pinned HPKE KEM identifier.
    pub const fn kem_id(self) -> KemId {
        match self {
            Self::MlKem768P256 => KemId(0x0050),
            Self::MlKem768X25519 => KemId(0x647a),
            Self::MlKem1024P384 => KemId(0x0051),
        }
    }

    /// Return `Nsecret`.
    pub const fn shared_secret_length(self) -> usize {
        32
    }

    /// Return `Nenc`.
    pub const fn encapsulation_length(self) -> usize {
        match self {
            Self::MlKem768P256 => 1153,
            Self::MlKem768X25519 => 1120,
            Self::MlKem1024P384 => 1665,
        }
    }

    /// Return `Npk`.
    pub const fn public_key_length(self) -> usize {
        match self {
            Self::MlKem768P256 => 1249,
            Self::MlKem768X25519 => 1216,
            Self::MlKem1024P384 => 1665,
        }
    }

    /// Return `Nsk`.
    pub const fn private_key_length(self) -> usize {
        32
    }

    /// Return deterministic encapsulation randomness length.
    pub const fn randomness_length(self) -> usize {
        match self {
            Self::MlKem768P256 => 160,
            Self::MlKem768X25519 => 64,
            Self::MlKem1024P384 => 80,
        }
    }

    /// Derive a hybrid key pair from HPKE input keying material.
    pub fn derive_key_pair(self, ikm: &[u8]) -> Result<HybridKeyPair, HybridKemError> {
        let seed = labeled_derive(self.kem_id(), ikm, DERIVE_KEY_PAIR_LABEL, b"", 32)?;
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| HybridKemError::InternalLength)?;
        self.expand_seed(seed)
    }

    /// Expand a 32-byte hybrid private seed.
    pub fn expand_seed(self, private_seed: [u8; 32]) -> Result<HybridKeyPair, HybridKemError> {
        let expanded = shake256(&private_seed, 64 + self.group_seed_length());
        let pq_seed: [u8; 64] = expanded[..64]
            .try_into()
            .map_err(|_| HybridKemError::InternalLength)?;
        let group_seed = &expanded[64..];

        let (pq_public, pq_private) = self.expand_pq_seed(pq_seed)?;
        let (traditional_private, traditional_public) = self.derive_traditional_key(group_seed)?;

        let mut public_key = Vec::with_capacity(self.public_key_length());
        public_key.extend_from_slice(&pq_public);
        public_key.extend_from_slice(&traditional_public);

        Ok(HybridKeyPair {
            private_seed: SecretBytes::new(private_seed),
            public_key,
            expanded_pq_private_key: SecretVec::new(pq_private),
            traditional_private_key: SecretVec::new(traditional_private),
        })
    }

    /// Deterministically encapsulate using the draft's `EncapsDerand`.
    pub fn encapsulate_deterministic(
        self,
        public_key: &[u8],
        randomness: &[u8],
    ) -> Result<HybridEncapsulation, HybridKemError> {
        if public_key.len() != self.public_key_length() {
            return Err(HybridKemError::InvalidPublicKeyLength);
        }
        if randomness.len() != self.randomness_length() {
            return Err(HybridKemError::InvalidRandomnessLength);
        }

        let pq_public_length = self.pq_public_key_length();
        let pq_public = &public_key[..pq_public_length];
        let traditional_public = &public_key[pq_public_length..];
        let pq_randomness: [u8; 32] = randomness[..32]
            .try_into()
            .map_err(|_| HybridKemError::InternalLength)?;
        let traditional_randomness = &randomness[32..];

        let (pq_secret, pq_ciphertext) = self.pq_encapsulate(pq_public, &pq_randomness)?;
        let (traditional_ciphertext, traditional_secret) =
            self.traditional_encapsulate(traditional_public, traditional_randomness)?;

        let shared_secret = self.combine(
            &pq_secret,
            &traditional_secret,
            &traditional_ciphertext,
            traditional_public,
        );

        let mut encapsulated_key = Vec::with_capacity(self.encapsulation_length());
        encapsulated_key.extend_from_slice(&pq_ciphertext);
        encapsulated_key.extend_from_slice(&traditional_ciphertext);

        Ok(HybridEncapsulation {
            encapsulated_key,
            shared_secret: SecretVec::new(shared_secret),
        })
    }

    /// Decapsulate a hybrid KEM ciphertext.
    pub fn decapsulate(
        self,
        private_seed: &[u8],
        encapsulated_key: &[u8],
    ) -> Result<Vec<u8>, HybridKemError> {
        if private_seed.len() != self.private_key_length() {
            return Err(HybridKemError::InvalidPrivateKeyLength);
        }
        if encapsulated_key.len() != self.encapsulation_length() {
            return Err(HybridKemError::InvalidEncapsulationLength);
        }

        let seed: [u8; 32] = private_seed
            .try_into()
            .map_err(|_| HybridKemError::InvalidPrivateKeyLength)?;
        let key_pair = self.expand_seed(seed)?;
        let pq_ciphertext_length = self.pq_ciphertext_length();
        let pq_ciphertext = &encapsulated_key[..pq_ciphertext_length];
        let traditional_ciphertext = &encapsulated_key[pq_ciphertext_length..];
        let traditional_public = &key_pair.public_key[self.pq_public_key_length()..];

        let pq_secret =
            self.pq_decapsulate(key_pair.expanded_pq_private_key.as_bytes(), pq_ciphertext)?;
        let traditional_secret = self.traditional_decapsulate(
            key_pair.traditional_private_key.as_bytes(),
            traditional_ciphertext,
        )?;

        Ok(self.combine(
            &pq_secret,
            &traditional_secret,
            traditional_ciphertext,
            traditional_public,
        ))
    }

    fn expand_pq_seed(self, seed: [u8; 64]) -> Result<(Vec<u8>, Vec<u8>), HybridKemError> {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&seed[..32]);
        z.copy_from_slice(&seed[32..]);

        match self {
            Self::MlKem768P256 | Self::MlKem768X25519 => {
                let output =
                    ml_kem_768_keygen_internal(&d, &z).map_err(|_| HybridKemError::PqOperation)?;
                Ok((
                    output.encapsulation_key.to_vec(),
                    output.decapsulation_key.to_vec(),
                ))
            }
            Self::MlKem1024P384 => {
                let output =
                    ml_kem_1024_keygen_internal(&d, &z).map_err(|_| HybridKemError::PqOperation)?;
                Ok((
                    output.encapsulation_key.to_vec(),
                    output.decapsulation_key.to_vec(),
                ))
            }
        }
    }

    fn pq_encapsulate(
        self,
        public_key: &[u8],
        randomness: &[u8; 32],
    ) -> Result<(Vec<u8>, Vec<u8>), HybridKemError> {
        let output = encaps_internal(self.parameter_set(), public_key, randomness)
            .map_err(|_| HybridKemError::PqOperation)?;
        Ok((output.shared_secret.as_bytes().to_vec(), output.ciphertext))
    }

    fn pq_decapsulate(
        self,
        private_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HybridKemError> {
        let output = decaps_internal(self.parameter_set(), private_key, ciphertext)
            .map_err(|_| HybridKemError::PqOperation)?;
        Ok(output.shared_secret.as_bytes().to_vec())
    }

    fn derive_traditional_key(self, seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HybridKemError> {
        match self {
            Self::MlKem768X25519 => {
                let scalar: [u8; 32] = seed
                    .try_into()
                    .map_err(|_| HybridKemError::TraditionalOperation)?;
                let secret = StaticSecret::from(scalar);
                let public = X25519PublicKey::from(&secret);
                Ok((secret.to_bytes().to_vec(), public.as_bytes().to_vec()))
            }
            Self::MlKem768P256 => {
                let secret = select_p256_scalar(seed)?;
                let public = secret.public_key();
                Ok((
                    secret.to_bytes().to_vec(),
                    public.to_encoded_point(false).as_bytes().to_vec(),
                ))
            }
            Self::MlKem1024P384 => {
                let secret = p384::SecretKey::from_slice(seed)
                    .map_err(|_| HybridKemError::TraditionalOperation)?;
                let public = secret.public_key();
                Ok((
                    secret.to_bytes().to_vec(),
                    public.to_encoded_point(false).as_bytes().to_vec(),
                ))
            }
        }
    }

    fn traditional_encapsulate(
        self,
        recipient_public: &[u8],
        randomness: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), HybridKemError> {
        match self {
            Self::MlKem768X25519 => {
                let scalar: [u8; 32] = randomness
                    .try_into()
                    .map_err(|_| HybridKemError::TraditionalOperation)?;
                let ephemeral = StaticSecret::from(scalar);
                let ciphertext = X25519PublicKey::from(&ephemeral);
                let recipient_bytes: [u8; 32] = recipient_public
                    .try_into()
                    .map_err(|_| HybridKemError::TraditionalOperation)?;
                let recipient = X25519PublicKey::from(recipient_bytes);
                let shared = ephemeral.diffie_hellman(&recipient);
                if shared.as_bytes().iter().all(|byte| *byte == 0) {
                    return Err(HybridKemError::TraditionalOperation);
                }
                Ok((ciphertext.as_bytes().to_vec(), shared.as_bytes().to_vec()))
            }
            Self::MlKem768P256 => {
                let ephemeral = select_p256_scalar(randomness)?;
                let recipient = p256::PublicKey::from_sec1_bytes(recipient_public)
                    .map_err(|_| HybridKemError::TraditionalOperation)?;
                let shared = p256::ecdh::diffie_hellman(
                    ephemeral.to_nonzero_scalar(),
                    recipient.as_affine(),
                );
                Ok((
                    ephemeral
                        .public_key()
                        .to_encoded_point(false)
                        .as_bytes()
                        .to_vec(),
                    shared.raw_secret_bytes().to_vec(),
                ))
            }
            Self::MlKem1024P384 => {
                let ephemeral = p384::SecretKey::from_slice(randomness)
                    .map_err(|_| HybridKemError::TraditionalOperation)?;
                let recipient = p384::PublicKey::from_sec1_bytes(recipient_public)
                    .map_err(|_| HybridKemError::TraditionalOperation)?;
                let shared = p384::ecdh::diffie_hellman(
                    ephemeral.to_nonzero_scalar(),
                    recipient.as_affine(),
                );
                Ok((
                    ephemeral
                        .public_key()
                        .to_encoded_point(false)
                        .as_bytes()
                        .to_vec(),
                    shared.raw_secret_bytes().to_vec(),
                ))
            }
        }
    }

    fn traditional_decapsulate(
        self,
        private_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HybridKemError> {
        match self {
            Self::MlKem768X25519 => {
                let scalar: [u8; 32] = private_key
                    .try_into()
                    .map_err(|_| HybridKemError::TraditionalOperation)?;
                let secret = StaticSecret::from(scalar);
                let peer_bytes: [u8; 32] = ciphertext
                    .try_into()
                    .map_err(|_| HybridKemError::TraditionalOperation)?;
                let peer = X25519PublicKey::from(peer_bytes);
                let shared = secret.diffie_hellman(&peer);
                if shared.as_bytes().iter().all(|byte| *byte == 0) {
                    return Err(HybridKemError::TraditionalOperation);
                }
                Ok(shared.as_bytes().to_vec())
            }
            Self::MlKem768P256 => {
                let secret = p256::SecretKey::from_slice(private_key)
                    .map_err(|_| HybridKemError::TraditionalOperation)?;
                let peer = p256::PublicKey::from_sec1_bytes(ciphertext)
                    .map_err(|_| HybridKemError::TraditionalOperation)?;
                Ok(
                    p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine())
                        .raw_secret_bytes()
                        .to_vec(),
                )
            }
            Self::MlKem1024P384 => {
                let secret = p384::SecretKey::from_slice(private_key)
                    .map_err(|_| HybridKemError::TraditionalOperation)?;
                let peer = p384::PublicKey::from_sec1_bytes(ciphertext)
                    .map_err(|_| HybridKemError::TraditionalOperation)?;
                Ok(
                    p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine())
                        .raw_secret_bytes()
                        .to_vec(),
                )
            }
        }
    }

    fn combine(
        self,
        pq_secret: &[u8],
        traditional_secret: &[u8],
        traditional_ciphertext: &[u8],
        traditional_public_key: &[u8],
    ) -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(pq_secret);
        input.extend_from_slice(traditional_secret);
        input.extend_from_slice(traditional_ciphertext);
        input.extend_from_slice(traditional_public_key);
        input.extend_from_slice(self.label());
        Sha3_256::digest(&input).to_vec()
    }

    const fn parameter_set(self) -> MlKemParameterSet {
        match self {
            Self::MlKem768P256 | Self::MlKem768X25519 => MlKemParameterSet::MlKem768,
            Self::MlKem1024P384 => MlKemParameterSet::MlKem1024,
        }
    }

    const fn pq_public_key_length(self) -> usize {
        match self {
            Self::MlKem768P256 | Self::MlKem768X25519 => 1184,
            Self::MlKem1024P384 => 1568,
        }
    }

    const fn pq_ciphertext_length(self) -> usize {
        match self {
            Self::MlKem768P256 | Self::MlKem768X25519 => 1088,
            Self::MlKem1024P384 => 1568,
        }
    }

    const fn group_seed_length(self) -> usize {
        match self {
            Self::MlKem768P256 => 128,
            Self::MlKem768X25519 => 32,
            Self::MlKem1024P384 => 48,
        }
    }

    const fn label(self) -> &'static [u8] {
        match self {
            Self::MlKem768P256 => b"MLKEM768-P256",
            Self::MlKem768X25519 => b"\\.//^\\",
            Self::MlKem1024P384 => b"MLKEM1024-P384",
        }
    }
}

/// Expanded hybrid key pair.
pub struct HybridKeyPair {
    /// Serialized 32-byte hybrid private key seed.
    pub private_seed: SecretBytes<32>,
    /// Serialized hybrid public key.
    pub public_key: Vec<u8>,
    expanded_pq_private_key: SecretVec,
    traditional_private_key: SecretVec,
}

/// Deterministic hybrid encapsulation output.
pub struct HybridEncapsulation {
    /// Serialized hybrid ciphertext.
    pub encapsulated_key: Vec<u8>,
    /// 32-byte combined KEM shared secret.
    pub shared_secret: SecretVec,
}

/// Hybrid KEM error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HybridKemError {
    /// Public key length is invalid.
    InvalidPublicKeyLength,
    /// Private seed length is invalid.
    InvalidPrivateKeyLength,
    /// Encapsulation length is invalid.
    InvalidEncapsulationLength,
    /// Deterministic randomness length is invalid.
    InvalidRandomnessLength,
    /// Internal fixed-length conversion failed.
    InternalLength,
    /// Labeled derivation input is too long.
    InputTooLong,
    /// Labeled derivation output is too long.
    OutputTooLong,
    /// ML-KEM operation failed.
    PqOperation,
    /// Traditional group operation failed.
    TraditionalOperation,
}

impl core::fmt::Display for HybridKemError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPublicKeyLength => "invalid hybrid public key length",
            Self::InvalidPrivateKeyLength => "invalid hybrid private key length",
            Self::InvalidEncapsulationLength => "invalid hybrid encapsulation length",
            Self::InvalidRandomnessLength => "invalid hybrid randomness length",
            Self::InternalLength => "internal fixed-length conversion failed",
            Self::InputTooLong => "labeled derivation input is too long",
            Self::OutputTooLong => "labeled derivation output is too long",
            Self::PqOperation => "ML-KEM component operation failed",
            Self::TraditionalOperation => "traditional component operation failed",
        })
    }
}

impl std::error::Error for HybridKemError {}

fn select_p256_scalar(seed: &[u8]) -> Result<p256::SecretKey, HybridKemError> {
    for candidate in seed.chunks_exact(32) {
        if let Ok(secret) = p256::SecretKey::from_slice(candidate) {
            return Ok(secret);
        }
    }
    Err(HybridKemError::TraditionalOperation)
}

fn shake256(input: &[u8], length: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; length];
    reader.read(&mut output);
    output
}

fn labeled_derive(
    kem_id: KemId,
    ikm: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, HybridKemError> {
    let label_length = u16::try_from(label.len()).map_err(|_| HybridKemError::InputTooLong)?;
    let output_length = u16::try_from(length).map_err(|_| HybridKemError::OutputTooLong)?;
    let suite_id = KemSuiteId { kem_id }.to_bytes();

    let mut input = Vec::new();
    input.extend_from_slice(ikm);
    input.extend_from_slice(VERSION_LABEL);
    input.extend_from_slice(&suite_id);
    input.extend_from_slice(&label_length.to_be_bytes());
    input.extend_from_slice(label);
    input.extend_from_slice(&output_length.to_be_bytes());
    input.extend_from_slice(context);
    Ok(shake256(&input, length))
}
