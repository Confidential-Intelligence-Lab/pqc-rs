//! Publication-facing ML-DSA API.
//!
//! This module wraps the validated FIPS 204 implementation with parameter-set
//! binding, strict encoded-object validation, explicit deterministic and
//! hedged signing operations, and zeroizing private-key ownership.

use core::fmt;

use pqc_core::{
    secret::{SecretBytes, SecretVec},
    PqcError, PqcResult, SignatureScheme,
};
use rand_core::{CryptoRng, RngCore};

use crate::hash_mldsa::{hash_sign, hash_verify, PreHashAlgorithm};
use crate::keygen::{keygen_internal, KEYGEN_SEED_BYTES};
use crate::signature::sign_internal;
use crate::signing::{decode_private_key, MAX_CONTEXT_BYTES, SIGNING_RANDOMNESS_BYTES};
use crate::verification::{decode_public_key, decode_signature, verify_internal};
use crate::{MlDsaError, MlDsaParameterSet};

/// Length in bytes of the FIPS 204 external key-generation seed `xi`.
pub const ML_DSA_KEYGEN_SEED_BYTES: usize = KEYGEN_SEED_BYTES;

/// Parameter-bound FIPS 204 key-generation seed.
///
/// This compact seed form is distinct from [`MlDsaPrivateKey`], which owns an
/// expanded private-key encoding suitable for signing. Seed bytes are zeroized
/// on drop. This type intentionally implements neither `Clone` nor `Debug`.
///
/// A seed can be expanded repeatedly when deterministic reprovisioning is
/// required:
///
/// ```
/// use pqc_ml_dsa::{MlDsaKeyGenSeed, MlDsaParameterSet};
///
/// let seed = MlDsaKeyGenSeed::from_bytes(
///     MlDsaParameterSet::MlDsa44,
///     [0x42; 32],
/// );
/// let key_pair = seed.expand().unwrap();
/// assert_eq!(key_pair.private_key().parameter_set(), MlDsaParameterSet::MlDsa44);
/// ```
///
/// Seed material cannot be cloned accidentally:
///
/// ```compile_fail
/// use pqc_ml_dsa::{MlDsaKeyGenSeed, MlDsaParameterSet};
///
/// let seed = MlDsaKeyGenSeed::from_bytes(MlDsaParameterSet::MlDsa44, [0_u8; 32]);
/// let copied = seed.clone();
/// # drop(copied);
/// ```
///
/// Seed material cannot be formatted accidentally:
///
/// ```compile_fail
/// use pqc_ml_dsa::{MlDsaKeyGenSeed, MlDsaParameterSet};
///
/// let seed = MlDsaKeyGenSeed::from_bytes(MlDsaParameterSet::MlDsa44, [0_u8; 32]);
/// println!("{seed:?}");
/// ```
pub struct MlDsaKeyGenSeed {
    parameter_set: MlDsaParameterSet,
    bytes: SecretBytes<ML_DSA_KEYGEN_SEED_BYTES>,
}

impl MlDsaKeyGenSeed {
    /// Take protected ownership of an external key-generation seed and bind it
    /// to `parameter_set`.
    pub const fn from_bytes(
        parameter_set: MlDsaParameterSet,
        bytes: [u8; ML_DSA_KEYGEN_SEED_BYTES],
    ) -> Self {
        Self {
            parameter_set,
            bytes: SecretBytes::new(bytes),
        }
    }

    /// Return the parameter set bound to this seed.
    pub const fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }

    /// Explicitly borrow the key-generation seed bytes.
    pub fn as_bytes(&self) -> &[u8; ML_DSA_KEYGEN_SEED_BYTES] {
        self.bytes.as_bytes()
    }

    /// Deterministically expand this seed into a public key and an expanded
    /// private key.
    pub fn expand(&self) -> Result<MlDsaKeyPair, MlDsaError> {
        MlDsa::new(self.parameter_set).keygen_from_seed(self)
    }
}

/// Encoded, strictly validated ML-DSA public key.
#[derive(Clone, Eq, PartialEq)]
pub struct MlDsaPublicKey {
    parameter_set: MlDsaParameterSet,
    bytes: Vec<u8>,
}

impl MlDsaPublicKey {
    /// Decode and validate a public key for `parameter_set`.
    pub fn from_bytes(
        parameter_set: MlDsaParameterSet,
        encoded: &[u8],
    ) -> Result<Self, MlDsaError> {
        decode_public_key(parameter_set, encoded)?;
        Ok(Self {
            parameter_set,
            bytes: encoded.to_vec(),
        })
    }

    /// Return the parameter set bound to this key.
    pub const fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }

    /// Borrow the canonical public-key encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the wrapper and return the canonical public-key encoding.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Debug for MlDsaPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlDsaPublicKey")
            .field("parameter_set", &self.parameter_set)
            .field("bytes", &format_args!("<{} bytes>", self.bytes.len()))
            .finish()
    }
}

/// Encoded, strictly validated, expanded ML-DSA private key.
///
/// This signing-key form is distinct from the compact [`MlDsaKeyGenSeed`]. The
/// encoded key is zeroized on drop. This type intentionally implements neither
/// `Clone` nor `Debug`.
pub struct MlDsaPrivateKey {
    parameter_set: MlDsaParameterSet,
    bytes: SecretVec,
}

impl MlDsaPrivateKey {
    /// Decode, validate, and take protected ownership of a private key.
    pub fn from_bytes(
        parameter_set: MlDsaParameterSet,
        encoded: &[u8],
    ) -> Result<Self, MlDsaError> {
        decode_private_key(parameter_set, encoded)?;
        Ok(Self {
            parameter_set,
            bytes: SecretVec::new(encoded.to_vec()),
        })
    }

    /// Return the parameter set bound to this key.
    pub const fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }

    /// Explicitly borrow the canonical private-key encoding.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
}

/// Encoded, strictly validated ML-DSA signature.
#[derive(Clone, Eq, PartialEq)]
pub struct MlDsaSignature {
    parameter_set: MlDsaParameterSet,
    bytes: Vec<u8>,
}

impl MlDsaSignature {
    /// Decode and validate a signature for `parameter_set`.
    pub fn from_bytes(
        parameter_set: MlDsaParameterSet,
        encoded: &[u8],
    ) -> Result<Self, MlDsaError> {
        decode_signature(parameter_set, encoded)?;
        Ok(Self {
            parameter_set,
            bytes: encoded.to_vec(),
        })
    }

    /// Return the parameter set bound to this signature.
    pub const fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }

    /// Borrow the canonical signature encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the wrapper and return the canonical signature encoding.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Debug for MlDsaSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlDsaSignature")
            .field("parameter_set", &self.parameter_set)
            .field("bytes", &format_args!("<{} bytes>", self.bytes.len()))
            .finish()
    }
}

/// Parameter-bound ML-DSA signing and verification key pair.
///
/// This type intentionally does not implement `Debug` because it owns a
/// private key.
pub struct MlDsaKeyPair {
    public_key: MlDsaPublicKey,
    private_key: MlDsaPrivateKey,
}

impl MlDsaKeyPair {
    /// Borrow the public verification key.
    pub const fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    /// Borrow the protected private signing key.
    pub const fn private_key(&self) -> &MlDsaPrivateKey {
        &self.private_key
    }

    /// Consume the key pair and return its two typed keys.
    pub fn into_parts(self) -> (MlDsaPublicKey, MlDsaPrivateKey) {
        (self.public_key, self.private_key)
    }
}

/// ML-DSA implementation selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlDsa {
    parameter_set: MlDsaParameterSet,
}

impl MlDsa {
    /// Construct an ML-DSA instance.
    pub const fn new(parameter_set: MlDsaParameterSet) -> Self {
        Self { parameter_set }
    }

    /// Return the selected parameter set.
    pub const fn parameter_set(self) -> MlDsaParameterSet {
        self.parameter_set
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

    /// Generate a fresh ML-DSA key pair from caller-supplied cryptographic
    /// randomness.
    pub fn keygen<R>(&self, rng: &mut R) -> Result<MlDsaKeyPair, MlDsaError>
    where
        R: CryptoRng + RngCore,
    {
        self.generate_keygen_seed(rng)?.expand()
    }

    /// Generate a fresh, parameter-bound FIPS 204 key-generation seed from
    /// caller-supplied cryptographic randomness.
    ///
    /// Applications that need only a fresh key pair should use [`Self::keygen`].
    /// This operation is for systems that intentionally retain compact seed
    /// form for deterministic reprovisioning.
    pub fn generate_keygen_seed<R>(&self, rng: &mut R) -> Result<MlDsaKeyGenSeed, MlDsaError>
    where
        R: CryptoRng + RngCore,
    {
        Ok(MlDsaKeyGenSeed {
            parameter_set: self.parameter_set,
            bytes: random_secret::<ML_DSA_KEYGEN_SEED_BYTES, R>(rng)?,
        })
    }

    /// Generate an ML-DSA key pair deterministically from the FIPS 204 seed
    /// `xi`.
    ///
    /// This operation is intended for reproducible validation and controlled
    /// deterministic provisioning. Ordinary applications should use
    /// [`Self::keygen`].
    pub fn keygen_from_seed(&self, seed: &MlDsaKeyGenSeed) -> Result<MlDsaKeyPair, MlDsaError> {
        self.ensure_parameter_set(seed.parameter_set())?;

        let generated = keygen_internal(self.parameter_set, seed.as_bytes())?;
        let (public_key, private_key) = generated.into_parts();

        // The validated core constructs canonical keys. Bind those encodings
        // to the selected parameter set while moving the private allocation
        // directly into zeroizing ownership.
        if public_key.len() != self.public_key_bytes()
            || private_key.as_bytes().len() != self.private_key_bytes()
        {
            return Err(MlDsaError::InternalError);
        }

        Ok(MlDsaKeyPair {
            public_key: MlDsaPublicKey {
                parameter_set: self.parameter_set,
                bytes: public_key,
            },
            private_key: MlDsaPrivateKey {
                parameter_set: self.parameter_set,
                bytes: private_key,
            },
        })
    }

    /// Generate a deterministic Pure ML-DSA signature.
    pub fn sign_deterministic(
        &self,
        private_key: &MlDsaPrivateKey,
        message: &[u8],
        context: &[u8],
    ) -> Result<MlDsaSignature, MlDsaError> {
        self.ensure_parameter_set(private_key.parameter_set())?;
        ensure_context_length(context)?;

        let randomness = SecretBytes::new([0_u8; SIGNING_RANDOMNESS_BYTES]);
        let encoded = sign_internal(
            self.parameter_set,
            private_key.as_bytes(),
            message,
            context,
            randomness.as_bytes(),
        )?;
        self.signature_from_core(encoded)
    }

    /// Generate a hedged Pure ML-DSA signature using fresh caller-supplied
    /// cryptographic randomness.
    pub fn sign_hedged<R>(
        &self,
        private_key: &MlDsaPrivateKey,
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> Result<MlDsaSignature, MlDsaError>
    where
        R: CryptoRng + RngCore,
    {
        self.ensure_parameter_set(private_key.parameter_set())?;
        ensure_context_length(context)?;

        let randomness = random_secret::<SIGNING_RANDOMNESS_BYTES, R>(rng)?;
        let encoded = sign_internal(
            self.parameter_set,
            private_key.as_bytes(),
            message,
            context,
            randomness.as_bytes(),
        )?;
        self.signature_from_core(encoded)
    }

    /// Verify a Pure ML-DSA signature.
    ///
    /// Returns `Ok(false)` for a well-formed signature that is not valid for
    /// the supplied key, message, and context.
    pub fn verify(
        &self,
        public_key: &MlDsaPublicKey,
        message: &[u8],
        context: &[u8],
        signature: &MlDsaSignature,
    ) -> Result<bool, MlDsaError> {
        self.ensure_parameter_set(public_key.parameter_set())?;
        self.ensure_parameter_set(signature.parameter_set())?;
        ensure_context_length(context)?;

        verify_internal(
            self.parameter_set,
            public_key.as_bytes(),
            message,
            context,
            signature.as_bytes(),
        )
        .map_err(Into::into)
    }

    /// Generate a deterministic HashML-DSA signature.
    pub fn hash_sign_deterministic(
        &self,
        private_key: &MlDsaPrivateKey,
        message: &[u8],
        context: &[u8],
        prehash: PreHashAlgorithm,
    ) -> Result<MlDsaSignature, MlDsaError> {
        self.ensure_parameter_set(private_key.parameter_set())?;
        ensure_context_length(context)?;

        let randomness = SecretBytes::new([0_u8; SIGNING_RANDOMNESS_BYTES]);
        let encoded = hash_sign(
            self.parameter_set,
            private_key.as_bytes(),
            message,
            context,
            prehash,
            randomness.as_bytes(),
        )?;
        self.signature_from_core(encoded)
    }

    /// Generate a hedged HashML-DSA signature using fresh caller-supplied
    /// cryptographic randomness.
    pub fn hash_sign_hedged<R>(
        &self,
        private_key: &MlDsaPrivateKey,
        message: &[u8],
        context: &[u8],
        prehash: PreHashAlgorithm,
        rng: &mut R,
    ) -> Result<MlDsaSignature, MlDsaError>
    where
        R: CryptoRng + RngCore,
    {
        self.ensure_parameter_set(private_key.parameter_set())?;
        ensure_context_length(context)?;

        let randomness = random_secret::<SIGNING_RANDOMNESS_BYTES, R>(rng)?;
        let encoded = hash_sign(
            self.parameter_set,
            private_key.as_bytes(),
            message,
            context,
            prehash,
            randomness.as_bytes(),
        )?;
        self.signature_from_core(encoded)
    }

    /// Verify a HashML-DSA signature.
    ///
    /// Returns `Ok(false)` for a well-formed signature that is not valid for
    /// the supplied key, message, context, and prehash algorithm.
    pub fn hash_verify(
        &self,
        public_key: &MlDsaPublicKey,
        message: &[u8],
        context: &[u8],
        prehash: PreHashAlgorithm,
        signature: &MlDsaSignature,
    ) -> Result<bool, MlDsaError> {
        self.ensure_parameter_set(public_key.parameter_set())?;
        self.ensure_parameter_set(signature.parameter_set())?;
        ensure_context_length(context)?;

        hash_verify(
            self.parameter_set,
            public_key.as_bytes(),
            message,
            context,
            prehash,
            signature.as_bytes(),
        )
        .map_err(Into::into)
    }

    fn ensure_parameter_set(&self, actual: MlDsaParameterSet) -> Result<(), MlDsaError> {
        if actual == self.parameter_set {
            Ok(())
        } else {
            Err(MlDsaError::ParameterSetMismatch)
        }
    }

    fn signature_from_core(&self, encoded: Vec<u8>) -> Result<MlDsaSignature, MlDsaError> {
        if encoded.len() != self.signature_bytes() {
            return Err(MlDsaError::InternalError);
        }

        Ok(MlDsaSignature {
            parameter_set: self.parameter_set,
            bytes: encoded,
        })
    }
}

fn ensure_context_length(context: &[u8]) -> Result<(), MlDsaError> {
    if context.len() <= MAX_CONTEXT_BYTES {
        Ok(())
    } else {
        Err(MlDsaError::ContextTooLong)
    }
}

fn random_secret<const LENGTH: usize, R>(rng: &mut R) -> Result<SecretBytes<LENGTH>, MlDsaError>
where
    R: CryptoRng + RngCore,
{
    let mut output = SecretBytes::new([0_u8; LENGTH]);
    rng.try_fill_bytes(output.as_mut_bytes())
        .map_err(|_| MlDsaError::RandomnessFailure)?;
    Ok(output)
}

impl SignatureScheme for MlDsa {
    type PublicKey = MlDsaPublicKey;
    type SecretKey = MlDsaPrivateKey;
    type Signature = MlDsaSignature;

    fn keygen<R>(&self, rng: &mut R) -> PqcResult<(Self::PublicKey, Self::SecretKey)>
    where
        R: CryptoRng + RngCore,
    {
        let key_pair = MlDsa::keygen(self, rng).map_err(map_mldsa_error)?;
        Ok(key_pair.into_parts())
    }

    fn sign<R>(
        &self,
        secret_key: &Self::SecretKey,
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> PqcResult<Self::Signature>
    where
        R: CryptoRng + RngCore,
    {
        if context.len() > MAX_CONTEXT_BYTES {
            return Err(PqcError::InvalidLength {
                expected: MAX_CONTEXT_BYTES,
                actual: context.len(),
            });
        }

        MlDsa::sign_hedged(self, secret_key, message, context, rng).map_err(map_mldsa_error)
    }

    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        context: &[u8],
        signature: &Self::Signature,
    ) -> PqcResult<()> {
        if context.len() > MAX_CONTEXT_BYTES {
            return Err(PqcError::InvalidLength {
                expected: MAX_CONTEXT_BYTES,
                actual: context.len(),
            });
        }

        match MlDsa::verify(self, public_key, message, context, signature)
            .map_err(map_mldsa_error)?
        {
            true => Ok(()),
            false => Err(PqcError::VerificationFailed),
        }
    }
}

fn map_mldsa_error(error: MlDsaError) -> PqcError {
    match error {
        MlDsaError::InvalidPublicKey
        | MlDsaError::InvalidPrivateKey
        | MlDsaError::InvalidSignature => PqcError::MalformedEncoding,

        MlDsaError::ParameterSetMismatch => PqcError::ParameterSetMismatch,

        MlDsaError::ContextTooLong => PqcError::InvalidInput,

        MlDsaError::RandomnessFailure => PqcError::RandomnessFailure,

        MlDsaError::RejectionLimitExceeded | MlDsaError::InternalError => PqcError::InternalError,
    }
}
