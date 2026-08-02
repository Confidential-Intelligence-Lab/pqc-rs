//! Publication-facing SLH-DSA object model.

use core::fmt;

use pqc_core::secret::SecretVec;
use rand_core::{CryptoRng, RngCore};

use crate::{
    address::{Address, AddressType},
    fors,
    hash_suite::HashSuite,
    hypertree::{self, HypertreePosition},
    message_digest::parse_message_digest,
    xmss, SlhDsaError, SlhDsaParameterSet,
};

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

    /// Generate a fresh SLH-DSA key pair using caller-supplied
    /// cryptographic randomness.
    pub fn keygen<R>(&self, rng: &mut R) -> Result<SlhDsaKeyPair, SlhDsaError>
    where
        R: CryptoRng + RngCore,
    {
        let seed = self.generate_keygen_seed(rng)?;
        self.keygen_from_seed(&seed)
    }

    /// Generate a fresh parameter-bound SLH-DSA key-generation seed.
    ///
    /// The returned seed contains `SK.seed || SK.prf || PK.seed` and can be
    /// retained for deterministic reprovisioning through
    /// [`Self::keygen_from_seed`].
    pub fn generate_keygen_seed<R>(&self, rng: &mut R) -> Result<SlhDsaKeyGenSeed, SlhDsaError>
    where
        R: CryptoRng + RngCore,
    {
        let mut bytes = vec![0_u8; self.keygen_seed_bytes()];

        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| SlhDsaError::RandomnessFailure)?;

        SlhDsaKeyGenSeed::from_bytes(self.parameter_set, &bytes)
    }

    /// Generate a deterministic Pure SLH-DSA signature.
    ///
    /// The message supplied to the internal FIPS 205 signing algorithm is:
    ///
    /// `0x00 || len(context) || context || message`.
    ///
    /// Deterministic signing uses `PK.seed` as the optional randomization
    /// input to `PRF_msg`.
    pub fn sign_deterministic(
        &self,
        private_key: &SlhDsaPrivateKey,
        message: &[u8],
        context: &[u8],
    ) -> Result<SlhDsaSignature, SlhDsaError> {
        self.ensure_private_key_parameter_set(private_key)?;
        self.ensure_context_length(context)?;

        let parameters = self.parameter_set.parameters();
        let encoded_key = private_key.as_bytes();

        if encoded_key.len() != parameters.private_key_bytes {
            return Err(SlhDsaError::InvalidPrivateKey);
        }

        let public_seed = &encoded_key[2 * parameters.n..3 * parameters.n];

        let encoded_message = Self::encode_external_message(message, context)?;

        self.sign_with_randomness(private_key, &encoded_message, public_seed)
    }

    /// Generate a hedged Pure SLH-DSA signature.
    ///
    /// The caller-supplied cryptographic RNG generates the `n`-byte
    /// `opt_rand` input to `PRF_msg`.
    pub fn sign_hedged<R>(
        &self,
        private_key: &SlhDsaPrivateKey,
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> Result<SlhDsaSignature, SlhDsaError>
    where
        R: CryptoRng + RngCore,
    {
        self.ensure_private_key_parameter_set(private_key)?;
        self.ensure_context_length(context)?;

        let parameters = self.parameter_set.parameters();
        let mut optional_randomness = vec![0_u8; parameters.n];

        rng.try_fill_bytes(&mut optional_randomness)
            .map_err(|_| SlhDsaError::RandomnessFailure)?;

        let encoded_message = Self::encode_external_message(message, context)?;

        self.sign_with_randomness(private_key, &encoded_message, &optional_randomness)
    }

    /// Sign a FIPS 205 internal-interface message deterministically.
    ///
    /// This entry point exists for conformance validation. Unlike the public
    /// Pure SLH-DSA interface, the supplied message is passed directly to the
    /// internal signing algorithm without external-interface framing.
    #[cfg(feature = "internal-api")]
    #[doc(hidden)]
    pub fn sign_internal_deterministic(
        &self,
        private_key: &SlhDsaPrivateKey,
        message: &[u8],
    ) -> Result<SlhDsaSignature, SlhDsaError> {
        self.ensure_private_key_parameter_set(private_key)?;

        let parameters = self.parameter_set.parameters();
        let encoded_key = private_key.as_bytes();

        if encoded_key.len() != parameters.private_key_bytes {
            return Err(SlhDsaError::InvalidPrivateKey);
        }

        let public_seed = &encoded_key[2 * parameters.n..3 * parameters.n];

        self.sign_with_randomness(private_key, message, public_seed)
    }

    /// Sign a FIPS 205 internal-interface message with hedged randomness.
    ///
    /// This entry point exists for conformance validation.
    #[cfg(feature = "internal-api")]
    #[doc(hidden)]
    pub fn sign_internal_hedged<R>(
        &self,
        private_key: &SlhDsaPrivateKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<SlhDsaSignature, SlhDsaError>
    where
        R: CryptoRng + RngCore,
    {
        self.ensure_private_key_parameter_set(private_key)?;

        let parameters = self.parameter_set.parameters();
        let mut optional_randomness = vec![0_u8; parameters.n];

        rng.try_fill_bytes(&mut optional_randomness)
            .map_err(|_| SlhDsaError::RandomnessFailure)?;

        self.sign_with_randomness(private_key, message, &optional_randomness)
    }

    fn sign_with_randomness(
        &self,
        private_key: &SlhDsaPrivateKey,
        encoded_message: &[u8],
        optional_randomness: &[u8],
    ) -> Result<SlhDsaSignature, SlhDsaError> {
        let parameters = self.parameter_set.parameters();
        let encoded_key = private_key.as_bytes();

        if encoded_key.len() != parameters.private_key_bytes {
            return Err(SlhDsaError::InvalidPrivateKey);
        }

        if optional_randomness.len() != parameters.n {
            return Err(SlhDsaError::InternalError);
        }

        let secret_seed = &encoded_key[..parameters.n];
        let secret_prf = &encoded_key[parameters.n..2 * parameters.n];
        let public_seed = &encoded_key[2 * parameters.n..3 * parameters.n];
        let public_root = &encoded_key[3 * parameters.n..4 * parameters.n];

        let suite = HashSuite::new(&parameters);
        let mut randomizer = vec![0_u8; parameters.n];

        suite
            .prf_msg(
                secret_prf,
                optional_randomness,
                encoded_message,
                &mut randomizer,
            )
            .map_err(|_| SlhDsaError::InternalError)?;

        let mut digest = vec![0_u8; parameters.m];

        suite
            .h_msg(
                &randomizer,
                public_seed,
                public_root,
                encoded_message,
                &mut digest,
            )
            .map_err(|_| SlhDsaError::InternalError)?;

        let parsed =
            parse_message_digest(&parameters, &digest).map_err(|_| SlhDsaError::InternalError)?;

        let fors_bytes =
            fors::signature_bytes(&parameters).map_err(|_| SlhDsaError::InternalError)?;

        let hypertree_bytes =
            hypertree::signature_bytes(&parameters).map_err(|_| SlhDsaError::InternalError)?;

        let fors_start = parameters.n;
        let fors_end = fors_start
            .checked_add(fors_bytes)
            .ok_or(SlhDsaError::InternalError)?;

        let hypertree_end = fors_end
            .checked_add(hypertree_bytes)
            .ok_or(SlhDsaError::InternalError)?;

        if hypertree_end != parameters.signature_bytes {
            return Err(SlhDsaError::InternalError);
        }

        let mut encoded_signature = vec![0_u8; parameters.signature_bytes];

        encoded_signature[..parameters.n].copy_from_slice(&randomizer);

        let mut fors_address = Address::new();
        fors_address.set_tree_address(parsed.tree_index);
        fors_address.set_type_and_clear(AddressType::ForsTree);
        fors_address.set_key_pair_address(parsed.leaf_index);

        fors::sign(
            &parameters,
            parsed.fors_digest,
            secret_seed,
            public_seed,
            &fors_address,
            parsed.leaf_index,
            &mut encoded_signature[fors_start..fors_end],
        )
        .map_err(|_| SlhDsaError::InternalError)?;

        let mut fors_public_key = vec![0_u8; parameters.n];

        fors::public_key_from_signature(
            &parameters,
            &encoded_signature[fors_start..fors_end],
            parsed.fors_digest,
            public_seed,
            &fors_address,
            parsed.leaf_index,
            &mut fors_public_key,
        )
        .map_err(|_| SlhDsaError::InternalError)?;

        hypertree::sign(
            &parameters,
            secret_seed,
            public_seed,
            &fors_public_key,
            parsed.tree_index,
            parsed.leaf_index,
            &mut encoded_signature[fors_end..hypertree_end],
        )
        .map_err(|_| SlhDsaError::InternalError)?;

        SlhDsaSignature::from_bytes(self.parameter_set, &encoded_signature)
    }

    fn ensure_private_key_parameter_set(
        &self,
        private_key: &SlhDsaPrivateKey,
    ) -> Result<(), SlhDsaError> {
        if private_key.parameter_set() == self.parameter_set {
            Ok(())
        } else {
            Err(SlhDsaError::ParameterSetMismatch)
        }
    }

    fn ensure_context_length(&self, context: &[u8]) -> Result<(), SlhDsaError> {
        if context.len() <= u8::MAX as usize {
            Ok(())
        } else {
            Err(SlhDsaError::ContextTooLong)
        }
    }

    fn encode_external_message(message: &[u8], context: &[u8]) -> Result<Vec<u8>, SlhDsaError> {
        let encoded_length = 2_usize
            .checked_add(context.len())
            .and_then(|length| length.checked_add(message.len()))
            .ok_or(SlhDsaError::InternalError)?;

        let mut encoded = Vec::with_capacity(encoded_length);
        encoded.push(0);
        encoded.push(u8::try_from(context.len()).map_err(|_| SlhDsaError::ContextTooLong)?);
        encoded.extend_from_slice(context);
        encoded.extend_from_slice(message);

        Ok(encoded)
    }

    /// Verify a Pure SLH-DSA signature.
    ///
    /// Returns `Ok(false)` when the signature is structurally well formed but
    /// does not authenticate the supplied public key, message, and context.
    pub fn verify(
        &self,
        public_key: &SlhDsaPublicKey,
        message: &[u8],
        context: &[u8],
        signature: &SlhDsaSignature,
    ) -> Result<bool, SlhDsaError> {
        self.ensure_context_length(context)?;

        let encoded_message = Self::encode_external_message(message, context)?;

        self.verify_encoded_message(public_key, &encoded_message, signature)
    }

    /// Verify a FIPS 205 internal-interface signature.
    ///
    /// This entry point exists for conformance validation and passes the
    /// supplied message directly to the internal verification algorithm.
    #[cfg(feature = "internal-api")]
    #[doc(hidden)]
    pub fn verify_internal(
        &self,
        public_key: &SlhDsaPublicKey,
        message: &[u8],
        signature: &SlhDsaSignature,
    ) -> Result<bool, SlhDsaError> {
        self.verify_encoded_message(public_key, message, signature)
    }

    fn verify_encoded_message(
        &self,
        public_key: &SlhDsaPublicKey,
        encoded_message: &[u8],
        signature: &SlhDsaSignature,
    ) -> Result<bool, SlhDsaError> {
        if public_key.parameter_set() != self.parameter_set
            || signature.parameter_set() != self.parameter_set
        {
            return Err(SlhDsaError::ParameterSetMismatch);
        }

        let parameters = self.parameter_set.parameters();
        let encoded_public_key = public_key.as_bytes();
        let encoded_signature = signature.as_bytes();

        if encoded_public_key.len() != parameters.public_key_bytes {
            return Err(SlhDsaError::InvalidPublicKey);
        }

        if encoded_signature.len() != parameters.signature_bytes {
            return Err(SlhDsaError::InvalidSignature);
        }

        let public_seed = &encoded_public_key[..parameters.n];
        let public_root = &encoded_public_key[parameters.n..2 * parameters.n];

        let randomizer = &encoded_signature[..parameters.n];
        let mut digest = vec![0_u8; parameters.m];

        HashSuite::new(&parameters)
            .h_msg(
                randomizer,
                public_seed,
                public_root,
                encoded_message,
                &mut digest,
            )
            .map_err(|_| SlhDsaError::InternalError)?;

        let parsed =
            parse_message_digest(&parameters, &digest).map_err(|_| SlhDsaError::InternalError)?;

        let fors_bytes =
            fors::signature_bytes(&parameters).map_err(|_| SlhDsaError::InternalError)?;

        let hypertree_bytes =
            hypertree::signature_bytes(&parameters).map_err(|_| SlhDsaError::InternalError)?;

        let fors_start = parameters.n;
        let fors_end = fors_start
            .checked_add(fors_bytes)
            .ok_or(SlhDsaError::InternalError)?;

        let hypertree_end = fors_end
            .checked_add(hypertree_bytes)
            .ok_or(SlhDsaError::InternalError)?;

        if hypertree_end != encoded_signature.len() {
            return Err(SlhDsaError::InvalidSignature);
        }

        let fors_signature = &encoded_signature[fors_start..fors_end];

        let hypertree_signature = &encoded_signature[fors_end..hypertree_end];

        let mut fors_address = Address::new();
        fors_address.set_tree_address(parsed.tree_index);
        fors_address.set_type_and_clear(AddressType::ForsTree);
        fors_address.set_key_pair_address(parsed.leaf_index);

        let mut fors_public_key = vec![0_u8; parameters.n];

        fors::public_key_from_signature(
            &parameters,
            fors_signature,
            parsed.fors_digest,
            public_seed,
            &fors_address,
            parsed.leaf_index,
            &mut fors_public_key,
        )
        .map_err(|_| SlhDsaError::InternalError)?;

        let mut reconstructed_root = vec![0_u8; parameters.n];

        hypertree::root_from_signature(
            &parameters,
            hypertree_signature,
            &fors_public_key,
            public_seed,
            parsed.tree_index,
            parsed.leaf_index,
            &mut reconstructed_root,
        )
        .map_err(|_| SlhDsaError::InternalError)?;

        Ok(reconstructed_root.as_slice() == public_root)
    }

    /// Deterministically derive an SLH-DSA key pair from a key-generation seed.
    ///
    /// The `3n`-byte input is interpreted as:
    ///
    /// `SK.seed || SK.prf || PK.seed`.
    ///
    /// The public root is generated from the top XMSS tree at layer `d - 1`
    /// and tree index zero. The resulting encodings are:
    ///
    /// `SK.seed || SK.prf || PK.seed || PK.root`
    ///
    /// and
    ///
    /// `PK.seed || PK.root`.
    pub fn keygen_from_seed(&self, seed: &SlhDsaKeyGenSeed) -> Result<SlhDsaKeyPair, SlhDsaError> {
        if seed.parameter_set() != self.parameter_set {
            return Err(SlhDsaError::ParameterSetMismatch);
        }

        let parameters = self.parameter_set.parameters();
        let seed_bytes = seed.as_bytes();

        if seed_bytes.len() != parameters.keygen_seed_bytes {
            return Err(SlhDsaError::InvalidKeyGenSeed);
        }

        let secret_seed_end = parameters.n;
        let secret_prf_end = secret_seed_end
            .checked_add(parameters.n)
            .ok_or(SlhDsaError::InternalError)?;
        let public_seed_end = secret_prf_end
            .checked_add(parameters.n)
            .ok_or(SlhDsaError::InternalError)?;

        if public_seed_end != seed_bytes.len() {
            return Err(SlhDsaError::InternalError);
        }

        let secret_seed = &seed_bytes[..secret_seed_end];
        let secret_prf = &seed_bytes[secret_seed_end..secret_prf_end];
        let public_seed = &seed_bytes[secret_prf_end..public_seed_end];

        let top_layer = parameters
            .d
            .checked_sub(1)
            .ok_or(SlhDsaError::InternalError)?;

        let top_position = HypertreePosition {
            layer: top_layer,
            tree_index: 0,
            leaf_index: 0,
        };

        let top_address = hypertree::xmss_address(&parameters, top_position)
            .map_err(|_| SlhDsaError::InternalError)?;

        let mut public_root = vec![0_u8; parameters.n];

        xmss::root(
            &parameters,
            secret_seed,
            public_seed,
            &top_address,
            &mut public_root,
        )
        .map_err(|_| SlhDsaError::InternalError)?;

        let mut private_key_bytes = Vec::with_capacity(parameters.private_key_bytes);

        private_key_bytes.extend_from_slice(secret_seed);
        private_key_bytes.extend_from_slice(secret_prf);
        private_key_bytes.extend_from_slice(public_seed);
        private_key_bytes.extend_from_slice(&public_root);

        if private_key_bytes.len() != parameters.private_key_bytes {
            return Err(SlhDsaError::InternalError);
        }

        let mut public_key_bytes = Vec::with_capacity(parameters.public_key_bytes);

        public_key_bytes.extend_from_slice(public_seed);
        public_key_bytes.extend_from_slice(&public_root);

        if public_key_bytes.len() != parameters.public_key_bytes {
            return Err(SlhDsaError::InternalError);
        }

        Ok(SlhDsaKeyPair {
            public_key: SlhDsaPublicKey::from_bytes(self.parameter_set, &public_key_bytes)?,
            private_key: SlhDsaPrivateKey::from_bytes(self.parameter_set, &private_key_bytes)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{CryptoRng, Error as RandError, RngCore};

    #[derive(Clone)]
    struct DeterministicRng {
        next: u8,
    }

    impl DeterministicRng {
        const fn new(next: u8) -> Self {
            Self { next }
        }
    }

    impl RngCore for DeterministicRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0_u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0_u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            self.try_fill_bytes(destination)
                .expect("deterministic RNG cannot fail");
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
            for byte in destination {
                *byte = self.next;
                self.next = self.next.wrapping_add(1);
            }

            Ok(())
        }
    }

    impl CryptoRng for DeterministicRng {}

    struct FailingRng;

    impl RngCore for FailingRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            destination.fill(0);
        }

        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), RandError> {
            Err(RandError::from(
                core::num::NonZeroU32::new(1).expect("nonzero error code"),
            ))
        }
    }

    impl CryptoRng for FailingRng {}

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

    #[test]
    fn keygen_from_seed_rejects_a_parameter_set_mismatch() {
        let seed =
            SlhDsaKeyGenSeed::from_bytes(SlhDsaParameterSet::Shake128s, &[0_u8; 48]).unwrap();

        let slh_dsa = SlhDsa::new(SlhDsaParameterSet::Sha2_128s);

        assert_eq!(
            slh_dsa.keygen_from_seed(&seed).err(),
            Some(SlhDsaError::ParameterSetMismatch)
        );
    }

    #[test]
    fn keygen_from_seed_produces_expected_key_lengths() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let parameters = parameter_set.parameters();
        let seed_bytes = vec![0x21_u8; parameters.keygen_seed_bytes];
        let seed = SlhDsaKeyGenSeed::from_bytes(parameter_set, &seed_bytes).unwrap();

        let key_pair = SlhDsa::new(parameter_set).keygen_from_seed(&seed).unwrap();

        assert_eq!(
            key_pair.public_key().as_bytes().len(),
            parameters.public_key_bytes
        );
        assert_eq!(
            key_pair.private_key().as_bytes().len(),
            parameters.private_key_bytes
        );
    }

    #[test]
    fn keygen_from_seed_preserves_the_three_seed_components() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let parameters = parameter_set.parameters();

        let mut seed_bytes = vec![0_u8; parameters.keygen_seed_bytes];
        seed_bytes[..parameters.n].fill(0x11);
        seed_bytes[parameters.n..2 * parameters.n].fill(0x22);
        seed_bytes[2 * parameters.n..3 * parameters.n].fill(0x33);

        let seed = SlhDsaKeyGenSeed::from_bytes(parameter_set, &seed_bytes).unwrap();

        let key_pair = SlhDsa::new(parameter_set).keygen_from_seed(&seed).unwrap();

        let private_key = key_pair.private_key().as_bytes();
        let public_key = key_pair.public_key().as_bytes();

        assert_eq!(&private_key[..parameters.n], &[0x11_u8; 16]);
        assert_eq!(&private_key[parameters.n..2 * parameters.n], &[0x22_u8; 16]);
        assert_eq!(
            &private_key[2 * parameters.n..3 * parameters.n],
            &[0x33_u8; 16]
        );
        assert_eq!(&public_key[..parameters.n], &[0x33_u8; 16]);
    }

    #[test]
    fn private_and_public_keys_contain_the_same_public_components() {
        let parameter_set = SlhDsaParameterSet::Sha2_128f;
        let parameters = parameter_set.parameters();
        let seed_bytes = vec![0x57_u8; parameters.keygen_seed_bytes];
        let seed = SlhDsaKeyGenSeed::from_bytes(parameter_set, &seed_bytes).unwrap();

        let key_pair = SlhDsa::new(parameter_set).keygen_from_seed(&seed).unwrap();

        let private_key = key_pair.private_key().as_bytes();
        let public_key = key_pair.public_key().as_bytes();

        assert_eq!(&private_key[2 * parameters.n..4 * parameters.n], public_key);
    }

    #[test]
    fn keygen_from_seed_is_deterministic() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let parameters = parameter_set.parameters();
        let seed_bytes = vec![0x79_u8; parameters.keygen_seed_bytes];
        let seed = SlhDsaKeyGenSeed::from_bytes(parameter_set, &seed_bytes).unwrap();
        let slh_dsa = SlhDsa::new(parameter_set);

        let first = slh_dsa.keygen_from_seed(&seed).unwrap();
        let second = slh_dsa.keygen_from_seed(&seed).unwrap();

        assert_eq!(
            first.public_key().as_bytes(),
            second.public_key().as_bytes()
        );
        assert_eq!(
            first.private_key().as_bytes(),
            second.private_key().as_bytes()
        );
    }

    #[test]
    fn keygen_public_root_matches_direct_top_xmss_root() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let parameters = parameter_set.parameters();

        let mut seed_bytes = vec![0_u8; parameters.keygen_seed_bytes];
        seed_bytes[..parameters.n].fill(0x91);
        seed_bytes[parameters.n..2 * parameters.n].fill(0xa2);
        seed_bytes[2 * parameters.n..3 * parameters.n].fill(0xb3);

        let seed = SlhDsaKeyGenSeed::from_bytes(parameter_set, &seed_bytes).unwrap();

        let key_pair = SlhDsa::new(parameter_set).keygen_from_seed(&seed).unwrap();

        let top_position = HypertreePosition {
            layer: parameters.d - 1,
            tree_index: 0,
            leaf_index: 0,
        };

        let address = hypertree::xmss_address(&parameters, top_position).unwrap();

        let mut expected_root = vec![0_u8; parameters.n];

        xmss::root(
            &parameters,
            &seed_bytes[..parameters.n],
            &seed_bytes[2 * parameters.n..3 * parameters.n],
            &address,
            &mut expected_root,
        )
        .unwrap();

        assert_eq!(
            &key_pair.public_key().as_bytes()[parameters.n..],
            expected_root
        );
    }

    #[test]
    fn every_parameter_set_expands_a_key_generation_seed() {
        let parameter_sets = [
            SlhDsaParameterSet::Sha2_128s,
            SlhDsaParameterSet::Sha2_128f,
            SlhDsaParameterSet::Sha2_192s,
            SlhDsaParameterSet::Sha2_192f,
            SlhDsaParameterSet::Sha2_256s,
            SlhDsaParameterSet::Sha2_256f,
            SlhDsaParameterSet::Shake128s,
            SlhDsaParameterSet::Shake128f,
            SlhDsaParameterSet::Shake192s,
            SlhDsaParameterSet::Shake192f,
            SlhDsaParameterSet::Shake256s,
            SlhDsaParameterSet::Shake256f,
        ];

        for parameter_set in parameter_sets {
            let mut parameters = parameter_set.parameters();

            // Keep this cross-parameter structural test inexpensive while
            // exercising all hash families and n values.
            parameters.hp = 2;
            parameters.d = 3;
            parameters.h = 6;

            let seed_bytes = vec![0x5a_u8; parameters.keygen_seed_bytes];
            let secret_seed = &seed_bytes[..parameters.n];
            let public_seed = &seed_bytes[2 * parameters.n..3 * parameters.n];

            let top_position = HypertreePosition {
                layer: parameters.d - 1,
                tree_index: 0,
                leaf_index: 0,
            };

            let address = hypertree::xmss_address(&parameters, top_position).unwrap();
            let mut root = vec![0_u8; parameters.n];

            xmss::root(&parameters, secret_seed, public_seed, &address, &mut root).unwrap();

            assert_eq!(root.len(), parameters.n, "{parameter_set:?}");
        }
    }

    #[test]
    fn generated_keygen_seed_has_the_expected_length_and_parameter_set() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let slh_dsa = SlhDsa::new(parameter_set);
        let mut rng = DeterministicRng::new(0x21);

        let seed = slh_dsa.generate_keygen_seed(&mut rng).unwrap();

        assert_eq!(seed.parameter_set(), parameter_set);
        assert_eq!(seed.as_bytes().len(), slh_dsa.keygen_seed_bytes());
    }

    #[test]
    fn generated_keygen_seed_contains_the_rng_stream() {
        let slh_dsa = SlhDsa::new(SlhDsaParameterSet::Shake128f);
        let mut rng = DeterministicRng::new(0x40);

        let seed = slh_dsa.generate_keygen_seed(&mut rng).unwrap();

        let expected: Vec<u8> = (0..slh_dsa.keygen_seed_bytes())
            .map(|offset| 0x40_u8.wrapping_add(offset as u8))
            .collect();

        assert_eq!(seed.as_bytes(), expected);
    }

    #[test]
    fn keygen_matches_seed_generation_followed_by_expansion() {
        let slh_dsa = SlhDsa::new(SlhDsaParameterSet::Shake128f);
        let mut direct_rng = DeterministicRng::new(0x65);
        let mut staged_rng = DeterministicRng::new(0x65);

        let direct = slh_dsa.keygen(&mut direct_rng).unwrap();

        let seed = slh_dsa.generate_keygen_seed(&mut staged_rng).unwrap();

        let staged = slh_dsa.keygen_from_seed(&seed).unwrap();

        assert_eq!(
            direct.public_key().as_bytes(),
            staged.public_key().as_bytes()
        );

        assert_eq!(
            direct.private_key().as_bytes(),
            staged.private_key().as_bytes()
        );
    }

    #[test]
    fn keygen_is_reproducible_for_identical_rng_streams() {
        let slh_dsa = SlhDsa::new(SlhDsaParameterSet::Sha2_128f);
        let mut first_rng = DeterministicRng::new(0x87);
        let mut second_rng = DeterministicRng::new(0x87);

        let first = slh_dsa.keygen(&mut first_rng).unwrap();
        let second = slh_dsa.keygen(&mut second_rng).unwrap();

        assert_eq!(
            first.public_key().as_bytes(),
            second.public_key().as_bytes()
        );

        assert_eq!(
            first.private_key().as_bytes(),
            second.private_key().as_bytes()
        );
    }

    #[test]
    fn generate_keygen_seed_maps_rng_failures() {
        let slh_dsa = SlhDsa::new(SlhDsaParameterSet::Shake128f);
        let mut rng = FailingRng;

        assert_eq!(
            slh_dsa.generate_keygen_seed(&mut rng).err(),
            Some(SlhDsaError::RandomnessFailure)
        );
    }

    #[test]
    fn keygen_maps_rng_failures() {
        let slh_dsa = SlhDsa::new(SlhDsaParameterSet::Shake128f);
        let mut rng = FailingRng;

        assert_eq!(
            slh_dsa.keygen(&mut rng).err(),
            Some(SlhDsaError::RandomnessFailure)
        );
    }

    #[test]
    fn every_parameter_set_generates_the_expected_seed_length() {
        let parameter_sets = [
            SlhDsaParameterSet::Sha2_128s,
            SlhDsaParameterSet::Sha2_128f,
            SlhDsaParameterSet::Sha2_192s,
            SlhDsaParameterSet::Sha2_192f,
            SlhDsaParameterSet::Sha2_256s,
            SlhDsaParameterSet::Sha2_256f,
            SlhDsaParameterSet::Shake128s,
            SlhDsaParameterSet::Shake128f,
            SlhDsaParameterSet::Shake192s,
            SlhDsaParameterSet::Shake192f,
            SlhDsaParameterSet::Shake256s,
            SlhDsaParameterSet::Shake256f,
        ];

        for (offset, parameter_set) in parameter_sets.into_iter().enumerate() {
            let slh_dsa = SlhDsa::new(parameter_set);
            let mut rng = DeterministicRng::new(offset as u8);

            let seed = slh_dsa.generate_keygen_seed(&mut rng).unwrap();

            assert_eq!(
                seed.as_bytes().len(),
                parameter_set.parameters().keygen_seed_bytes,
                "{parameter_set:?}"
            );

            assert_eq!(seed.parameter_set(), parameter_set);
        }
    }

    fn signing_key_pair(parameter_set: SlhDsaParameterSet) -> SlhDsaKeyPair {
        let parameters = parameter_set.parameters();
        let seed_bytes: Vec<u8> = (0..parameters.keygen_seed_bytes)
            .map(|offset| 0x31_u8.wrapping_add(offset as u8))
            .collect();

        let seed = SlhDsaKeyGenSeed::from_bytes(parameter_set, &seed_bytes).unwrap();

        SlhDsa::new(parameter_set).keygen_from_seed(&seed).unwrap()
    }

    #[test]
    fn deterministic_signing_rejects_a_parameter_set_mismatch() {
        let key_pair = signing_key_pair(SlhDsaParameterSet::Shake128f);
        let slh_dsa = SlhDsa::new(SlhDsaParameterSet::Sha2_128f);

        assert_eq!(
            slh_dsa
                .sign_deterministic(key_pair.private_key(), b"message", b"",)
                .err(),
            Some(SlhDsaError::ParameterSetMismatch)
        );
    }

    #[test]
    fn deterministic_signing_rejects_an_oversized_context() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);
        let context = [0_u8; 256];

        assert_eq!(
            slh_dsa
                .sign_deterministic(key_pair.private_key(), b"message", &context,)
                .err(),
            Some(SlhDsaError::ContextTooLong)
        );
    }

    #[test]
    fn deterministic_signature_has_the_expected_encoding_length() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);

        let signature = slh_dsa
            .sign_deterministic(
                key_pair.private_key(),
                b"deterministic SLH-DSA signing",
                b"test",
            )
            .unwrap();

        assert_eq!(signature.parameter_set(), parameter_set);
        assert_eq!(
            signature.as_bytes().len(),
            parameter_set.parameters().signature_bytes
        );
    }

    #[test]
    fn deterministic_signing_is_reproducible() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);

        let first = slh_dsa
            .sign_deterministic(key_pair.private_key(), b"same message", b"same context")
            .unwrap();

        let second = slh_dsa
            .sign_deterministic(key_pair.private_key(), b"same message", b"same context")
            .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn deterministic_signature_randomizer_matches_direct_prf_msg() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let parameters = parameter_set.parameters();
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);
        let message = b"message randomizer test";
        let context = b"ctx";

        let signature = slh_dsa
            .sign_deterministic(key_pair.private_key(), message, context)
            .unwrap();

        let private_key = key_pair.private_key().as_bytes();
        let secret_prf = &private_key[parameters.n..2 * parameters.n];
        let public_seed = &private_key[2 * parameters.n..3 * parameters.n];

        let mut prefixed_message = Vec::with_capacity(2 + context.len() + message.len());
        prefixed_message.push(0);
        prefixed_message.push(context.len() as u8);
        prefixed_message.extend_from_slice(context);
        prefixed_message.extend_from_slice(message);

        let mut expected = vec![0_u8; parameters.n];

        HashSuite::new(&parameters)
            .prf_msg(secret_prf, public_seed, &prefixed_message, &mut expected)
            .unwrap();

        assert_eq!(&signature.as_bytes()[..parameters.n], expected);
    }

    #[test]
    fn changing_the_message_changes_the_deterministic_signature() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);

        let first = slh_dsa
            .sign_deterministic(key_pair.private_key(), b"first message", b"context")
            .unwrap();

        let second = slh_dsa
            .sign_deterministic(key_pair.private_key(), b"second message", b"context")
            .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn changing_the_context_changes_the_deterministic_signature() {
        let parameter_set = SlhDsaParameterSet::Sha2_128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);

        let first = slh_dsa
            .sign_deterministic(key_pair.private_key(), b"message", b"first context")
            .unwrap();

        let second = slh_dsa
            .sign_deterministic(key_pair.private_key(), b"message", b"second context")
            .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn hedged_signing_rejects_a_parameter_set_mismatch() {
        let key_pair = signing_key_pair(SlhDsaParameterSet::Shake128f);
        let slh_dsa = SlhDsa::new(SlhDsaParameterSet::Sha2_128f);
        let mut rng = DeterministicRng::new(0x11);

        assert_eq!(
            slh_dsa
                .sign_hedged(key_pair.private_key(), b"message", b"", &mut rng,)
                .err(),
            Some(SlhDsaError::ParameterSetMismatch)
        );
    }

    #[test]
    fn hedged_signing_rejects_an_oversized_context() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);
        let context = [0_u8; 256];
        let mut rng = DeterministicRng::new(0x22);

        assert_eq!(
            slh_dsa
                .sign_hedged(key_pair.private_key(), b"message", &context, &mut rng,)
                .err(),
            Some(SlhDsaError::ContextTooLong)
        );
    }

    #[test]
    fn hedged_signing_maps_rng_failures() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);
        let mut rng = FailingRng;

        assert_eq!(
            slh_dsa
                .sign_hedged(key_pair.private_key(), b"message", b"context", &mut rng,)
                .err(),
            Some(SlhDsaError::RandomnessFailure)
        );
    }

    #[test]
    fn hedged_signature_has_the_expected_length() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);
        let mut rng = DeterministicRng::new(0x33);

        let signature = slh_dsa
            .sign_hedged(
                key_pair.private_key(),
                b"hedged SLH-DSA signing",
                b"test",
                &mut rng,
            )
            .unwrap();

        assert_eq!(signature.parameter_set(), parameter_set);
        assert_eq!(
            signature.as_bytes().len(),
            parameter_set.parameters().signature_bytes
        );
    }

    #[test]
    fn identical_rng_streams_produce_identical_hedged_signatures() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);
        let mut first_rng = DeterministicRng::new(0x44);
        let mut second_rng = DeterministicRng::new(0x44);

        let first = slh_dsa
            .sign_hedged(
                key_pair.private_key(),
                b"same message",
                b"same context",
                &mut first_rng,
            )
            .unwrap();

        let second = slh_dsa
            .sign_hedged(
                key_pair.private_key(),
                b"same message",
                b"same context",
                &mut second_rng,
            )
            .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn different_rng_streams_produce_different_hedged_signatures() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);
        let mut first_rng = DeterministicRng::new(0x55);
        let mut second_rng = DeterministicRng::new(0x99);

        let first = slh_dsa
            .sign_hedged(
                key_pair.private_key(),
                b"same message",
                b"same context",
                &mut first_rng,
            )
            .unwrap();

        let second = slh_dsa
            .sign_hedged(
                key_pair.private_key(),
                b"same message",
                b"same context",
                &mut second_rng,
            )
            .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn hedged_signature_randomizer_matches_direct_prf_msg() {
        let parameter_set = SlhDsaParameterSet::Sha2_128f;
        let parameters = parameter_set.parameters();
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);
        let message = b"hedged randomizer test";
        let context = b"ctx";
        let starting_byte = 0x6a;
        let mut rng = DeterministicRng::new(starting_byte);

        let signature = slh_dsa
            .sign_hedged(key_pair.private_key(), message, context, &mut rng)
            .unwrap();

        let private_key = key_pair.private_key().as_bytes();
        let secret_prf = &private_key[parameters.n..2 * parameters.n];

        let optional_randomness: Vec<u8> = (0..parameters.n)
            .map(|offset| starting_byte.wrapping_add(offset as u8))
            .collect();

        let mut prefixed_message = Vec::with_capacity(2 + context.len() + message.len());

        prefixed_message.push(0);
        prefixed_message.push(context.len() as u8);
        prefixed_message.extend_from_slice(context);
        prefixed_message.extend_from_slice(message);

        let mut expected = vec![0_u8; parameters.n];

        HashSuite::new(&parameters)
            .prf_msg(
                secret_prf,
                &optional_randomness,
                &prefixed_message,
                &mut expected,
            )
            .unwrap();

        assert_eq!(&signature.as_bytes()[..parameters.n], expected);
    }

    #[test]
    fn deterministic_and_hedged_signatures_use_distinct_randomization() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);
        let mut rng = DeterministicRng::new(0xc1);

        let deterministic = slh_dsa
            .sign_deterministic(key_pair.private_key(), b"message", b"context")
            .unwrap();

        let hedged = slh_dsa
            .sign_hedged(key_pair.private_key(), b"message", b"context", &mut rng)
            .unwrap();

        assert_ne!(deterministic, hedged);
    }

    #[test]
    fn deterministic_signature_verifies() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);
        let message = b"deterministic verification";
        let context = b"test";

        let signature = slh_dsa
            .sign_deterministic(key_pair.private_key(), message, context)
            .unwrap();

        assert_eq!(
            slh_dsa.verify(key_pair.public_key(), message, context, &signature,),
            Ok(true)
        );
    }

    #[test]
    fn hedged_signature_verifies() {
        let parameter_set = SlhDsaParameterSet::Sha2_128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);
        let message = b"hedged verification";
        let context = b"ctx";
        let mut rng = DeterministicRng::new(0x42);

        let signature = slh_dsa
            .sign_hedged(key_pair.private_key(), message, context, &mut rng)
            .unwrap();

        assert_eq!(
            slh_dsa.verify(key_pair.public_key(), message, context, &signature,),
            Ok(true)
        );
    }

    #[test]
    fn verification_rejects_a_changed_message() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);

        let signature = slh_dsa
            .sign_deterministic(key_pair.private_key(), b"original message", b"context")
            .unwrap();

        assert_eq!(
            slh_dsa.verify(
                key_pair.public_key(),
                b"changed message",
                b"context",
                &signature,
            ),
            Ok(false)
        );
    }

    #[test]
    fn verification_rejects_a_changed_context() {
        let parameter_set = SlhDsaParameterSet::Sha2_128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);

        let signature = slh_dsa
            .sign_deterministic(key_pair.private_key(), b"message", b"original context")
            .unwrap();

        assert_eq!(
            slh_dsa.verify(
                key_pair.public_key(),
                b"message",
                b"changed context",
                &signature,
            ),
            Ok(false)
        );
    }

    #[test]
    fn verification_rejects_a_modified_signature() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);

        let signature = slh_dsa
            .sign_deterministic(key_pair.private_key(), b"message", b"context")
            .unwrap();

        let mut modified = signature.clone().into_bytes();
        let modified_index = modified.len() / 2;
        modified[modified_index] ^= 1;

        let modified_signature = SlhDsaSignature::from_bytes(parameter_set, &modified).unwrap();

        assert_eq!(
            slh_dsa.verify(
                key_pair.public_key(),
                b"message",
                b"context",
                &modified_signature,
            ),
            Ok(false)
        );
    }

    #[test]
    fn verification_rejects_a_different_public_key() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let first_pair = signing_key_pair(parameter_set);

        let parameters = parameter_set.parameters();
        let second_seed_bytes: Vec<u8> = (0..parameters.keygen_seed_bytes)
            .map(|offset| 0xa1_u8.wrapping_add(offset as u8))
            .collect();

        let second_seed = SlhDsaKeyGenSeed::from_bytes(parameter_set, &second_seed_bytes).unwrap();

        let second_pair = SlhDsa::new(parameter_set)
            .keygen_from_seed(&second_seed)
            .unwrap();

        let slh_dsa = SlhDsa::new(parameter_set);

        let signature = slh_dsa
            .sign_deterministic(first_pair.private_key(), b"message", b"context")
            .unwrap();

        assert_eq!(
            slh_dsa.verify(second_pair.public_key(), b"message", b"context", &signature,),
            Ok(false)
        );
    }

    #[test]
    fn verification_rejects_a_public_key_parameter_set_mismatch() {
        let key_pair = signing_key_pair(SlhDsaParameterSet::Shake128f);
        let slh_dsa = SlhDsa::new(SlhDsaParameterSet::Sha2_128f);

        let signature = SlhDsaSignature::from_bytes(
            SlhDsaParameterSet::Sha2_128f,
            &vec![0_u8; SlhDsaParameterSet::Sha2_128f.parameters().signature_bytes],
        )
        .unwrap();

        assert_eq!(
            slh_dsa
                .verify(key_pair.public_key(), b"message", b"", &signature,)
                .err(),
            Some(SlhDsaError::ParameterSetMismatch)
        );
    }

    #[test]
    fn verification_rejects_a_signature_parameter_set_mismatch() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);

        let mismatched_signature = SlhDsaSignature::from_bytes(
            SlhDsaParameterSet::Sha2_128f,
            &vec![0_u8; SlhDsaParameterSet::Sha2_128f.parameters().signature_bytes],
        )
        .unwrap();

        assert_eq!(
            slh_dsa
                .verify(
                    key_pair.public_key(),
                    b"message",
                    b"",
                    &mismatched_signature,
                )
                .err(),
            Some(SlhDsaError::ParameterSetMismatch)
        );
    }

    #[test]
    fn verification_rejects_an_oversized_context() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);

        let signature = slh_dsa
            .sign_deterministic(key_pair.private_key(), b"message", b"")
            .unwrap();

        assert_eq!(
            slh_dsa
                .verify(key_pair.public_key(), b"message", &[0_u8; 256], &signature,)
                .err(),
            Some(SlhDsaError::ContextTooLong)
        );
    }

    #[test]
    fn empty_message_and_context_verify() {
        let parameter_set = SlhDsaParameterSet::Sha2_128f;
        let key_pair = signing_key_pair(parameter_set);
        let slh_dsa = SlhDsa::new(parameter_set);

        let signature = slh_dsa
            .sign_deterministic(key_pair.private_key(), b"", b"")
            .unwrap();

        assert_eq!(
            slh_dsa.verify(key_pair.public_key(), b"", b"", &signature,),
            Ok(true)
        );
    }

    #[cfg(feature = "internal-api")]
    #[test]
    fn internal_deterministic_signature_verifies() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let implementation = SlhDsa::new(parameter_set);
        let message = b"internal interface message";

        let signature = implementation
            .sign_internal_deterministic(key_pair.private_key(), message)
            .unwrap();

        assert_eq!(
            implementation.verify_internal(key_pair.public_key(), message, &signature,),
            Ok(true)
        );
    }

    #[cfg(feature = "internal-api")]
    #[test]
    fn internal_hedged_signature_verifies() {
        let parameter_set = SlhDsaParameterSet::Sha2_128f;
        let key_pair = signing_key_pair(parameter_set);
        let implementation = SlhDsa::new(parameter_set);
        let message = b"internal hedged message";
        let mut rng = DeterministicRng::new(0x72);

        let signature = implementation
            .sign_internal_hedged(key_pair.private_key(), message, &mut rng)
            .unwrap();

        assert_eq!(
            implementation.verify_internal(key_pair.public_key(), message, &signature,),
            Ok(true)
        );
    }

    #[cfg(feature = "internal-api")]
    #[test]
    fn external_verification_rejects_an_internal_signature() {
        let parameter_set = SlhDsaParameterSet::Shake128f;
        let key_pair = signing_key_pair(parameter_set);
        let implementation = SlhDsa::new(parameter_set);
        let message = b"interface separation";

        let signature = implementation
            .sign_internal_deterministic(key_pair.private_key(), message)
            .unwrap();

        assert_eq!(
            implementation.verify(key_pair.public_key(), message, b"", &signature,),
            Ok(false)
        );
    }

    #[cfg(feature = "internal-api")]
    #[test]
    fn internal_verification_rejects_an_external_signature() {
        let parameter_set = SlhDsaParameterSet::Sha2_128f;
        let key_pair = signing_key_pair(parameter_set);
        let implementation = SlhDsa::new(parameter_set);
        let message = b"interface separation";

        let signature = implementation
            .sign_deterministic(key_pair.private_key(), message, b"")
            .unwrap();

        assert_eq!(
            implementation.verify_internal(key_pair.public_key(), message, &signature,),
            Ok(false)
        );
    }

    #[cfg(feature = "internal-api")]
    #[test]
    fn internal_signing_rejects_a_parameter_set_mismatch() {
        let key_pair = signing_key_pair(SlhDsaParameterSet::Shake128f);
        let implementation = SlhDsa::new(SlhDsaParameterSet::Sha2_128f);

        assert_eq!(
            implementation
                .sign_internal_deterministic(key_pair.private_key(), b"message",)
                .err(),
            Some(SlhDsaError::ParameterSetMismatch)
        );
    }
}
