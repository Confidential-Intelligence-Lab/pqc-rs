//! Publication-facing SLH-DSA object model.

use core::fmt;

use pqc_core::secret::SecretVec;

use crate::{
    hypertree::{self, HypertreePosition},
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
}
