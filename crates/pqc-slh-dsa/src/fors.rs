//! Deterministic preprocessing and secret-value generation for FORS.

use core::fmt;

use crate::{
    address::{Address, AddressType},
    conversion::{base_2b, ConversionError},
    hash::HashError,
    hash_suite::HashSuite,
    params::SlhDsaParameters,
};

/// Errors returned by deterministic FORS operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForsError {
    /// The FORS message digest has the wrong length.
    InvalidDigestLength {
        /// Required digest length in bytes.
        expected: usize,

        /// Supplied digest length in bytes.
        actual: usize,
    },

    /// The caller supplied the wrong number of FORS indices.
    InvalidIndexCount {
        /// Required number of indices.
        expected: usize,

        /// Supplied number of indices.
        actual: usize,
    },

    /// The selected FORS tree is outside the configured tree set.
    InvalidTreeIndex {
        /// Supplied tree index.
        tree: usize,

        /// Number of FORS trees.
        tree_count: usize,
    },

    /// The selected leaf is outside a FORS tree.
    InvalidLeafIndex {
        /// Supplied leaf index.
        leaf: u32,

        /// Number of leaves in each FORS tree.
        leaf_count: u64,
    },

    /// A FORS parameter or index calculation overflowed.
    ParameterOverflow,

    /// The FORS height cannot be represented by the current implementation.
    UnsupportedTreeHeight {
        /// Configured FORS tree height.
        height: usize,
    },

    /// Byte-to-integer conversion failed.
    Conversion(ConversionError),

    /// Hash evaluation failed.
    Hash(HashError),
}

impl fmt::Display for ForsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDigestLength { expected, actual } => {
                write!(
                    formatter,
                    "invalid FORS digest length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidIndexCount { expected, actual } => {
                write!(
                    formatter,
                    "invalid FORS index count: expected {expected}, got {actual}"
                )
            }
            Self::InvalidTreeIndex { tree, tree_count } => {
                write!(
                    formatter,
                    "FORS tree index {tree} is outside the configured {tree_count} trees"
                )
            }
            Self::InvalidLeafIndex { leaf, leaf_count } => {
                write!(
                    formatter,
                    "FORS leaf index {leaf} is outside a tree with {leaf_count} leaves"
                )
            }
            Self::ParameterOverflow => {
                write!(formatter, "FORS parameter or index calculation overflowed")
            }
            Self::UnsupportedTreeHeight { height } => {
                write!(
                    formatter,
                    "FORS tree height {height} exceeds the supported 32 bits"
                )
            }
            Self::Conversion(error) => {
                write!(formatter, "FORS digest conversion failed: {error}")
            }
            Self::Hash(error) => {
                write!(formatter, "FORS hash evaluation failed: {error}")
            }
        }
    }
}

impl From<ConversionError> for ForsError {
    fn from(error: ConversionError) -> Self {
        Self::Conversion(error)
    }
}

impl From<HashError> for ForsError {
    fn from(error: HashError) -> Self {
        Self::Hash(error)
    }
}

/// Location of a selected secret value within a FORS instance.
///
/// The key-pair address identifies the XMSS leaf associated with the FORS
/// instance. The tree and leaf fields identify one secret value among the
/// `k * 2^a` deterministic FORS secret values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForsPosition {
    /// Key-pair address inherited from the enclosing hypertree operation.
    pub key_pair_address: u32,

    /// Index of the selected FORS tree.
    pub tree: usize,

    /// Index of the selected leaf within that tree.
    pub leaf: u32,
}

/// Return the number of bytes occupied by the FORS portion of `H_msg`.
pub fn digest_bytes(parameters: &SlhDsaParameters) -> Result<usize, ForsError> {
    let digest_bits = parameters
        .k
        .checked_mul(parameters.a)
        .ok_or(ForsError::ParameterOverflow)?;

    digest_bits
        .checked_add(7)
        .map(|rounded| rounded / 8)
        .ok_or(ForsError::ParameterOverflow)
}

/// Split the FORS digest into `k` separate `a`-bit indices.
///
/// This implements the `base_2b(md, a, k)` operation used by FIPS 205
/// `fors_sign` and `fors_pkFromSig`.
pub fn message_to_indices(
    parameters: &SlhDsaParameters,
    digest: &[u8],
    indices: &mut [u32],
) -> Result<(), ForsError> {
    if parameters.a > u32::BITS as usize {
        return Err(ForsError::UnsupportedTreeHeight {
            height: parameters.a,
        });
    }

    let expected_digest_bytes = digest_bytes(parameters)?;

    if digest.len() != expected_digest_bytes {
        return Err(ForsError::InvalidDigestLength {
            expected: expected_digest_bytes,
            actual: digest.len(),
        });
    }

    if indices.len() != parameters.k {
        return Err(ForsError::InvalidIndexCount {
            expected: parameters.k,
            actual: indices.len(),
        });
    }

    base_2b(digest, parameters.a, indices)?;

    Ok(())
}

/// Return the number of leaves in one FORS tree.
pub fn leaves_per_tree(parameters: &SlhDsaParameters) -> Result<u64, ForsError> {
    if parameters.a > u32::BITS as usize {
        return Err(ForsError::UnsupportedTreeHeight {
            height: parameters.a,
        });
    }

    1_u64
        .checked_shl(parameters.a as u32)
        .ok_or(ForsError::ParameterOverflow)
}

/// Convert a tree-local leaf index into the global FORS secret-value index.
///
/// FIPS 205 numbers all FORS secret values consecutively:
///
/// `index = tree * 2^a + leaf`.
pub fn secret_value_index(
    parameters: &SlhDsaParameters,
    tree: usize,
    leaf: u32,
) -> Result<u32, ForsError> {
    if tree >= parameters.k {
        return Err(ForsError::InvalidTreeIndex {
            tree,
            tree_count: parameters.k,
        });
    }

    let leaf_count = leaves_per_tree(parameters)?;

    if u64::from(leaf) >= leaf_count {
        return Err(ForsError::InvalidLeafIndex { leaf, leaf_count });
    }

    let global_index = (tree as u64)
        .checked_mul(leaf_count)
        .and_then(|base| base.checked_add(u64::from(leaf)))
        .ok_or(ForsError::ParameterOverflow)?;

    u32::try_from(global_index).map_err(|_| ForsError::ParameterOverflow)
}

/// Generate a deterministic FORS private-key value.
///
/// This implements FIPS 205 `fors_skGen`. The caller supplies the FORS-tree
/// address so that the layer and tree address are preserved. The key-pair
/// address is restored after changing the address type because
/// `set_type_and_clear` clears all type-dependent words.
pub fn secret_value(
    parameters: &SlhDsaParameters,
    secret_seed: &[u8],
    public_seed: &[u8],
    fors_address: &Address,
    key_pair_address: u32,
    index: u32,
    output: &mut [u8],
) -> Result<(), ForsError> {
    let mut secret_address = *fors_address;

    secret_address.set_type_and_clear(AddressType::ForsPrf);
    secret_address.set_key_pair_address(key_pair_address);
    secret_address.set_tree_index(index);

    HashSuite::new(parameters).prf(public_seed, secret_seed, &secret_address, output)?;

    Ok(())
}

/// Generate the selected secret value from a tree-local leaf index.
pub fn selected_secret_value(
    parameters: &SlhDsaParameters,
    secret_seed: &[u8],
    public_seed: &[u8],
    fors_address: &Address,
    position: ForsPosition,
    output: &mut [u8],
) -> Result<(), ForsError> {
    let index = secret_value_index(parameters, position.tree, position.leaf)?;

    secret_value(
        parameters,
        secret_seed,
        public_seed,
        fors_address,
        position.key_pair_address,
        index,
        output,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SlhDsaParameterSet;

    const PARAMETER_SETS: [SlhDsaParameterSet; 12] = [
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

    fn fors_address() -> Address {
        let mut address = Address::new();
        address.set_layer_address(0);
        address.set_tree_address(0x0102_0304_0506_0708);
        address.set_type_and_clear(AddressType::ForsTree);
        address.set_key_pair_address(9);
        address
    }

    #[test]
    fn every_parameter_set_has_a_consistent_fors_digest_length() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();

            assert_eq!(
                digest_bytes(&parameters).unwrap(),
                (parameters.k * parameters.a).div_ceil(8)
            );
        }
    }

    #[test]
    fn every_parameter_set_produces_bounded_indices() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let digest = [0xff_u8; 40];
            let mut indices = [0_u32; 35];

            message_to_indices(
                &parameters,
                &digest[..digest_bytes(&parameters).unwrap()],
                &mut indices[..parameters.k],
            )
            .unwrap();

            let bound = 1_u64 << parameters.a;

            assert!(indices[..parameters.k]
                .iter()
                .all(|index| u64::from(*index) < bound));
        }
    }

    #[test]
    fn message_to_indices_matches_msb_first_bit_groups() {
        let mut parameters = SlhDsaParameterSet::Shake128s.parameters();
        parameters.a = 12;
        parameters.k = 2;

        let digest = [0xab, 0xcd, 0xef];
        let mut indices = [0_u32; 2];

        message_to_indices(&parameters, &digest, &mut indices).unwrap();

        assert_eq!(indices, [0xabc, 0xdef]);
    }

    #[test]
    fn message_to_indices_rejects_wrong_digest_length() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let expected = digest_bytes(&parameters).unwrap();
        let digest = [0_u8; 40];
        let mut indices = [0_u32; 35];

        assert_eq!(
            message_to_indices(
                &parameters,
                &digest[..expected - 1],
                &mut indices[..parameters.k],
            ),
            Err(ForsError::InvalidDigestLength {
                expected,
                actual: expected - 1,
            })
        );
    }

    #[test]
    fn message_to_indices_rejects_wrong_index_count() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let digest = [0_u8; 40];
        let expected_digest_bytes = digest_bytes(&parameters).unwrap();
        let mut indices = [0_u32; 35];

        assert_eq!(
            message_to_indices(
                &parameters,
                &digest[..expected_digest_bytes],
                &mut indices[..parameters.k - 1],
            ),
            Err(ForsError::InvalidIndexCount {
                expected: parameters.k,
                actual: parameters.k - 1,
            })
        );
    }

    #[test]
    fn secret_value_index_numbers_tree_sets_consecutively() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let leaf_count = leaves_per_tree(&parameters).unwrap();

        assert_eq!(
            secret_value_index(&parameters, 3, 7),
            Ok((3 * leaf_count + 7) as u32)
        );
    }

    #[test]
    fn secret_value_index_rejects_invalid_tree() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();

        assert_eq!(
            secret_value_index(&parameters, parameters.k, 0),
            Err(ForsError::InvalidTreeIndex {
                tree: parameters.k,
                tree_count: parameters.k,
            })
        );
    }

    #[test]
    fn secret_value_index_rejects_invalid_leaf() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let leaf_count = leaves_per_tree(&parameters).unwrap();

        assert_eq!(
            secret_value_index(&parameters, 0, leaf_count as u32),
            Err(ForsError::InvalidLeafIndex {
                leaf: leaf_count as u32,
                leaf_count,
            })
        );
    }

    #[test]
    fn secret_value_matches_direct_prf_evaluation() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0x11_u8; 32];
        let public_seed = [0x22_u8; 32];
        let address = fors_address();
        let index = 0x0001_2345;
        let mut generated = [0_u8; 32];
        let mut expected = [0_u8; 32];

        secret_value(
            &parameters,
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            9,
            index,
            &mut generated[..parameters.n],
        )
        .unwrap();

        let mut secret_address = address;
        secret_address.set_type_and_clear(AddressType::ForsPrf);
        secret_address.set_key_pair_address(9);
        secret_address.set_tree_index(index);

        HashSuite::new(&parameters)
            .prf(
                &public_seed[..parameters.n],
                &secret_seed[..parameters.n],
                &secret_address,
                &mut expected[..parameters.n],
            )
            .unwrap();

        assert_eq!(&generated[..parameters.n], &expected[..parameters.n]);
    }

    #[test]
    fn selected_secret_value_uses_the_global_fors_index() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let secret_seed = [0x31_u8; 32];
        let public_seed = [0x42_u8; 32];
        let address = fors_address();
        let tree = 2;
        let leaf = 17;
        let index = secret_value_index(&parameters, tree, leaf).unwrap();
        let mut selected = [0_u8; 32];
        let mut direct = [0_u8; 32];

        selected_secret_value(
            &parameters,
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            ForsPosition {
                key_pair_address: 9,
                tree,
                leaf,
            },
            &mut selected[..parameters.n],
        )
        .unwrap();

        secret_value(
            &parameters,
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            9,
            index,
            &mut direct[..parameters.n],
        )
        .unwrap();

        assert_eq!(&selected[..parameters.n], &direct[..parameters.n]);
    }

    #[test]
    fn hash_errors_are_preserved() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let secret_seed = [0_u8; 16];
        let public_seed = [0_u8; 15];
        let address = fors_address();
        let mut output = [0_u8; 16];

        assert_eq!(
            secret_value(
                &parameters,
                &secret_seed,
                &public_seed,
                &address,
                9,
                0,
                &mut output,
            ),
            Err(ForsError::Hash(HashError::InvalidInputLength {
                input: "public seed",
                expected: 16,
                actual: 15,
            }))
        );
    }
}
