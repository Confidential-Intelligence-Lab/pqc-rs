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

    /// The caller supplied an authentication path with the wrong length.
    InvalidAuthenticationPathLength {
        /// Required authentication-path length in bytes.
        expected: usize,

        /// Supplied authentication-path length in bytes.
        actual: usize,
    },

    /// The caller supplied a FORS signature buffer with the wrong length.
    InvalidSignatureLength {
        /// Required FORS signature length in bytes.
        expected: usize,

        /// Supplied signature-buffer length in bytes.
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

    /// The requested node height exceeds the configured FORS tree height.
    InvalidNodeHeight {
        /// Requested node height.
        height: u32,

        /// Configured FORS tree height.
        tree_height: usize,
    },

    /// The requested node index is outside the forest at its height.
    InvalidNodeIndex {
        /// Requested node height.
        height: u32,

        /// Supplied forest-wide node index.
        index: u32,

        /// Number of nodes at the requested height.
        node_count: u64,
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
            Self::InvalidAuthenticationPathLength { expected, actual } => {
                write!(
                    formatter,
                    "invalid FORS authentication-path length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidSignatureLength { expected, actual } => {
                write!(
                    formatter,
                    "invalid FORS signature length: expected {expected} bytes, got {actual}"
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
            Self::InvalidNodeHeight {
                height,
                tree_height,
            } => {
                write!(
                    formatter,
                    "FORS node height {height} exceeds the configured tree height {tree_height}"
                )
            }
            Self::InvalidNodeIndex {
                height,
                index,
                node_count,
            } => {
                write!(
                    formatter,
                    "FORS node index {index} is outside the {node_count} nodes at height {height}"
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

impl ForsPosition {
    /// Resolve this tree-local position to the global FORS secret-value index.
    ///
    /// FIPS 205 numbers the leaves of all `k` FORS trees consecutively:
    ///
    /// `index = tree * 2^a + leaf`.
    pub fn global_index(self, parameters: &SlhDsaParameters) -> Result<u32, ForsError> {
        secret_value_index(parameters, self.tree, self.leaf)
    }
}

/// Coordinates of a node within the complete FORS forest.
///
/// FIPS 205 numbers nodes continuously across all `k` FORS trees at every
/// height. At height zero, `index` is therefore the global FORS secret-value
/// index. At higher levels, it is the forest-wide node index at that height.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForsNodePosition {
    /// Key-pair address inherited from the enclosing hypertree operation.
    pub key_pair_address: u32,

    /// Height of the node above the leaves.
    pub height: u32,

    /// Forest-wide node index at this height.
    pub index: u32,
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
    let index = position.global_index(parameters)?;

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

/// Generate a FORS leaf from its global secret-value index.
///
/// This implements the leaf case of FIPS 205 `fors_node`. The secret value is
/// generated with a `FORS_PRF` address and then hashed with an address of type
/// `FORS_TREE`, tree height zero, and the same global tree index.
///
/// The supplied address contributes the layer and tree address. The key-pair
/// address is restored after each type transition because
/// [`Address::set_type_and_clear`] clears all type-dependent words.
pub fn leaf(
    parameters: &SlhDsaParameters,
    secret_seed: &[u8],
    public_seed: &[u8],
    fors_address: &Address,
    key_pair_address: u32,
    index: u32,
    output: &mut [u8],
) -> Result<(), ForsError> {
    let mut secret_value_bytes = [0_u8; 32];

    secret_value(
        parameters,
        secret_seed,
        public_seed,
        fors_address,
        key_pair_address,
        index,
        &mut secret_value_bytes[..parameters.n],
    )?;

    let mut tree_address = *fors_address;
    tree_address.set_type_and_clear(AddressType::ForsTree);
    tree_address.set_key_pair_address(key_pair_address);
    tree_address.set_tree_height(0);
    tree_address.set_tree_index(index);

    HashSuite::new(parameters).f(
        public_seed,
        &tree_address,
        &secret_value_bytes[..parameters.n],
        output,
    )?;

    Ok(())
}

/// Generate the FORS leaf selected by a tree-local position.
pub fn selected_leaf(
    parameters: &SlhDsaParameters,
    secret_seed: &[u8],
    public_seed: &[u8],
    fors_address: &Address,
    position: ForsPosition,
    output: &mut [u8],
) -> Result<(), ForsError> {
    let index = position.global_index(parameters)?;

    leaf(
        parameters,
        secret_seed,
        public_seed,
        fors_address,
        position.key_pair_address,
        index,
        output,
    )
}

/// Hash two child nodes into one internal FORS tree node.
///
/// The node coordinates are local to one FORS tree. `height` is the height of
/// the parent node above the leaves, and `index` is the parent node's
/// left-to-right index at that height.
///
/// The supplied address contributes the layer and tree address. Changing the
/// address type clears all type-dependent words, so the key-pair address,
/// tree height, and tree index are restored explicitly before evaluating `H`.
pub fn parent_node(
    parameters: &SlhDsaParameters,
    public_seed: &[u8],
    fors_address: &Address,
    position: ForsNodePosition,
    left: &[u8],
    right: &[u8],
    output: &mut [u8],
) -> Result<(), ForsError> {
    let mut tree_address = *fors_address;
    tree_address.set_type_and_clear(AddressType::ForsTree);
    tree_address.set_key_pair_address(position.key_pair_address);
    tree_address.set_tree_height(position.height);
    tree_address.set_tree_index(position.index);

    HashSuite::new(parameters).h(public_seed, &tree_address, left, right, output)?;

    Ok(())
}

/// Return the number of FORS nodes at a given height across the complete forest.
fn nodes_at_height(parameters: &SlhDsaParameters, height: u32) -> Result<u64, ForsError> {
    if height as usize > parameters.a {
        return Err(ForsError::InvalidNodeHeight {
            height,
            tree_height: parameters.a,
        });
    }

    let remaining_height = parameters
        .a
        .checked_sub(height as usize)
        .ok_or(ForsError::ParameterOverflow)?;

    let nodes_per_tree = 1_u64
        .checked_shl(u32::try_from(remaining_height).map_err(|_| ForsError::ParameterOverflow)?)
        .ok_or(ForsError::ParameterOverflow)?;

    (parameters.k as u64)
        .checked_mul(nodes_per_tree)
        .ok_or(ForsError::ParameterOverflow)
}

/// Validate a forest-wide FORS node coordinate.
fn validate_node_position(
    parameters: &SlhDsaParameters,
    position: ForsNodePosition,
) -> Result<(), ForsError> {
    let node_count = nodes_at_height(parameters, position.height)?;

    if u64::from(position.index) >= node_count {
        return Err(ForsError::InvalidNodeIndex {
            height: position.height,
            index: position.index,
            node_count,
        });
    }

    Ok(())
}

/// Generate an arbitrary node in the complete FORS forest.
///
/// This implements FIPS 205 `fors_node`. At height zero, the node is generated
/// directly from the global FORS secret-value index. At higher levels, the
/// function recursively generates the two children and combines them with
/// [`parent_node`].
pub fn node(
    parameters: &SlhDsaParameters,
    secret_seed: &[u8],
    public_seed: &[u8],
    fors_address: &Address,
    position: ForsNodePosition,
    output: &mut [u8],
) -> Result<(), ForsError> {
    validate_node_position(parameters, position)?;

    if position.height == 0 {
        return leaf(
            parameters,
            secret_seed,
            public_seed,
            fors_address,
            position.key_pair_address,
            position.index,
            output,
        );
    }

    let child_height = position
        .height
        .checked_sub(1)
        .ok_or(ForsError::ParameterOverflow)?;

    let left_index = position
        .index
        .checked_mul(2)
        .ok_or(ForsError::ParameterOverflow)?;

    let right_index = left_index
        .checked_add(1)
        .ok_or(ForsError::ParameterOverflow)?;

    let mut left = [0_u8; 32];
    let mut right = [0_u8; 32];

    node(
        parameters,
        secret_seed,
        public_seed,
        fors_address,
        ForsNodePosition {
            key_pair_address: position.key_pair_address,
            height: child_height,
            index: left_index,
        },
        &mut left[..parameters.n],
    )?;

    node(
        parameters,
        secret_seed,
        public_seed,
        fors_address,
        ForsNodePosition {
            key_pair_address: position.key_pair_address,
            height: child_height,
            index: right_index,
        },
        &mut right[..parameters.n],
    )?;

    parent_node(
        parameters,
        public_seed,
        fors_address,
        position,
        &left[..parameters.n],
        &right[..parameters.n],
        output,
    )
}

/// Return the encoded length of one FORS authentication path.
///
/// A FORS authentication path contains one `n`-byte sibling node for each of
/// the `a` levels between a selected leaf and its tree root.
pub fn authentication_path_bytes(parameters: &SlhDsaParameters) -> Result<usize, ForsError> {
    parameters
        .a
        .checked_mul(parameters.n)
        .ok_or(ForsError::ParameterOverflow)
}

/// Generate the authentication path for a selected FORS leaf.
///
/// The output contains `a` consecutive `n`-byte nodes, ordered from the leaf
/// level toward the root. For level `j`, the sibling node has height `j` and
/// forest-wide index
///
/// `tree * 2^(a - j) + ((leaf >> j) ^ 1)`.
pub fn authentication_path(
    parameters: &SlhDsaParameters,
    secret_seed: &[u8],
    public_seed: &[u8],
    fors_address: &Address,
    position: ForsPosition,
    output: &mut [u8],
) -> Result<(), ForsError> {
    let expected = authentication_path_bytes(parameters)?;

    if output.len() != expected {
        return Err(ForsError::InvalidAuthenticationPathLength {
            expected,
            actual: output.len(),
        });
    }

    // Validate both the selected tree and the tree-local leaf before deriving
    // any forest-wide authentication-node coordinates.
    position.global_index(parameters)?;

    for level in 0..parameters.a {
        let height = u32::try_from(level).map_err(|_| ForsError::ParameterOverflow)?;
        let remaining_height = parameters
            .a
            .checked_sub(level)
            .ok_or(ForsError::ParameterOverflow)?;

        let nodes_per_tree = 1_u64
            .checked_shl(u32::try_from(remaining_height).map_err(|_| ForsError::ParameterOverflow)?)
            .ok_or(ForsError::ParameterOverflow)?;

        let tree_base = (position.tree as u64)
            .checked_mul(nodes_per_tree)
            .ok_or(ForsError::ParameterOverflow)?;

        let sibling_local_index = u64::from(position.leaf.checked_shr(height).unwrap_or(0) ^ 1);

        let sibling_index = tree_base
            .checked_add(sibling_local_index)
            .ok_or(ForsError::ParameterOverflow)?;

        let sibling_index =
            u32::try_from(sibling_index).map_err(|_| ForsError::ParameterOverflow)?;

        let start = level
            .checked_mul(parameters.n)
            .ok_or(ForsError::ParameterOverflow)?;
        let end = start
            .checked_add(parameters.n)
            .ok_or(ForsError::ParameterOverflow)?;

        node(
            parameters,
            secret_seed,
            public_seed,
            fors_address,
            ForsNodePosition {
                key_pair_address: position.key_pair_address,
                height,
                index: sibling_index,
            },
            &mut output[start..end],
        )?;
    }

    Ok(())
}

/// Generate the root of the FORS tree containing a selected leaf.
///
/// The selected leaf is validated even though every leaf in the same FORS tree
/// resolves to the same root. At height `a`, the forest-wide node index equals
/// the selected tree index.
pub fn selected_tree_root(
    parameters: &SlhDsaParameters,
    secret_seed: &[u8],
    public_seed: &[u8],
    fors_address: &Address,
    position: ForsPosition,
    output: &mut [u8],
) -> Result<(), ForsError> {
    position.global_index(parameters)?;

    let height = u32::try_from(parameters.a).map_err(|_| ForsError::UnsupportedTreeHeight {
        height: parameters.a,
    })?;

    let index = u32::try_from(position.tree).map_err(|_| ForsError::ParameterOverflow)?;

    node(
        parameters,
        secret_seed,
        public_seed,
        fors_address,
        ForsNodePosition {
            key_pair_address: position.key_pair_address,
            height,
            index,
        },
        output,
    )
}

/// Maximum number of FORS trees among the FIPS 205 parameter sets.
const MAX_FORS_TREES: usize = 35;

/// Return the encoded length of a FORS signature.
///
/// Each of the `k` FORS trees contributes one selected `n`-byte secret value
/// followed by an authentication path containing `a` `n`-byte nodes.
pub fn signature_bytes(parameters: &SlhDsaParameters) -> Result<usize, ForsError> {
    let elements_per_tree = parameters
        .a
        .checked_add(1)
        .ok_or(ForsError::ParameterOverflow)?;

    parameters
        .k
        .checked_mul(elements_per_tree)
        .and_then(|elements| elements.checked_mul(parameters.n))
        .ok_or(ForsError::ParameterOverflow)
}

/// Generate a deterministic FORS signature.
///
/// This implements FIPS 205 `fors_sign`. The digest is split into `k`
/// `a`-bit indices. For each FORS tree, the signature contains:
///
/// 1. the selected `n`-byte secret value; and
/// 2. the corresponding `a * n`-byte authentication path.
///
/// Tree signatures are concatenated in increasing tree-index order.
pub fn sign(
    parameters: &SlhDsaParameters,
    digest: &[u8],
    secret_seed: &[u8],
    public_seed: &[u8],
    fors_address: &Address,
    key_pair_address: u32,
    signature: &mut [u8],
) -> Result<(), ForsError> {
    let expected_signature_bytes = signature_bytes(parameters)?;

    if signature.len() != expected_signature_bytes {
        return Err(ForsError::InvalidSignatureLength {
            expected: expected_signature_bytes,
            actual: signature.len(),
        });
    }

    if parameters.k > MAX_FORS_TREES {
        return Err(ForsError::ParameterOverflow);
    }

    let mut indices = [0_u32; MAX_FORS_TREES];
    message_to_indices(parameters, digest, &mut indices[..parameters.k])?;

    let authentication_bytes = authentication_path_bytes(parameters)?;
    let tree_signature_bytes = parameters
        .n
        .checked_add(authentication_bytes)
        .ok_or(ForsError::ParameterOverflow)?;

    for (tree, leaf) in indices[..parameters.k].iter().copied().enumerate() {
        let tree_start = tree
            .checked_mul(tree_signature_bytes)
            .ok_or(ForsError::ParameterOverflow)?;

        let secret_end = tree_start
            .checked_add(parameters.n)
            .ok_or(ForsError::ParameterOverflow)?;

        let tree_end = tree_start
            .checked_add(tree_signature_bytes)
            .ok_or(ForsError::ParameterOverflow)?;

        let position = ForsPosition {
            key_pair_address,
            tree,
            leaf,
        };

        selected_secret_value(
            parameters,
            secret_seed,
            public_seed,
            fors_address,
            position,
            &mut signature[tree_start..secret_end],
        )?;

        authentication_path(
            parameters,
            secret_seed,
            public_seed,
            fors_address,
            position,
            &mut signature[secret_end..tree_end],
        )?;
    }

    Ok(())
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
    fn fors_position_resolves_to_the_global_secret_value_index() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let position = ForsPosition {
            key_pair_address: 9,
            tree: 3,
            leaf: 7,
        };

        assert_eq!(
            position.global_index(&parameters),
            secret_value_index(&parameters, position.tree, position.leaf)
        );
    }

    #[test]
    fn fors_position_preserves_the_key_pair_address() {
        let parameters = SlhDsaParameterSet::Shake256f.parameters();
        let position = ForsPosition {
            key_pair_address: 0x1122_3344,
            tree: 1,
            leaf: 2,
        };

        assert!(position.global_index(&parameters).is_ok());
        assert_eq!(position.key_pair_address, 0x1122_3344);
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
    #[test]
    fn leaf_matches_direct_secret_generation_and_f_evaluation() {
        for parameter_set in [
            SlhDsaParameterSet::Sha2_128s,
            SlhDsaParameterSet::Shake128s,
            SlhDsaParameterSet::Sha2_256f,
            SlhDsaParameterSet::Shake256f,
        ] {
            let parameters = parameter_set.parameters();
            let secret_seed = [0x31_u8; 32];
            let public_seed = [0x57_u8; 32];
            let address = fors_address();
            let key_pair_address = 9;
            let index = 17;

            let mut actual = [0_u8; 32];
            leaf(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                key_pair_address,
                index,
                &mut actual[..parameters.n],
            )
            .unwrap();

            let mut secret = [0_u8; 32];
            secret_value(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                key_pair_address,
                index,
                &mut secret[..parameters.n],
            )
            .unwrap();

            let mut tree_address = address;
            tree_address.set_type_and_clear(AddressType::ForsTree);
            tree_address.set_key_pair_address(key_pair_address);
            tree_address.set_tree_height(0);
            tree_address.set_tree_index(index);

            let mut expected = [0_u8; 32];
            HashSuite::new(&parameters)
                .f(
                    &public_seed[..parameters.n],
                    &tree_address,
                    &secret[..parameters.n],
                    &mut expected[..parameters.n],
                )
                .unwrap();

            assert_eq!(
                &actual[..parameters.n],
                &expected[..parameters.n],
                "{parameter_set:?}"
            );
        }
    }

    #[test]
    fn selected_leaf_uses_the_global_fors_index() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0x42_u8; 32];
        let public_seed = [0x24_u8; 32];
        let address = fors_address();
        let position = ForsPosition {
            key_pair_address: 11,
            tree: 3,
            leaf: 7,
        };
        let index = position.global_index(&parameters).unwrap();

        let mut selected = [0_u8; 32];
        selected_leaf(
            &parameters,
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            position,
            &mut selected[..parameters.n],
        )
        .unwrap();

        let mut direct = [0_u8; 32];
        leaf(
            &parameters,
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            position.key_pair_address,
            index,
            &mut direct[..parameters.n],
        )
        .unwrap();

        assert_eq!(&selected[..parameters.n], &direct[..parameters.n]);
    }

    #[test]
    fn selected_leaf_rejects_an_invalid_tree_position() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let secret_seed = [0_u8; 32];
        let public_seed = [0_u8; 32];
        let address = fors_address();
        let position = ForsPosition {
            key_pair_address: 0,
            tree: parameters.k,
            leaf: 0,
        };
        let mut output = [0_u8; 32];

        assert_eq!(
            selected_leaf(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                position,
                &mut output[..parameters.n],
            ),
            Err(ForsError::InvalidTreeIndex {
                tree: parameters.k,
                tree_count: parameters.k,
            })
        );
    }

    #[test]
    fn selected_leaf_rejects_an_invalid_leaf_position() {
        let parameters = SlhDsaParameterSet::Shake128f.parameters();
        let leaf_count = leaves_per_tree(&parameters).unwrap();
        let secret_seed = [0_u8; 32];
        let public_seed = [0_u8; 32];
        let address = fors_address();
        let position = ForsPosition {
            key_pair_address: 0,
            tree: 0,
            leaf: leaf_count as u32,
        };
        let mut output = [0_u8; 32];

        assert_eq!(
            selected_leaf(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                position,
                &mut output[..parameters.n],
            ),
            Err(ForsError::InvalidLeafIndex {
                leaf: leaf_count as u32,
                leaf_count,
            })
        );
    }

    #[test]
    fn leaf_propagates_output_length_errors() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let secret_seed = [0_u8; 32];
        let public_seed = [0_u8; 32];
        let address = fors_address();
        let mut output = [0_u8; 32];

        assert!(matches!(
            leaf(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                0,
                0,
                &mut output[..parameters.n - 1],
            ),
            Err(ForsError::Hash(_))
        ));
    }

    #[test]
    fn every_parameter_set_generates_a_fors_leaf() {
        let secret_seed = [0xa5_u8; 32];
        let public_seed = [0x5a_u8; 32];
        let address = fors_address();

        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let mut output = [0_u8; 32];

            selected_leaf(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                ForsPosition {
                    key_pair_address: 9,
                    tree: parameters.k - 1,
                    leaf: 0,
                },
                &mut output[..parameters.n],
            )
            .unwrap();

            assert_ne!(
                &output[..parameters.n],
                &[0_u8; 32][..parameters.n],
                "{parameter_set:?}"
            );
        }
    }
    #[test]
    fn parent_node_matches_direct_h_evaluation() {
        for parameter_set in [
            SlhDsaParameterSet::Sha2_128s,
            SlhDsaParameterSet::Shake128s,
            SlhDsaParameterSet::Sha2_256f,
            SlhDsaParameterSet::Shake256f,
        ] {
            let parameters = parameter_set.parameters();
            let public_seed = [0x39_u8; 32];
            let left = [0x51_u8; 32];
            let right = [0xa7_u8; 32];
            let address = fors_address();
            let key_pair_address = 13;
            let height = 4;
            let index = 6;

            let mut actual = [0_u8; 32];
            parent_node(
                &parameters,
                &public_seed[..parameters.n],
                &address,
                ForsNodePosition {
                    key_pair_address,
                    height,
                    index,
                },
                &left[..parameters.n],
                &right[..parameters.n],
                &mut actual[..parameters.n],
            )
            .unwrap();

            let mut tree_address = address;
            tree_address.set_type_and_clear(AddressType::ForsTree);
            tree_address.set_key_pair_address(key_pair_address);
            tree_address.set_tree_height(height);
            tree_address.set_tree_index(index);

            let mut expected = [0_u8; 32];
            HashSuite::new(&parameters)
                .h(
                    &public_seed[..parameters.n],
                    &tree_address,
                    &left[..parameters.n],
                    &right[..parameters.n],
                    &mut expected[..parameters.n],
                )
                .unwrap();

            assert_eq!(
                &actual[..parameters.n],
                &expected[..parameters.n],
                "{parameter_set:?}"
            );
        }
    }

    #[test]
    fn parent_node_domain_separates_tree_coordinates() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let public_seed = [0x63_u8; 32];
        let left = [0x18_u8; 32];
        let right = [0x81_u8; 32];
        let address = fors_address();

        let mut baseline = [0_u8; 32];
        parent_node(
            &parameters,
            &public_seed[..parameters.n],
            &address,
            ForsNodePosition {
                key_pair_address: 5,
                height: 2,
                index: 7,
            },
            &left[..parameters.n],
            &right[..parameters.n],
            &mut baseline[..parameters.n],
        )
        .unwrap();

        let mut different_height = [0_u8; 32];
        parent_node(
            &parameters,
            &public_seed[..parameters.n],
            &address,
            ForsNodePosition {
                key_pair_address: 5,
                height: 3,
                index: 7,
            },
            &left[..parameters.n],
            &right[..parameters.n],
            &mut different_height[..parameters.n],
        )
        .unwrap();

        let mut different_index = [0_u8; 32];
        parent_node(
            &parameters,
            &public_seed[..parameters.n],
            &address,
            ForsNodePosition {
                key_pair_address: 5,
                height: 2,
                index: 8,
            },
            &left[..parameters.n],
            &right[..parameters.n],
            &mut different_index[..parameters.n],
        )
        .unwrap();

        assert_ne!(&baseline[..parameters.n], &different_height[..parameters.n]);
        assert_ne!(&baseline[..parameters.n], &different_index[..parameters.n]);
    }

    #[test]
    fn parent_node_domain_separates_key_pair_addresses() {
        let parameters = SlhDsaParameterSet::Sha2_192f.parameters();
        let public_seed = [0xc3_u8; 32];
        let left = [0x2d_u8; 32];
        let right = [0xd2_u8; 32];
        let address = fors_address();

        let mut first = [0_u8; 32];
        parent_node(
            &parameters,
            &public_seed[..parameters.n],
            &address,
            ForsNodePosition {
                key_pair_address: 11,
                height: 1,
                index: 0,
            },
            &left[..parameters.n],
            &right[..parameters.n],
            &mut first[..parameters.n],
        )
        .unwrap();

        let mut second = [0_u8; 32];
        parent_node(
            &parameters,
            &public_seed[..parameters.n],
            &address,
            ForsNodePosition {
                key_pair_address: 12,
                height: 1,
                index: 0,
            },
            &left[..parameters.n],
            &right[..parameters.n],
            &mut second[..parameters.n],
        )
        .unwrap();

        assert_ne!(&first[..parameters.n], &second[..parameters.n]);
    }

    #[test]
    fn parent_node_propagates_hash_length_errors() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let public_seed = [0_u8; 32];
        let left = [0_u8; 32];
        let right = [0_u8; 32];
        let address = fors_address();
        let mut output = [0_u8; 32];

        assert!(matches!(
            parent_node(
                &parameters,
                &public_seed[..parameters.n],
                &address,
                ForsNodePosition {
                    key_pair_address: 0,
                    height: 1,
                    index: 0,
                },
                &left[..parameters.n - 1],
                &right[..parameters.n],
                &mut output[..parameters.n],
            ),
            Err(ForsError::Hash(_))
        ));

        assert!(matches!(
            parent_node(
                &parameters,
                &public_seed[..parameters.n],
                &address,
                ForsNodePosition {
                    key_pair_address: 0,
                    height: 1,
                    index: 0,
                },
                &left[..parameters.n],
                &right[..parameters.n],
                &mut output[..parameters.n - 1],
            ),
            Err(ForsError::Hash(_))
        ));
    }

    #[test]
    fn every_parameter_set_hashes_a_fors_parent_node() {
        let public_seed = [0x96_u8; 32];
        let left = [0x3c_u8; 32];
        let right = [0xc3_u8; 32];
        let address = fors_address();

        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let mut output = [0_u8; 32];

            parent_node(
                &parameters,
                &public_seed[..parameters.n],
                &address,
                ForsNodePosition {
                    key_pair_address: 17,
                    height: 1,
                    index: 0,
                },
                &left[..parameters.n],
                &right[..parameters.n],
                &mut output[..parameters.n],
            )
            .unwrap();

            assert_ne!(
                &output[..parameters.n],
                &[0_u8; 32][..parameters.n],
                "{parameter_set:?}"
            );
        }
    }
    #[test]
    fn node_height_zero_matches_leaf_generation() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let secret_seed = [0x12_u8; 32];
        let public_seed = [0x34_u8; 32];
        let address = fors_address();
        let position = ForsNodePosition {
            key_pair_address: 9,
            height: 0,
            index: 17,
        };

        let mut actual = [0_u8; 32];
        node(
            &parameters,
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            position,
            &mut actual[..parameters.n],
        )
        .unwrap();

        let mut expected = [0_u8; 32];
        leaf(
            &parameters,
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            position.key_pair_address,
            position.index,
            &mut expected[..parameters.n],
        )
        .unwrap();

        assert_eq!(&actual[..parameters.n], &expected[..parameters.n]);
    }

    #[test]
    fn node_height_one_matches_two_leaves_and_parent_hashing() {
        for parameter_set in [
            SlhDsaParameterSet::Sha2_128s,
            SlhDsaParameterSet::Shake128s,
            SlhDsaParameterSet::Sha2_256f,
            SlhDsaParameterSet::Shake256f,
        ] {
            let parameters = parameter_set.parameters();
            let secret_seed = [0x56_u8; 32];
            let public_seed = [0x78_u8; 32];
            let address = fors_address();
            let position = ForsNodePosition {
                key_pair_address: 11,
                height: 1,
                index: 3,
            };

            let mut actual = [0_u8; 32];
            node(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                position,
                &mut actual[..parameters.n],
            )
            .unwrap();

            let mut left = [0_u8; 32];
            leaf(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                position.key_pair_address,
                2 * position.index,
                &mut left[..parameters.n],
            )
            .unwrap();

            let mut right = [0_u8; 32];
            leaf(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                position.key_pair_address,
                2 * position.index + 1,
                &mut right[..parameters.n],
            )
            .unwrap();

            let mut expected = [0_u8; 32];
            parent_node(
                &parameters,
                &public_seed[..parameters.n],
                &address,
                position,
                &left[..parameters.n],
                &right[..parameters.n],
                &mut expected[..parameters.n],
            )
            .unwrap();

            assert_eq!(
                &actual[..parameters.n],
                &expected[..parameters.n],
                "{parameter_set:?}"
            );
        }
    }

    #[test]
    fn node_height_two_matches_recursive_children() {
        let parameters = SlhDsaParameterSet::Shake192f.parameters();
        let secret_seed = [0x9a_u8; 32];
        let public_seed = [0xbc_u8; 32];
        let address = fors_address();
        let position = ForsNodePosition {
            key_pair_address: 21,
            height: 2,
            index: 2,
        };

        let mut actual = [0_u8; 32];
        node(
            &parameters,
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            position,
            &mut actual[..parameters.n],
        )
        .unwrap();

        let child_height = position.height - 1;

        let mut left = [0_u8; 32];
        node(
            &parameters,
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            ForsNodePosition {
                key_pair_address: position.key_pair_address,
                height: child_height,
                index: 2 * position.index,
            },
            &mut left[..parameters.n],
        )
        .unwrap();

        let mut right = [0_u8; 32];
        node(
            &parameters,
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            ForsNodePosition {
                key_pair_address: position.key_pair_address,
                height: child_height,
                index: 2 * position.index + 1,
            },
            &mut right[..parameters.n],
        )
        .unwrap();

        let mut expected = [0_u8; 32];
        parent_node(
            &parameters,
            &public_seed[..parameters.n],
            &address,
            position,
            &left[..parameters.n],
            &right[..parameters.n],
            &mut expected[..parameters.n],
        )
        .unwrap();

        assert_eq!(&actual[..parameters.n], &expected[..parameters.n]);
    }

    #[test]
    fn node_rejects_heights_above_the_fors_tree() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let secret_seed = [0_u8; 32];
        let public_seed = [0_u8; 32];
        let address = fors_address();
        let mut output = [0_u8; 32];

        let height = u32::try_from(parameters.a).unwrap() + 1;

        assert_eq!(
            node(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                ForsNodePosition {
                    key_pair_address: 0,
                    height,
                    index: 0,
                },
                &mut output[..parameters.n],
            ),
            Err(ForsError::InvalidNodeHeight {
                height,
                tree_height: parameters.a,
            })
        );
    }

    #[test]
    fn node_rejects_indices_outside_the_fors_forest() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0_u8; 32];
        let public_seed = [0_u8; 32];
        let address = fors_address();
        let mut output = [0_u8; 32];

        let height = 1;
        let node_count = nodes_at_height(&parameters, height).unwrap();
        let index = u32::try_from(node_count).unwrap();

        assert_eq!(
            node(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                ForsNodePosition {
                    key_pair_address: 0,
                    height,
                    index,
                },
                &mut output[..parameters.n],
            ),
            Err(ForsError::InvalidNodeIndex {
                height,
                index,
                node_count,
            })
        );
    }

    #[test]
    fn authentication_path_length_is_a_times_n() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();

            assert_eq!(
                authentication_path_bytes(&parameters),
                Ok(parameters.a * parameters.n)
            );
        }
    }

    #[test]
    fn authentication_path_rejects_the_wrong_output_length() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let secret_seed = [0_u8; 32];
        let public_seed = [0_u8; 32];
        let address = fors_address();
        let position = ForsPosition {
            key_pair_address: 9,
            tree: 0,
            leaf: 0,
        };
        let expected = authentication_path_bytes(&parameters).unwrap();
        let mut output = [0_u8; 512];

        assert_eq!(
            authentication_path(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                position,
                &mut output[..expected - 1],
            ),
            Err(ForsError::InvalidAuthenticationPathLength {
                expected,
                actual: expected - 1,
            })
        );
    }

    #[test]
    fn authentication_path_matches_independent_sibling_nodes() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0x21_u8; 32];
        let public_seed = [0x43_u8; 32];
        let address = fors_address();
        let position = ForsPosition {
            key_pair_address: 13,
            tree: 2,
            leaf: 17,
        };

        let path_length = authentication_path_bytes(&parameters).unwrap();
        let mut path = [0_u8; 512];

        authentication_path(
            &parameters,
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            position,
            &mut path[..path_length],
        )
        .unwrap();

        for level in 0..parameters.a {
            let height = u32::try_from(level).unwrap();
            let nodes_per_tree = 1_u64 << (parameters.a - level);
            let sibling_index =
                position.tree as u64 * nodes_per_tree + u64::from((position.leaf >> height) ^ 1);

            let mut expected = [0_u8; 32];
            node(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                ForsNodePosition {
                    key_pair_address: position.key_pair_address,
                    height,
                    index: u32::try_from(sibling_index).unwrap(),
                },
                &mut expected[..parameters.n],
            )
            .unwrap();

            let start = level * parameters.n;
            let end = start + parameters.n;

            assert_eq!(
                &path[start..end],
                &expected[..parameters.n],
                "authentication node mismatch at level {level}"
            );
        }
    }

    #[test]
    fn every_parameter_set_generates_an_authentication_path() {
        let secret_seed = [0x65_u8; 32];
        let public_seed = [0x87_u8; 32];
        let address = fors_address();
        let mut path = [0_u8; 512];

        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let path_length = authentication_path_bytes(&parameters).unwrap();
            let leaf_count = leaves_per_tree(&parameters).unwrap();

            authentication_path(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                ForsPosition {
                    key_pair_address: 7,
                    tree: parameters.k - 1,
                    leaf: u32::try_from(leaf_count - 1).unwrap(),
                },
                &mut path[..path_length],
            )
            .unwrap();
        }
    }

    #[test]
    fn selected_tree_root_matches_the_full_height_node() {
        for parameter_set in [
            SlhDsaParameterSet::Sha2_128s,
            SlhDsaParameterSet::Shake192f,
            SlhDsaParameterSet::Sha2_256f,
        ] {
            let parameters = parameter_set.parameters();
            let secret_seed = [0xa9_u8; 32];
            let public_seed = [0xcb_u8; 32];
            let address = fors_address();
            let position = ForsPosition {
                key_pair_address: 19,
                tree: 1,
                leaf: 3,
            };

            let mut actual = [0_u8; 32];
            selected_tree_root(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                position,
                &mut actual[..parameters.n],
            )
            .unwrap();

            let mut expected = [0_u8; 32];
            node(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                ForsNodePosition {
                    key_pair_address: position.key_pair_address,
                    height: u32::try_from(parameters.a).unwrap(),
                    index: u32::try_from(position.tree).unwrap(),
                },
                &mut expected[..parameters.n],
            )
            .unwrap();

            assert_eq!(
                &actual[..parameters.n],
                &expected[..parameters.n],
                "{parameter_set:?}"
            );
        }
    }

    #[test]
    fn selected_tree_root_domain_separates_key_pair_addresses() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0xed_u8; 32];
        let public_seed = [0x0f_u8; 32];
        let address = fors_address();

        let mut first = [0_u8; 32];
        selected_tree_root(
            &parameters,
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            ForsPosition {
                key_pair_address: 1,
                tree: 0,
                leaf: 0,
            },
            &mut first[..parameters.n],
        )
        .unwrap();

        let mut second = [0_u8; 32];
        selected_tree_root(
            &parameters,
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            ForsPosition {
                key_pair_address: 2,
                tree: 0,
                leaf: 0,
            },
            &mut second[..parameters.n],
        )
        .unwrap();

        assert_ne!(&first[..parameters.n], &second[..parameters.n]);
    }

    #[test]
    fn signature_length_matches_fips_layout() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();

            assert_eq!(
                signature_bytes(&parameters),
                Ok(parameters.k * (parameters.a + 1) * parameters.n)
            );
        }
    }

    #[test]
    fn sign_rejects_the_wrong_signature_length() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let digest = [0_u8; 40];
        let secret_seed = [0_u8; 32];
        let public_seed = [0_u8; 32];
        let address = fors_address();
        let expected = signature_bytes(&parameters).unwrap();
        let digest_length = digest_bytes(&parameters).unwrap();
        let mut signature = [0_u8; 12_000];

        assert_eq!(
            sign(
                &parameters,
                &digest[..digest_length],
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                9,
                &mut signature[..expected - 1],
            ),
            Err(ForsError::InvalidSignatureLength {
                expected,
                actual: expected - 1,
            })
        );
    }

    #[test]
    fn sign_rejects_the_wrong_digest_length() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let digest = [0_u8; 40];
        let secret_seed = [0_u8; 32];
        let public_seed = [0_u8; 32];
        let address = fors_address();
        let signature_length = signature_bytes(&parameters).unwrap();
        let digest_length = digest_bytes(&parameters).unwrap();
        let mut signature = [0_u8; 12_000];

        assert_eq!(
            sign(
                &parameters,
                &digest[..digest_length - 1],
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                9,
                &mut signature[..signature_length],
            ),
            Err(ForsError::InvalidDigestLength {
                expected: digest_length,
                actual: digest_length - 1,
            })
        );
    }

    #[test]
    fn sign_encodes_selected_secret_and_authentication_path() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let digest = [0xa5_u8; 40];
        let secret_seed = [0x31_u8; 32];
        let public_seed = [0x72_u8; 32];
        let address = fors_address();
        let key_pair_address = 17;

        let digest_length = digest_bytes(&parameters).unwrap();
        let signature_length = signature_bytes(&parameters).unwrap();
        let authentication_length = authentication_path_bytes(&parameters).unwrap();
        let tree_signature_length = parameters.n + authentication_length;

        let mut signature = [0_u8; 12_000];
        sign(
            &parameters,
            &digest[..digest_length],
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            key_pair_address,
            &mut signature[..signature_length],
        )
        .unwrap();

        let mut indices = [0_u32; MAX_FORS_TREES];
        message_to_indices(
            &parameters,
            &digest[..digest_length],
            &mut indices[..parameters.k],
        )
        .unwrap();

        for (tree, leaf) in indices[..parameters.k].iter().copied().enumerate() {
            let position = ForsPosition {
                key_pair_address,
                tree,
                leaf,
            };

            let tree_start = tree * tree_signature_length;
            let secret_end = tree_start + parameters.n;
            let tree_end = tree_start + tree_signature_length;

            let mut expected_secret = [0_u8; 32];
            selected_secret_value(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                position,
                &mut expected_secret[..parameters.n],
            )
            .unwrap();

            assert_eq!(
                &signature[tree_start..secret_end],
                &expected_secret[..parameters.n],
                "secret-value mismatch for tree {tree}"
            );

            let mut expected_authentication = [0_u8; 512];
            authentication_path(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                position,
                &mut expected_authentication[..authentication_length],
            )
            .unwrap();

            assert_eq!(
                &signature[secret_end..tree_end],
                &expected_authentication[..authentication_length],
                "authentication-path mismatch for tree {tree}"
            );
        }
    }

    #[test]
    fn sign_is_deterministic() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let digest = [0x19_u8; 40];
        let secret_seed = [0x2a_u8; 32];
        let public_seed = [0x3b_u8; 32];
        let address = fors_address();

        let digest_length = digest_bytes(&parameters).unwrap();
        let signature_length = signature_bytes(&parameters).unwrap();

        let mut first = [0_u8; 12_000];
        sign(
            &parameters,
            &digest[..digest_length],
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            23,
            &mut first[..signature_length],
        )
        .unwrap();

        let mut second = [0_u8; 12_000];
        sign(
            &parameters,
            &digest[..digest_length],
            &secret_seed[..parameters.n],
            &public_seed[..parameters.n],
            &address,
            23,
            &mut second[..signature_length],
        )
        .unwrap();

        assert_eq!(&first[..signature_length], &second[..signature_length]);
    }

    #[test]
    fn every_parameter_set_generates_a_fors_signature() {
        let digest = [0xd4_u8; 40];
        let secret_seed = [0xe5_u8; 32];
        let public_seed = [0xf6_u8; 32];
        let address = fors_address();
        let mut signature = [0_u8; 12_000];

        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let digest_length = digest_bytes(&parameters).unwrap();
            let signature_length = signature_bytes(&parameters).unwrap();

            sign(
                &parameters,
                &digest[..digest_length],
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                29,
                &mut signature[..signature_length],
            )
            .unwrap();
        }
    }
}
