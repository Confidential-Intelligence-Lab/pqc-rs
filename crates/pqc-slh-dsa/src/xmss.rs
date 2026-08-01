//! eXtended Merkle Signature Scheme primitives for SLH-DSA.
//!
//! This initial stage introduces XMSS leaf generation from WOTS+ public keys.
//! Tree-node construction, authentication paths, signing, and reconstruction
//! are added in subsequent stages.

use core::fmt;

use crate::{
    address::{Address, AddressType},
    hash::HashError,
    hash_suite::HashSuite,
    params::SlhDsaParameters,
    wots::{self, WotsError},
};

/// Coordinates of an XMSS tree node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XmssNodePosition {
    /// Height of the node above the leaves.
    pub height: u32,

    /// Node index at the selected height.
    pub index: u32,
}

/// Errors returned by XMSS operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XmssError {
    /// The selected leaf index is outside the XMSS tree.
    InvalidLeafIndex {
        /// Supplied leaf index.
        index: u32,

        /// Number of leaves in the XMSS tree.
        leaf_count: u64,
    },

    /// The supplied node height is invalid for parent-node hashing.
    InvalidParentHeight {
        /// Supplied parent-node height.
        height: u32,
    },

    /// The selected node height exceeds the XMSS tree height.
    InvalidNodeHeight {
        /// Supplied node height.
        height: u32,

        /// Configured XMSS tree height.
        tree_height: usize,
    },

    /// The selected node index is outside the nodes available at its height.
    InvalidNodeIndex {
        /// Supplied node index.
        index: u32,

        /// Selected node height.
        height: u32,

        /// Number of nodes available at that height.
        node_count: u64,
    },

    /// The supplied byte string has the wrong length.
    InvalidByteLength {
        /// Required byte length.
        expected: usize,

        /// Supplied byte length.
        actual: usize,
    },

    /// An XMSS parameter calculation overflowed.
    ParameterOverflow,

    /// WOTS+ processing failed.
    Wots(WotsError),

    /// Hash evaluation failed.
    Hash(HashError),
}

impl fmt::Display for XmssError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLeafIndex { index, leaf_count } => {
                write!(
                    formatter,
                    "XMSS leaf index {index} is outside the configured {leaf_count} leaves"
                )
            }
            Self::InvalidParentHeight { height } => {
                write!(
                    formatter,
                    "XMSS parent-node height must be at least one, got {height}"
                )
            }
            Self::InvalidNodeHeight {
                height,
                tree_height,
            } => {
                write!(
                    formatter,
                    "XMSS node height {height} exceeds the configured tree height {tree_height}"
                )
            }
            Self::InvalidNodeIndex {
                index,
                height,
                node_count,
            } => {
                write!(
                    formatter,
                    "XMSS node index {index} is outside the {node_count} nodes at height {height}"
                )
            }
            Self::InvalidByteLength { expected, actual } => {
                write!(
                    formatter,
                    "invalid XMSS byte length: expected {expected} bytes, got {actual}"
                )
            }
            Self::ParameterOverflow => {
                write!(formatter, "XMSS parameter calculation overflowed")
            }
            Self::Wots(error) => {
                write!(formatter, "XMSS WOTS+ processing failed: {error}")
            }
            Self::Hash(error) => {
                write!(formatter, "XMSS hash evaluation failed: {error}")
            }
        }
    }
}

impl From<WotsError> for XmssError {
    fn from(error: WotsError) -> Self {
        Self::Wots(error)
    }
}

impl From<HashError> for XmssError {
    fn from(error: HashError) -> Self {
        Self::Hash(error)
    }
}

/// Return the number of leaves in one XMSS tree.
pub fn leaf_count(parameters: &SlhDsaParameters) -> Result<u64, XmssError> {
    1_u64
        .checked_shl(u32::try_from(parameters.hp).map_err(|_| XmssError::ParameterOverflow)?)
        .ok_or(XmssError::ParameterOverflow)
}

/// Generate one XMSS leaf.
///
/// In SLH-DSA, an XMSS leaf is the compressed WOTS+ public key associated with
/// the leaf index. The layer and tree components are inherited from
/// `xmss_address`.
pub fn leaf(
    parameters: &SlhDsaParameters,
    secret_seed: &[u8],
    public_seed: &[u8],
    xmss_address: &Address,
    leaf_index: u32,
    output: &mut [u8],
) -> Result<(), XmssError> {
    let leaf_count = leaf_count(parameters)?;

    if u64::from(leaf_index) >= leaf_count {
        return Err(XmssError::InvalidLeafIndex {
            index: leaf_index,
            leaf_count,
        });
    }

    let mut wots_address = *xmss_address;
    wots_address.set_key_pair_address(leaf_index);

    wots::public_key(parameters, secret_seed, public_seed, &wots_address, output)?;

    Ok(())
}

/// Hash two XMSS child nodes into their parent.
///
/// `position.height` is the height of the resulting parent node above the
/// leaves. The function uses the FIPS 205 `TREE` address domain and sets the
/// tree height and tree index explicitly before invoking `H`.
pub fn parent_node(
    parameters: &SlhDsaParameters,
    public_seed: &[u8],
    xmss_address: &Address,
    position: XmssNodePosition,
    left: &[u8],
    right: &[u8],
    output: &mut [u8],
) -> Result<(), XmssError> {
    if position.height == 0 {
        return Err(XmssError::InvalidParentHeight {
            height: position.height,
        });
    }

    for value in [left, right, output] {
        if value.len() != parameters.n {
            return Err(XmssError::InvalidByteLength {
                expected: parameters.n,
                actual: value.len(),
            });
        }
    }

    let mut tree_address = *xmss_address;
    tree_address.set_type_and_clear(AddressType::Tree);
    tree_address.set_tree_height(position.height);
    tree_address.set_tree_index(position.index);

    HashSuite::new(parameters).h(public_seed, &tree_address, left, right, output)?;

    Ok(())
}

/// Generate an arbitrary node in an XMSS tree.
///
/// A node at height zero is the WOTS+-derived XMSS leaf with the same index.
/// A node at height `h > 0` is generated recursively from nodes
/// `(h - 1, 2 * index)` and `(h - 1, 2 * index + 1)`, then combined using
/// [`parent_node`].
pub fn node(
    parameters: &SlhDsaParameters,
    secret_seed: &[u8],
    public_seed: &[u8],
    xmss_address: &Address,
    position: XmssNodePosition,
    output: &mut [u8],
) -> Result<(), XmssError> {
    if output.len() != parameters.n {
        return Err(XmssError::InvalidByteLength {
            expected: parameters.n,
            actual: output.len(),
        });
    }

    let height = usize::try_from(position.height).map_err(|_| XmssError::ParameterOverflow)?;

    if height > parameters.hp {
        return Err(XmssError::InvalidNodeHeight {
            height: position.height,
            tree_height: parameters.hp,
        });
    }

    let levels_above = parameters
        .hp
        .checked_sub(height)
        .ok_or(XmssError::ParameterOverflow)?;

    let node_count = 1_u64
        .checked_shl(u32::try_from(levels_above).map_err(|_| XmssError::ParameterOverflow)?)
        .ok_or(XmssError::ParameterOverflow)?;

    if u64::from(position.index) >= node_count {
        return Err(XmssError::InvalidNodeIndex {
            index: position.index,
            height: position.height,
            node_count,
        });
    }

    if position.height == 0 {
        return leaf(
            parameters,
            secret_seed,
            public_seed,
            xmss_address,
            position.index,
            output,
        );
    }

    let child_height = position
        .height
        .checked_sub(1)
        .ok_or(XmssError::ParameterOverflow)?;

    let left_index = position
        .index
        .checked_mul(2)
        .ok_or(XmssError::ParameterOverflow)?;

    let right_index = left_index
        .checked_add(1)
        .ok_or(XmssError::ParameterOverflow)?;

    let mut left = [0_u8; 32];
    let mut right = [0_u8; 32];

    node(
        parameters,
        secret_seed,
        public_seed,
        xmss_address,
        XmssNodePosition {
            height: child_height,
            index: left_index,
        },
        &mut left[..parameters.n],
    )?;

    node(
        parameters,
        secret_seed,
        public_seed,
        xmss_address,
        XmssNodePosition {
            height: child_height,
            index: right_index,
        },
        &mut right[..parameters.n],
    )?;

    parent_node(
        parameters,
        public_seed,
        xmss_address,
        position,
        &left[..parameters.n],
        &right[..parameters.n],
        output,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{address::AddressType, params::SlhDsaParameterSet};

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

    fn test_address() -> Address {
        let mut address = Address::new();
        address.set_layer_address(2);
        address.set_tree_address(0x0102_0304_0506_0708);
        address.set_type_and_clear(AddressType::WotsHash);
        address
    }

    #[test]
    fn leaf_count_matches_subtree_height() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();

            assert_eq!(leaf_count(&parameters), Ok(1_u64 << parameters.hp));
        }
    }

    #[test]
    fn leaf_rejects_an_out_of_range_index() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0_u8; 16];
        let public_seed = [0_u8; 16];
        let leaf_count = leaf_count(&parameters).unwrap();
        let mut output = [0_u8; 16];

        assert_eq!(
            leaf(
                &parameters,
                &secret_seed,
                &public_seed,
                &test_address(),
                u32::try_from(leaf_count).unwrap(),
                &mut output,
            ),
            Err(XmssError::InvalidLeafIndex {
                index: u32::try_from(leaf_count).unwrap(),
                leaf_count,
            })
        );
    }

    #[test]
    fn leaf_matches_direct_wots_public_key_generation() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0x21_u8; 16];
        let public_seed = [0x43_u8; 16];
        let address = test_address();
        let leaf_index = 7;

        let mut actual = [0_u8; 16];

        leaf(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            leaf_index,
            &mut actual,
        )
        .unwrap();

        let mut wots_address = address;
        wots_address.set_key_pair_address(leaf_index);

        let mut expected = [0_u8; 16];

        wots::public_key(
            &parameters,
            &secret_seed,
            &public_seed,
            &wots_address,
            &mut expected,
        )
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn leaves_are_domain_separated_by_index() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0x65_u8; 16];
        let public_seed = [0x87_u8; 16];
        let address = test_address();

        let mut first = [0_u8; 16];
        let mut second = [0_u8; 16];

        leaf(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            0,
            &mut first,
        )
        .unwrap();

        leaf(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            1,
            &mut second,
        )
        .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn every_parameter_set_generates_an_xmss_leaf() {
        let secret_seed = [0xa9_u8; 32];
        let public_seed = [0xcb_u8; 32];
        let address = test_address();
        let mut output = [0_u8; 32];

        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();

            leaf(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                0,
                &mut output[..parameters.n],
            )
            .unwrap();
        }
    }

    #[test]
    fn parent_node_rejects_height_zero() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let public_seed = [0_u8; 16];
        let left = [0_u8; 16];
        let right = [0_u8; 16];
        let mut output = [0_u8; 16];

        assert_eq!(
            parent_node(
                &parameters,
                &public_seed,
                &test_address(),
                XmssNodePosition {
                    height: 0,
                    index: 0,
                },
                &left,
                &right,
                &mut output,
            ),
            Err(XmssError::InvalidParentHeight { height: 0 })
        );
    }

    #[test]
    fn parent_node_rejects_wrong_child_length() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let public_seed = [0_u8; 16];
        let left = [0_u8; 15];
        let right = [0_u8; 16];
        let mut output = [0_u8; 16];

        assert_eq!(
            parent_node(
                &parameters,
                &public_seed,
                &test_address(),
                XmssNodePosition {
                    height: 1,
                    index: 0,
                },
                &left,
                &right,
                &mut output,
            ),
            Err(XmssError::InvalidByteLength {
                expected: parameters.n,
                actual: left.len(),
            })
        );
    }

    #[test]
    fn parent_node_matches_direct_h_evaluation() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let public_seed = [0x21_u8; 16];
        let left = [0x43_u8; 16];
        let right = [0x65_u8; 16];
        let address = test_address();
        let position = XmssNodePosition {
            height: 3,
            index: 7,
        };

        let mut actual = [0_u8; 16];

        parent_node(
            &parameters,
            &public_seed,
            &address,
            position,
            &left,
            &right,
            &mut actual,
        )
        .unwrap();

        let mut expected_address = address;
        expected_address.set_type_and_clear(AddressType::Tree);
        expected_address.set_tree_height(position.height);
        expected_address.set_tree_index(position.index);

        let mut expected = [0_u8; 16];

        HashSuite::new(&parameters)
            .h(
                &public_seed,
                &expected_address,
                &left,
                &right,
                &mut expected,
            )
            .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn parent_nodes_are_domain_separated_by_coordinates() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let public_seed = [0x87_u8; 16];
        let left = [0xa9_u8; 16];
        let right = [0xcb_u8; 16];
        let address = test_address();

        let mut first = [0_u8; 16];
        let mut second = [0_u8; 16];

        parent_node(
            &parameters,
            &public_seed,
            &address,
            XmssNodePosition {
                height: 1,
                index: 2,
            },
            &left,
            &right,
            &mut first,
        )
        .unwrap();

        parent_node(
            &parameters,
            &public_seed,
            &address,
            XmssNodePosition {
                height: 1,
                index: 3,
            },
            &left,
            &right,
            &mut second,
        )
        .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn parent_node_preserves_layer_and_tree_address() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let public_seed = [0xed_u8; 16];
        let left = [0x0f_u8; 16];
        let right = [0x31_u8; 16];

        let mut first_address = test_address();
        first_address.set_layer_address(1);
        first_address.set_tree_address(5);

        let mut second_address = test_address();
        second_address.set_layer_address(2);
        second_address.set_tree_address(5);

        let mut first = [0_u8; 16];
        let mut second = [0_u8; 16];

        parent_node(
            &parameters,
            &public_seed,
            &first_address,
            XmssNodePosition {
                height: 2,
                index: 1,
            },
            &left,
            &right,
            &mut first,
        )
        .unwrap();

        parent_node(
            &parameters,
            &public_seed,
            &second_address,
            XmssNodePosition {
                height: 2,
                index: 1,
            },
            &left,
            &right,
            &mut second,
        )
        .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn every_parameter_set_hashes_an_xmss_parent_node() {
        let public_seed = [0x53_u8; 32];
        let left = [0x75_u8; 32];
        let right = [0x97_u8; 32];
        let address = test_address();
        let mut output = [0_u8; 32];

        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();

            parent_node(
                &parameters,
                &public_seed[..parameters.n],
                &address,
                XmssNodePosition {
                    height: 1,
                    index: 0,
                },
                &left[..parameters.n],
                &right[..parameters.n],
                &mut output[..parameters.n],
            )
            .unwrap();
        }
    }

    #[test]
    fn node_height_zero_matches_leaf_generation() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0x11_u8; 16];
        let public_seed = [0x22_u8; 16];
        let address = test_address();

        let mut actual = [0_u8; 16];

        node(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            XmssNodePosition {
                height: 0,
                index: 3,
            },
            &mut actual,
        )
        .unwrap();

        let mut expected = [0_u8; 16];

        leaf(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            3,
            &mut expected,
        )
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn node_height_one_matches_two_leaves_and_parent_hashing() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0x33_u8; 16];
        let public_seed = [0x44_u8; 16];
        let address = test_address();

        let mut actual = [0_u8; 16];

        node(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            XmssNodePosition {
                height: 1,
                index: 2,
            },
            &mut actual,
        )
        .unwrap();

        let mut left = [0_u8; 16];
        let mut right = [0_u8; 16];

        leaf(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            4,
            &mut left,
        )
        .unwrap();

        leaf(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            5,
            &mut right,
        )
        .unwrap();

        let mut expected = [0_u8; 16];

        parent_node(
            &parameters,
            &public_seed,
            &address,
            XmssNodePosition {
                height: 1,
                index: 2,
            },
            &left,
            &right,
            &mut expected,
        )
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn node_height_two_matches_recursive_children() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let secret_seed = [0x55_u8; 16];
        let public_seed = [0x66_u8; 16];
        let address = test_address();

        let mut actual = [0_u8; 16];

        node(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            XmssNodePosition {
                height: 2,
                index: 0,
            },
            &mut actual,
        )
        .unwrap();

        let mut left = [0_u8; 16];
        let mut right = [0_u8; 16];

        node(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            XmssNodePosition {
                height: 1,
                index: 0,
            },
            &mut left,
        )
        .unwrap();

        node(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            XmssNodePosition {
                height: 1,
                index: 1,
            },
            &mut right,
        )
        .unwrap();

        let mut expected = [0_u8; 16];

        parent_node(
            &parameters,
            &public_seed,
            &address,
            XmssNodePosition {
                height: 2,
                index: 0,
            },
            &left,
            &right,
            &mut expected,
        )
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn node_rejects_heights_above_the_xmss_tree() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0_u8; 16];
        let public_seed = [0_u8; 16];
        let height = u32::try_from(parameters.hp + 1).unwrap();
        let mut output = [0_u8; 16];

        assert_eq!(
            node(
                &parameters,
                &secret_seed,
                &public_seed,
                &test_address(),
                XmssNodePosition { height, index: 0 },
                &mut output,
            ),
            Err(XmssError::InvalidNodeHeight {
                height,
                tree_height: parameters.hp,
            })
        );
    }

    #[test]
    fn node_rejects_indices_outside_the_selected_height() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0_u8; 16];
        let public_seed = [0_u8; 16];
        let height = 1;
        let node_count = 1_u64 << (parameters.hp - height as usize);
        let index = u32::try_from(node_count).unwrap();
        let mut output = [0_u8; 16];

        assert_eq!(
            node(
                &parameters,
                &secret_seed,
                &public_seed,
                &test_address(),
                XmssNodePosition { height, index },
                &mut output,
            ),
            Err(XmssError::InvalidNodeIndex {
                index,
                height,
                node_count,
            })
        );
    }

    #[test]
    fn every_parameter_set_generates_a_small_xmss_subtree() {
        let secret_seed = [0x77_u8; 32];
        let public_seed = [0x88_u8; 32];
        let address = test_address();
        let mut output = [0_u8; 32];

        for parameter_set in PARAMETER_SETS {
            let mut parameters = parameter_set.parameters();

            // Keep this cross-parameter test inexpensive while exercising the
            // complete SHA2/SHAKE and n = 16/24/32 dispatch matrix.
            parameters.hp = 2;

            node(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                XmssNodePosition {
                    height: 2,
                    index: 0,
                },
                &mut output[..parameters.n],
            )
            .unwrap();
        }
    }
}
