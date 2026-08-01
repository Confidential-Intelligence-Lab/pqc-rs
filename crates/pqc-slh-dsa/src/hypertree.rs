//! SLH-DSA hypertree structure and traversal primitives.
//!
//! This stage defines hypertree signature sizing and the deterministic
//! transition between successive XMSS layers. Hypertree signing and
//! verification are introduced later.

use core::fmt;

use crate::{
    params::SlhDsaParameters,
    xmss::{self, XmssError},
};

/// Position of one XMSS signature within the SLH-DSA hypertree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HypertreePosition {
    /// Zero-based hypertree layer.
    pub layer: usize,

    /// Index of the XMSS tree at this layer.
    pub tree_index: u64,

    /// Index of the selected leaf within that XMSS tree.
    pub leaf_index: u32,
}

/// Errors returned by hypertree structural operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HypertreeError {
    /// The hypertree dimensions are internally inconsistent.
    InvalidDimensions {
        /// Total hypertree height.
        h: usize,

        /// Number of XMSS layers.
        d: usize,

        /// Height of each XMSS tree.
        hp: usize,
    },

    /// The XMSS subtree height cannot be represented by the index types.
    UnsupportedSubtreeHeight {
        /// Configured XMSS subtree height.
        hp: usize,
    },

    /// The selected hypertree layer is outside `0..d`.
    InvalidLayer {
        /// Supplied layer.
        layer: usize,

        /// Number of hypertree layers.
        layer_count: usize,
    },

    /// The selected XMSS leaf index is outside its subtree.
    InvalidLeafIndex {
        /// Supplied leaf index.
        leaf_index: u32,

        /// Number of leaves in one XMSS tree.
        leaf_count: u64,
    },

    /// The selected tree index exceeds the bits available at its layer.
    InvalidTreeIndex {
        /// Supplied tree index.
        tree_index: u64,

        /// Number of valid tree-index bits at the selected layer.
        tree_bits: usize,
    },

    /// A hypertree size calculation overflowed.
    ParameterOverflow,

    /// XMSS size calculation failed.
    Xmss(XmssError),
}

impl fmt::Display for HypertreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDimensions { h, d, hp } => {
                write!(
                    formatter,
                    "inconsistent hypertree dimensions: h={h}, d={d}, hp={hp}"
                )
            }
            Self::UnsupportedSubtreeHeight { hp } => {
                write!(
                    formatter,
                    "XMSS subtree height {hp} is unsupported by hypertree index types"
                )
            }
            Self::InvalidLayer { layer, layer_count } => {
                write!(
                    formatter,
                    "hypertree layer {layer} is outside the configured {layer_count} layers"
                )
            }
            Self::InvalidLeafIndex {
                leaf_index,
                leaf_count,
            } => {
                write!(
                    formatter,
                    "hypertree leaf index {leaf_index} is outside the configured {leaf_count} leaves"
                )
            }
            Self::InvalidTreeIndex {
                tree_index,
                tree_bits,
            } => {
                write!(
                    formatter,
                    "hypertree tree index {tree_index} exceeds the available {tree_bits} bits"
                )
            }
            Self::ParameterOverflow => {
                write!(formatter, "hypertree parameter calculation overflowed")
            }
            Self::Xmss(error) => {
                write!(formatter, "hypertree XMSS processing failed: {error}")
            }
        }
    }
}

impl From<XmssError> for HypertreeError {
    fn from(error: XmssError) -> Self {
        Self::Xmss(error)
    }
}

/// Validate the structural hypertree parameters.
pub fn validate_parameters(parameters: &SlhDsaParameters) -> Result<(), HypertreeError> {
    let composed_height = parameters
        .d
        .checked_mul(parameters.hp)
        .ok_or(HypertreeError::ParameterOverflow)?;

    if parameters.d == 0 || parameters.hp == 0 || parameters.h != composed_height {
        return Err(HypertreeError::InvalidDimensions {
            h: parameters.h,
            d: parameters.d,
            hp: parameters.hp,
        });
    }

    if parameters.hp > u32::BITS as usize {
        return Err(HypertreeError::UnsupportedSubtreeHeight { hp: parameters.hp });
    }

    Ok(())
}

/// Return the encoded length of a complete hypertree signature.
///
/// A hypertree signature contains one XMSS signature for each of the `d`
/// hypertree layers.
pub fn signature_bytes(parameters: &SlhDsaParameters) -> Result<usize, HypertreeError> {
    validate_parameters(parameters)?;

    parameters
        .d
        .checked_mul(xmss::signature_bytes(parameters)?)
        .ok_or(HypertreeError::ParameterOverflow)
}

/// Construct and validate the initial hypertree position.
///
/// The initial tree and leaf indices are obtained from the parsed SLH-DSA
/// message digest.
pub fn initial_position(
    parameters: &SlhDsaParameters,
    tree_index: u64,
    leaf_index: u32,
) -> Result<HypertreePosition, HypertreeError> {
    validate_parameters(parameters)?;

    let position = HypertreePosition {
        layer: 0,
        tree_index,
        leaf_index,
    };

    validate_position(parameters, position)?;

    Ok(position)
}

/// Return the position of the next XMSS layer.
///
/// The transition consumes the low `hp` bits of the current tree index as the
/// next layer's leaf index, then shifts the tree index right by `hp` bits.
/// The top hypertree layer has no successor and returns `None`.
pub fn next_position(
    parameters: &SlhDsaParameters,
    position: HypertreePosition,
) -> Result<Option<HypertreePosition>, HypertreeError> {
    validate_parameters(parameters)?;
    validate_position(parameters, position)?;

    let next_layer = position
        .layer
        .checked_add(1)
        .ok_or(HypertreeError::ParameterOverflow)?;

    if next_layer == parameters.d {
        return Ok(None);
    }

    let shift = u32::try_from(parameters.hp).map_err(|_| HypertreeError::ParameterOverflow)?;

    let leaf_mask = if parameters.hp == u32::BITS as usize {
        u64::from(u32::MAX)
    } else {
        (1_u64 << shift) - 1
    };

    let next_leaf_index = u32::try_from(position.tree_index & leaf_mask)
        .map_err(|_| HypertreeError::ParameterOverflow)?;

    let next_tree_index = position
        .tree_index
        .checked_shr(shift)
        .ok_or(HypertreeError::ParameterOverflow)?;

    let next = HypertreePosition {
        layer: next_layer,
        tree_index: next_tree_index,
        leaf_index: next_leaf_index,
    };

    validate_position(parameters, next)?;

    Ok(Some(next))
}

fn validate_position(
    parameters: &SlhDsaParameters,
    position: HypertreePosition,
) -> Result<(), HypertreeError> {
    if position.layer >= parameters.d {
        return Err(HypertreeError::InvalidLayer {
            layer: position.layer,
            layer_count: parameters.d,
        });
    }

    let shift = u32::try_from(parameters.hp).map_err(|_| HypertreeError::ParameterOverflow)?;

    let leaf_count = 1_u64
        .checked_shl(shift)
        .ok_or(HypertreeError::ParameterOverflow)?;

    if u64::from(position.leaf_index) >= leaf_count {
        return Err(HypertreeError::InvalidLeafIndex {
            leaf_index: position.leaf_index,
            leaf_count,
        });
    }

    let consumed_layers = position
        .layer
        .checked_add(1)
        .ok_or(HypertreeError::ParameterOverflow)?;

    let consumed_height = consumed_layers
        .checked_mul(parameters.hp)
        .ok_or(HypertreeError::ParameterOverflow)?;

    let tree_bits = parameters
        .h
        .checked_sub(consumed_height)
        .ok_or(HypertreeError::ParameterOverflow)?;

    let tree_index_valid = if tree_bits >= u64::BITS as usize {
        true
    } else {
        position.tree_index < (1_u64 << tree_bits)
    };

    if !tree_index_valid {
        return Err(HypertreeError::InvalidTreeIndex {
            tree_index: position.tree_index,
            tree_bits,
        });
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

    #[test]
    fn every_fips_parameter_set_has_valid_hypertree_dimensions() {
        for parameter_set in PARAMETER_SETS {
            assert_eq!(validate_parameters(&parameter_set.parameters()), Ok(()));
        }
    }

    #[test]
    fn inconsistent_dimensions_are_rejected() {
        let mut parameters = SlhDsaParameterSet::Shake128s.parameters();
        parameters.h += 1;

        assert_eq!(
            validate_parameters(&parameters),
            Err(HypertreeError::InvalidDimensions {
                h: parameters.h,
                d: parameters.d,
                hp: parameters.hp,
            })
        );
    }

    #[test]
    fn signature_length_is_d_times_the_xmss_signature_length() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();

            assert_eq!(
                signature_bytes(&parameters),
                Ok(parameters.d * xmss::signature_bytes(&parameters).unwrap())
            );
        }
    }

    #[test]
    fn initial_position_preserves_supplied_indices() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();

        assert_eq!(
            initial_position(&parameters, 0x1234, 7),
            Ok(HypertreePosition {
                layer: 0,
                tree_index: 0x1234,
                leaf_index: 7,
            })
        );
    }

    #[test]
    fn initial_position_rejects_an_out_of_range_leaf() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let leaf_count = 1_u64 << parameters.hp;
        let leaf_index = u32::try_from(leaf_count).unwrap();

        assert_eq!(
            initial_position(&parameters, 0, leaf_index),
            Err(HypertreeError::InvalidLeafIndex {
                leaf_index,
                leaf_count,
            })
        );
    }

    #[test]
    fn initial_position_rejects_an_out_of_range_tree_index() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let tree_bits = parameters.h - parameters.hp;
        let tree_index = 1_u64 << tree_bits;

        assert_eq!(
            initial_position(&parameters, tree_index, 0),
            Err(HypertreeError::InvalidTreeIndex {
                tree_index,
                tree_bits,
            })
        );
    }

    #[test]
    fn next_position_consumes_low_tree_bits_as_the_leaf_index() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let initial = initial_position(&parameters, 0x12_345, 3).unwrap();
        let mask = (1_u64 << parameters.hp) - 1;

        assert_eq!(
            next_position(&parameters, initial),
            Ok(Some(HypertreePosition {
                layer: 1,
                tree_index: initial.tree_index >> parameters.hp,
                leaf_index: u32::try_from(initial.tree_index & mask).unwrap(),
            }))
        );
    }

    #[test]
    fn repeated_transitions_shift_one_subtree_per_layer() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();

        // This value fits the 54 tree-index bits available at layer zero.
        let mut position = initial_position(&parameters, 0x0003_4567_89ab_cdef, 5).unwrap();

        for expected_layer in 1..parameters.d {
            let previous = position;
            position = next_position(&parameters, previous).unwrap().unwrap();

            assert_eq!(position.layer, expected_layer);
            assert_eq!(position.tree_index, previous.tree_index >> parameters.hp);
            assert_eq!(
                position.leaf_index,
                u32::try_from(previous.tree_index & ((1_u64 << parameters.hp) - 1)).unwrap()
            );
        }
    }

    #[test]
    fn top_layer_has_no_successor() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let top = HypertreePosition {
            layer: parameters.d - 1,
            tree_index: 0,
            leaf_index: 0,
        };

        assert_eq!(next_position(&parameters, top), Ok(None));
    }

    #[test]
    fn invalid_layer_is_rejected() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let invalid = HypertreePosition {
            layer: parameters.d,
            tree_index: 0,
            leaf_index: 0,
        };

        assert_eq!(
            next_position(&parameters, invalid),
            Err(HypertreeError::InvalidLayer {
                layer: parameters.d,
                layer_count: parameters.d,
            })
        );
    }

    #[test]
    fn every_parameter_set_traverses_all_hypertree_layers() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let mut position = initial_position(&parameters, 0, 0).unwrap();
            let mut visited = 1;

            while let Some(next) = next_position(&parameters, position).unwrap() {
                position = next;
                visited += 1;
            }

            assert_eq!(visited, parameters.d, "{parameter_set:?}");
            assert_eq!(position.layer, parameters.d - 1);
            assert_eq!(position.tree_index, 0);
        }
    }
}
