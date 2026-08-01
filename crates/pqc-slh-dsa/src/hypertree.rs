//! SLH-DSA hypertree structure and traversal primitives.
//!
//! This stage defines hypertree signature sizing and the deterministic
//! transition between successive XMSS layers. Hypertree signing and
//! verification are introduced later.

use core::fmt;

use crate::{
    address::Address,
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

/// Structural context for one XMSS layer of the hypertree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HypertreeLayer {
    /// Position of the XMSS operation within the hypertree.
    pub position: HypertreePosition,

    /// Base XMSS address derived from the position.
    pub address: Address,

    /// Inclusive byte offset of this layer's XMSS signature.
    pub signature_start: usize,

    /// Exclusive byte offset of this layer's XMSS signature.
    pub signature_end: usize,
}

impl HypertreeLayer {
    /// Return the encoded XMSS-signature length for this layer.
    pub fn signature_len(self) -> usize {
        self.signature_end - self.signature_start
    }
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

    /// The supplied hypertree-signature buffer has the wrong length.
    InvalidSignatureLength {
        /// Required hypertree-signature length in bytes.
        expected: usize,

        /// Supplied hypertree-signature length in bytes.
        actual: usize,
    },

    /// The supplied hypertree message has the wrong length.
    InvalidMessageLength {
        /// Required message length in bytes.
        expected: usize,

        /// Supplied message length in bytes.
        actual: usize,
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
            Self::InvalidSignatureLength { expected, actual } => {
                write!(
                    formatter,
                    "invalid hypertree signature length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidMessageLength { expected, actual } => {
                write!(
                    formatter,
                    "invalid hypertree message length: expected {expected} bytes, got {actual}"
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

/// Derive the base XMSS address for one hypertree position.
///
/// The returned address contains the position's hypertree layer and XMSS tree
/// index. Its type-dependent words remain zero; XMSS and WOTS+ operations set
/// those words when entering their respective domain-separation namespaces.
pub fn xmss_address(
    parameters: &SlhDsaParameters,
    position: HypertreePosition,
) -> Result<Address, HypertreeError> {
    validate_parameters(parameters)?;
    validate_position(parameters, position)?;

    let layer = u32::try_from(position.layer).map_err(|_| HypertreeError::ParameterOverflow)?;

    let mut address = Address::new();
    address.set_layer_address(layer);
    address.set_tree_address(position.tree_index);

    Ok(address)
}

/// Return the encoded length of one XMSS signature layer.
pub fn layer_signature_bytes(parameters: &SlhDsaParameters) -> Result<usize, HypertreeError> {
    validate_parameters(parameters)?;
    Ok(xmss::signature_bytes(parameters)?)
}

/// Construct the structural context for one hypertree layer.
///
/// `initial` must be the validated layer-zero position. The function advances
/// through the deterministic hypertree transitions until `layer` is reached,
/// then derives the corresponding XMSS address and signature-byte range.
pub fn layer_context(
    parameters: &SlhDsaParameters,
    initial: HypertreePosition,
    layer: usize,
) -> Result<HypertreeLayer, HypertreeError> {
    validate_parameters(parameters)?;
    validate_position(parameters, initial)?;

    if initial.layer != 0 {
        return Err(HypertreeError::InvalidLayer {
            layer: initial.layer,
            layer_count: parameters.d,
        });
    }

    if layer >= parameters.d {
        return Err(HypertreeError::InvalidLayer {
            layer,
            layer_count: parameters.d,
        });
    }

    let mut position = initial;

    for _ in 0..layer {
        position = next_position(parameters, position)?.ok_or(HypertreeError::InvalidLayer {
            layer,
            layer_count: parameters.d,
        })?;
    }

    let xmss_bytes = layer_signature_bytes(parameters)?;

    let signature_start = layer
        .checked_mul(xmss_bytes)
        .ok_or(HypertreeError::ParameterOverflow)?;

    let signature_end = signature_start
        .checked_add(xmss_bytes)
        .ok_or(HypertreeError::ParameterOverflow)?;

    Ok(HypertreeLayer {
        position,
        address: xmss_address(parameters, position)?,
        signature_start,
        signature_end,
    })
}

/// Visit every hypertree layer in ascending order.
///
/// The callback receives the validated position, derived XMSS address, and
/// exact signature-byte range for each layer. No cryptographic operation is
/// performed by this structural traversal.
pub fn for_each_layer<F>(
    parameters: &SlhDsaParameters,
    initial: HypertreePosition,
    mut visit: F,
) -> Result<(), HypertreeError>
where
    F: FnMut(HypertreeLayer) -> Result<(), HypertreeError>,
{
    validate_parameters(parameters)?;
    validate_position(parameters, initial)?;

    if initial.layer != 0 {
        return Err(HypertreeError::InvalidLayer {
            layer: initial.layer,
            layer_count: parameters.d,
        });
    }

    let mut position = initial;
    let xmss_bytes = layer_signature_bytes(parameters)?;

    for layer in 0..parameters.d {
        let signature_start = layer
            .checked_mul(xmss_bytes)
            .ok_or(HypertreeError::ParameterOverflow)?;

        let signature_end = signature_start
            .checked_add(xmss_bytes)
            .ok_or(HypertreeError::ParameterOverflow)?;

        visit(HypertreeLayer {
            position,
            address: xmss_address(parameters, position)?,
            signature_start,
            signature_end,
        })?;

        if layer + 1 < parameters.d {
            position =
                next_position(parameters, position)?.ok_or(HypertreeError::InvalidLayer {
                    layer: layer + 1,
                    layer_count: parameters.d,
                })?;
        }
    }

    Ok(())
}

/// Validate a complete hypertree-signature buffer.
pub fn validate_signature_buffer(
    parameters: &SlhDsaParameters,
    signature: &[u8],
) -> Result<(), HypertreeError> {
    let expected = signature_bytes(parameters)?;

    if signature.len() != expected {
        return Err(HypertreeError::InvalidSignatureLength {
            expected,
            actual: signature.len(),
        });
    }

    Ok(())
}

/// Generate a deterministic SLH-DSA hypertree signature.
///
/// `message` is the `n`-byte value signed by the bottom XMSS layer, normally
/// the public key reconstructed from the FORS signature. Each subsequent XMSS
/// layer signs the root of the XMSS tree immediately below it.
///
/// The signature encoding is the concatenation of `d` XMSS signatures in
/// ascending layer order.
pub fn sign(
    parameters: &SlhDsaParameters,
    secret_seed: &[u8],
    public_seed: &[u8],
    message: &[u8],
    tree_index: u64,
    leaf_index: u32,
    signature: &mut [u8],
) -> Result<(), HypertreeError> {
    validate_signature_buffer(parameters, signature)?;

    if message.len() != parameters.n {
        return Err(HypertreeError::InvalidMessageLength {
            expected: parameters.n,
            actual: message.len(),
        });
    }

    let initial = initial_position(parameters, tree_index, leaf_index)?;
    let mut current = [0_u8; 32];
    current[..parameters.n].copy_from_slice(message);

    for layer in 0..parameters.d {
        let context = layer_context(parameters, initial, layer)?;
        let layer_signature = &mut signature[context.signature_start..context.signature_end];

        xmss::sign(
            parameters,
            secret_seed,
            public_seed,
            &current[..parameters.n],
            &context.address,
            context.position.leaf_index,
            layer_signature,
        )?;

        if layer + 1 < parameters.d {
            let mut next_message = [0_u8; 32];

            xmss::root(
                parameters,
                secret_seed,
                public_seed,
                &context.address,
                &mut next_message[..parameters.n],
            )?;

            current[..parameters.n].copy_from_slice(&next_message[..parameters.n]);
        }
    }

    Ok(())
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

    #[test]
    fn xmss_address_encodes_the_layer_and_tree_index() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let position = HypertreePosition {
            layer: 3,
            tree_index: 0x0123_4567,
            leaf_index: 7,
        };

        let actual = xmss_address(&parameters, position).unwrap();

        let mut expected = Address::new();
        expected.set_layer_address(3);
        expected.set_tree_address(0x0123_4567);

        assert_eq!(actual, expected);
    }

    #[test]
    fn xmss_address_does_not_encode_the_leaf_index() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();

        let first = xmss_address(
            &parameters,
            HypertreePosition {
                layer: 1,
                tree_index: 9,
                leaf_index: 3,
            },
        )
        .unwrap();

        let second = xmss_address(
            &parameters,
            HypertreePosition {
                layer: 1,
                tree_index: 9,
                leaf_index: 17,
            },
        )
        .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn xmss_addresses_are_domain_separated_by_layer() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();

        let first = xmss_address(
            &parameters,
            HypertreePosition {
                layer: 1,
                tree_index: 5,
                leaf_index: 0,
            },
        )
        .unwrap();

        let second = xmss_address(
            &parameters,
            HypertreePosition {
                layer: 2,
                tree_index: 5,
                leaf_index: 0,
            },
        )
        .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn xmss_addresses_are_domain_separated_by_tree_index() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();

        let first = xmss_address(
            &parameters,
            HypertreePosition {
                layer: 1,
                tree_index: 5,
                leaf_index: 0,
            },
        )
        .unwrap();

        let second = xmss_address(
            &parameters,
            HypertreePosition {
                layer: 1,
                tree_index: 6,
                leaf_index: 0,
            },
        )
        .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn xmss_address_rejects_an_invalid_position() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let position = HypertreePosition {
            layer: parameters.d,
            tree_index: 0,
            leaf_index: 0,
        };

        assert_eq!(
            xmss_address(&parameters, position),
            Err(HypertreeError::InvalidLayer {
                layer: parameters.d,
                layer_count: parameters.d,
            })
        );
    }

    #[test]
    fn transitioned_positions_derive_the_expected_addresses() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let initial = initial_position(&parameters, 0x1234_5678, 3).unwrap();
        let next = next_position(&parameters, initial).unwrap().unwrap();

        let actual = xmss_address(&parameters, next).unwrap();

        let mut expected = Address::new();
        expected.set_layer_address(1);
        expected.set_tree_address(0x1234_5678 >> parameters.hp);

        assert_eq!(actual, expected);
    }

    #[test]
    fn every_parameter_set_derives_addresses_for_all_layers() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let mut position = initial_position(&parameters, 0, 0).unwrap();

            loop {
                let address = xmss_address(&parameters, position).unwrap();

                let layer_bytes = u32::try_from(position.layer).unwrap().to_be_bytes();

                assert_eq!(&address.as_bytes()[0..4], &layer_bytes);
                assert_eq!(&address.as_bytes()[16..32], &[0_u8; 16]);

                match next_position(&parameters, position).unwrap() {
                    Some(next) => position = next,
                    None => break,
                }
            }
        }
    }

    #[test]
    fn layer_signature_length_matches_xmss_signature_length() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();

            assert_eq!(
                layer_signature_bytes(&parameters),
                xmss::signature_bytes(&parameters).map_err(HypertreeError::from)
            );
        }
    }

    #[test]
    fn first_layer_context_matches_the_initial_position() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let initial = initial_position(&parameters, 0x1234, 7).unwrap();
        let context = layer_context(&parameters, initial, 0).unwrap();

        assert_eq!(context.position, initial);
        assert_eq!(context.address, xmss_address(&parameters, initial).unwrap());
        assert_eq!(context.signature_start, 0);
        assert_eq!(
            context.signature_end,
            xmss::signature_bytes(&parameters).unwrap()
        );
    }

    #[test]
    fn layer_context_matches_repeated_position_transitions() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let initial = initial_position(&parameters, 0x0003_4567_89ab_cdef, 5).unwrap();

        let mut expected = initial;

        for layer in 0..parameters.d {
            let context = layer_context(&parameters, initial, layer).unwrap();

            assert_eq!(context.position, expected);
            assert_eq!(
                context.address,
                xmss_address(&parameters, expected).unwrap()
            );

            if layer + 1 < parameters.d {
                expected = next_position(&parameters, expected).unwrap().unwrap();
            }
        }
    }

    #[test]
    fn layer_signature_ranges_are_contiguous() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let initial = initial_position(&parameters, 0, 0).unwrap();
        let xmss_bytes = xmss::signature_bytes(&parameters).unwrap();

        for layer in 0..parameters.d {
            let context = layer_context(&parameters, initial, layer).unwrap();

            assert_eq!(context.signature_start, layer * xmss_bytes);
            assert_eq!(context.signature_end, (layer + 1) * xmss_bytes);
            assert_eq!(context.signature_len(), xmss_bytes);
        }
    }

    #[test]
    fn final_layer_ends_at_the_hypertree_signature_length() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let initial = initial_position(&parameters, 0, 0).unwrap();
            let final_layer = layer_context(&parameters, initial, parameters.d - 1).unwrap();

            assert_eq!(
                final_layer.signature_end,
                signature_bytes(&parameters).unwrap(),
                "{parameter_set:?}"
            );
        }
    }

    #[test]
    fn layer_context_rejects_an_out_of_range_layer() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let initial = initial_position(&parameters, 0, 0).unwrap();

        assert_eq!(
            layer_context(&parameters, initial, parameters.d),
            Err(HypertreeError::InvalidLayer {
                layer: parameters.d,
                layer_count: parameters.d,
            })
        );
    }

    #[test]
    fn traversal_visits_every_layer_once() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let initial = initial_position(&parameters, 0, 0).unwrap();
            let mut visited = 0;

            for_each_layer(&parameters, initial, |context| {
                assert_eq!(context.position.layer, visited);
                visited += 1;
                Ok(())
            })
            .unwrap();

            assert_eq!(visited, parameters.d, "{parameter_set:?}");
        }
    }

    #[test]
    fn traversal_contexts_match_direct_layer_contexts() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let initial = initial_position(&parameters, 0x0003_4567_89ab_cdef, 5).unwrap();
        let mut layer = 0;

        for_each_layer(&parameters, initial, |actual| {
            let expected = layer_context(&parameters, initial, layer).unwrap();
            assert_eq!(actual, expected);
            layer += 1;
            Ok(())
        })
        .unwrap();

        assert_eq!(layer, parameters.d);
    }

    #[test]
    fn signature_buffer_validation_accepts_the_exact_length() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let expected = signature_bytes(&parameters).unwrap();
        let signature = vec![0_u8; expected];

        assert_eq!(validate_signature_buffer(&parameters, &signature), Ok(()));
    }

    #[test]
    fn signature_buffer_validation_rejects_the_wrong_length() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let expected = signature_bytes(&parameters).unwrap();
        let signature = vec![0_u8; expected - 1];

        assert_eq!(
            validate_signature_buffer(&parameters, &signature),
            Err(HypertreeError::InvalidSignatureLength {
                expected,
                actual: expected - 1,
            })
        );
    }

    #[test]
    fn sign_rejects_the_wrong_signature_length() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let expected = signature_bytes(&parameters).unwrap();
        let secret_seed = [0_u8; 16];
        let public_seed = [0_u8; 16];
        let message = [0_u8; 16];
        let mut signature = [0_u8; 8192];

        assert_eq!(
            sign(
                &parameters,
                &secret_seed,
                &public_seed,
                &message,
                0,
                0,
                &mut signature[..expected - 1],
            ),
            Err(HypertreeError::InvalidSignatureLength {
                expected,
                actual: expected - 1,
            })
        );
    }

    #[test]
    fn sign_rejects_the_wrong_message_length() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let signature_length = signature_bytes(&parameters).unwrap();
        let secret_seed = [0_u8; 16];
        let public_seed = [0_u8; 16];
        let message = [0_u8; 15];
        let mut signature = [0_u8; 8192];

        assert_eq!(
            sign(
                &parameters,
                &secret_seed,
                &public_seed,
                &message,
                0,
                0,
                &mut signature[..signature_length],
            ),
            Err(HypertreeError::InvalidMessageLength {
                expected: parameters.n,
                actual: message.len(),
            })
        );
    }

    #[test]
    fn first_layer_matches_direct_xmss_signing() {
        let mut parameters = SlhDsaParameterSet::Shake128s.parameters();
        parameters.hp = 2;
        parameters.d = 3;
        parameters.h = 6;

        let secret_seed = [0x21_u8; 16];
        let public_seed = [0x43_u8; 16];
        let message = [0x65_u8; 16];
        let tree_index = 0b1011;
        let leaf_index = 2;
        let signature_length = signature_bytes(&parameters).unwrap();
        let xmss_length = xmss::signature_bytes(&parameters).unwrap();

        let mut signature = [0_u8; 8192];

        sign(
            &parameters,
            &secret_seed,
            &public_seed,
            &message,
            tree_index,
            leaf_index,
            &mut signature[..signature_length],
        )
        .unwrap();

        let initial = initial_position(&parameters, tree_index, leaf_index).unwrap();
        let context = layer_context(&parameters, initial, 0).unwrap();
        let mut expected = [0_u8; 4096];

        xmss::sign(
            &parameters,
            &secret_seed,
            &public_seed,
            &message,
            &context.address,
            leaf_index,
            &mut expected[..xmss_length],
        )
        .unwrap();

        assert_eq!(&signature[..xmss_length], &expected[..xmss_length]);
    }

    #[test]
    fn second_layer_signs_the_previous_xmss_root() {
        let mut parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        parameters.hp = 2;
        parameters.d = 3;
        parameters.h = 6;

        let secret_seed = [0x87_u8; 16];
        let public_seed = [0xa9_u8; 16];
        let message = [0xcb_u8; 16];
        let tree_index = 0b1011;
        let leaf_index = 1;
        let signature_length = signature_bytes(&parameters).unwrap();
        let xmss_length = xmss::signature_bytes(&parameters).unwrap();

        let mut signature = [0_u8; 8192];

        sign(
            &parameters,
            &secret_seed,
            &public_seed,
            &message,
            tree_index,
            leaf_index,
            &mut signature[..signature_length],
        )
        .unwrap();

        let initial = initial_position(&parameters, tree_index, leaf_index).unwrap();
        let first_context = layer_context(&parameters, initial, 0).unwrap();
        let second_context = layer_context(&parameters, initial, 1).unwrap();

        let mut first_root = [0_u8; 16];

        xmss::root(
            &parameters,
            &secret_seed,
            &public_seed,
            &first_context.address,
            &mut first_root,
        )
        .unwrap();

        let mut expected = [0_u8; 4096];

        xmss::sign(
            &parameters,
            &secret_seed,
            &public_seed,
            &first_root,
            &second_context.address,
            second_context.position.leaf_index,
            &mut expected[..xmss_length],
        )
        .unwrap();

        assert_eq!(
            &signature[xmss_length..2 * xmss_length],
            &expected[..xmss_length]
        );
    }

    #[test]
    fn hypertree_signing_is_deterministic() {
        let mut parameters = SlhDsaParameterSet::Shake128s.parameters();
        parameters.hp = 2;
        parameters.d = 3;
        parameters.h = 6;

        let secret_seed = [0xed_u8; 16];
        let public_seed = [0x0f_u8; 16];
        let message = [0x31_u8; 16];
        let signature_length = signature_bytes(&parameters).unwrap();

        let mut first = [0_u8; 8192];
        let mut second = [0_u8; 8192];

        sign(
            &parameters,
            &secret_seed,
            &public_seed,
            &message,
            0b1011,
            2,
            &mut first[..signature_length],
        )
        .unwrap();

        sign(
            &parameters,
            &secret_seed,
            &public_seed,
            &message,
            0b1011,
            2,
            &mut second[..signature_length],
        )
        .unwrap();

        assert_eq!(&first[..signature_length], &second[..signature_length]);
    }

    #[test]
    fn changing_the_message_changes_the_hypertree_signature() {
        let mut parameters = SlhDsaParameterSet::Shake128s.parameters();
        parameters.hp = 2;
        parameters.d = 3;
        parameters.h = 6;

        let secret_seed = [0x53_u8; 16];
        let public_seed = [0x75_u8; 16];
        let first_message = [0x00_u8; 16];
        let second_message = [0xff_u8; 16];
        let signature_length = signature_bytes(&parameters).unwrap();

        let mut first = [0_u8; 8192];
        let mut second = [0_u8; 8192];

        sign(
            &parameters,
            &secret_seed,
            &public_seed,
            &first_message,
            0,
            1,
            &mut first[..signature_length],
        )
        .unwrap();

        sign(
            &parameters,
            &secret_seed,
            &public_seed,
            &second_message,
            0,
            1,
            &mut second[..signature_length],
        )
        .unwrap();

        assert_ne!(&first[..signature_length], &second[..signature_length]);
    }

    #[test]
    fn every_parameter_set_generates_a_small_hypertree_signature() {
        let secret_seed = [0x97_u8; 32];
        let public_seed = [0xb9_u8; 32];
        let message = [0xdb_u8; 32];
        let mut signature = [0_u8; 8192];

        for parameter_set in PARAMETER_SETS {
            let mut parameters = parameter_set.parameters();
            parameters.hp = 2;
            parameters.d = 3;
            parameters.h = 6;

            let signature_length = signature_bytes(&parameters).unwrap();

            sign(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &message[..parameters.n],
                0b1011,
                2,
                &mut signature[..signature_length],
            )
            .unwrap();
        }
    }

    #[test]
    fn every_signed_layer_reconstructs_the_message_for_the_next_layer() {
        let mut parameters = SlhDsaParameterSet::Shake128s.parameters();
        parameters.hp = 2;
        parameters.d = 3;
        parameters.h = 6;

        let secret_seed = [0x1c_u8; 16];
        let public_seed = [0x2d_u8; 16];
        let message = [0x3e_u8; 16];
        let tree_index = 0b1011;
        let leaf_index = 2;
        let signature_length = signature_bytes(&parameters).unwrap();

        let mut signature = [0_u8; 8192];

        sign(
            &parameters,
            &secret_seed,
            &public_seed,
            &message,
            tree_index,
            leaf_index,
            &mut signature[..signature_length],
        )
        .unwrap();

        let initial = initial_position(&parameters, tree_index, leaf_index).unwrap();
        let mut current = message;

        for layer in 0..parameters.d {
            let context = layer_context(&parameters, initial, layer).unwrap();
            let layer_signature = &signature[context.signature_start..context.signature_end];

            let mut reconstructed = [0_u8; 16];

            xmss::root_from_signature(
                &parameters,
                layer_signature,
                &current,
                &public_seed,
                &context.address,
                context.position.leaf_index,
                &mut reconstructed,
            )
            .unwrap();

            let mut expected = [0_u8; 16];

            xmss::root(
                &parameters,
                &secret_seed,
                &public_seed,
                &context.address,
                &mut expected,
            )
            .unwrap();

            assert_eq!(reconstructed, expected, "layer {layer}");
            current = reconstructed;
        }
    }
}
