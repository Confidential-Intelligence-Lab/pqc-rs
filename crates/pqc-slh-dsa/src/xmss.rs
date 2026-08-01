//! eXtended Merkle Signature Scheme primitives for SLH-DSA.
//!
//! This initial stage introduces XMSS leaf generation from WOTS+ public keys.
//! Tree-node construction, authentication paths, signing, and reconstruction
//! are added in subsequent stages.

use core::fmt;

use crate::{
    address::Address,
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

    /// An XMSS parameter calculation overflowed.
    ParameterOverflow,

    /// WOTS+ processing failed.
    Wots(WotsError),
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
            Self::ParameterOverflow => {
                write!(formatter, "XMSS parameter calculation overflowed")
            }
            Self::Wots(error) => {
                write!(formatter, "XMSS WOTS+ processing failed: {error}")
            }
        }
    }
}

impl From<WotsError> for XmssError {
    fn from(error: WotsError) -> Self {
        Self::Wots(error)
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
}
