//! Parsing of the FIPS 205 message digest produced by `H_msg`.

use core::fmt;

use crate::{
    conversion::{to_int, ConversionError},
    params::SlhDsaParameters,
};

/// Parsed components of an SLH-DSA message digest.
///
/// The FORS digest is borrowed directly from the original `H_msg` output, so
/// parsing requires no allocation or copying.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedMessageDigest<'a> {
    /// Message digest consumed by FORS.
    pub fors_digest: &'a [u8],

    /// Index of the selected tree in the hypertree.
    pub tree_index: u64,

    /// Index of the selected leaf in the bottom XMSS tree.
    pub leaf_index: u32,
}

/// Errors produced while parsing an SLH-DSA message digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageDigestError {
    /// The supplied digest length does not match the parameter set.
    InvalidDigestLength {
        /// Required digest length in bytes.
        expected: usize,

        /// Supplied digest length in bytes.
        actual: usize,
    },

    /// The configured message-digest length disagrees with the structural
    /// parameters.
    InvalidParameterLayout {
        /// Message-digest length configured in the parameter set.
        configured: usize,

        /// Message-digest length derived from `k`, `a`, `h`, and `hp`.
        derived: usize,
    },

    /// The XMSS tree height exceeds the total hypertree height.
    InvalidTreeHeight {
        /// Total hypertree height.
        h: usize,

        /// Height of one XMSS tree.
        hp: usize,
    },

    /// A parameter calculation overflowed `usize`.
    ParameterOverflow,

    /// The tree index cannot be represented by the parser.
    TreeIndexTooWide {
        /// Required tree-index width in bits.
        bits: usize,
    },

    /// The leaf index cannot be represented by the parser.
    LeafIndexTooWide {
        /// Required leaf-index width in bits.
        bits: usize,
    },

    /// Integer decoding failed.
    Conversion(ConversionError),
}

impl fmt::Display for MessageDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDigestLength { expected, actual } => {
                write!(
                    formatter,
                    "invalid message-digest length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidParameterLayout {
                configured,
                derived,
            } => {
                write!(
                    formatter,
                    "invalid message-digest layout: configured length is \
                     {configured} bytes, but structural parameters require \
                     {derived} bytes"
                )
            }
            Self::InvalidTreeHeight { h, hp } => {
                write!(
                    formatter,
                    "invalid tree heights: XMSS height {hp} exceeds hypertree height {h}"
                )
            }
            Self::ParameterOverflow => {
                write!(formatter, "message-digest parameter calculation overflowed")
            }
            Self::TreeIndexTooWide { bits } => {
                write!(
                    formatter,
                    "tree index width {bits} exceeds the supported 64 bits"
                )
            }
            Self::LeafIndexTooWide { bits } => {
                write!(
                    formatter,
                    "leaf index width {bits} exceeds the supported 32 bits"
                )
            }
            Self::Conversion(error) => {
                write!(
                    formatter,
                    "message-digest integer conversion failed: {error}"
                )
            }
        }
    }
}

impl From<ConversionError> for MessageDigestError {
    fn from(error: ConversionError) -> Self {
        Self::Conversion(error)
    }
}

/// Parse the output of the FIPS 205 `H_msg` function.
///
/// The `m`-byte digest is interpreted as:
///
/// `digest = md || tmp_idx_tree || tmp_idx_leaf`
///
/// where:
///
/// - `len(md) = ceil(k * a / 8)`;
/// - `len(tmp_idx_tree) = ceil((h - hp) / 8)`;
/// - `len(tmp_idx_leaf) = ceil(hp / 8)`.
///
/// The decoded tree and leaf indices are reduced to their exact bit widths as
/// required by FIPS 205.
pub fn parse_message_digest<'a>(
    parameters: &SlhDsaParameters,
    digest: &'a [u8],
) -> Result<ParsedMessageDigest<'a>, MessageDigestError> {
    if parameters.hp > parameters.h {
        return Err(MessageDigestError::InvalidTreeHeight {
            h: parameters.h,
            hp: parameters.hp,
        });
    }

    let fors_bits = parameters
        .k
        .checked_mul(parameters.a)
        .ok_or(MessageDigestError::ParameterOverflow)?;

    let tree_bits = parameters.h - parameters.hp;
    let leaf_bits = parameters.hp;

    if tree_bits > u64::BITS as usize {
        return Err(MessageDigestError::TreeIndexTooWide { bits: tree_bits });
    }

    if leaf_bits > u32::BITS as usize {
        return Err(MessageDigestError::LeafIndexTooWide { bits: leaf_bits });
    }

    let fors_bytes = bytes_for_bits(fors_bits)?;
    let tree_bytes = bytes_for_bits(tree_bits)?;
    let leaf_bytes = bytes_for_bits(leaf_bits)?;

    let derived_bytes = fors_bytes
        .checked_add(tree_bytes)
        .and_then(|length| length.checked_add(leaf_bytes))
        .ok_or(MessageDigestError::ParameterOverflow)?;

    if parameters.m != derived_bytes {
        return Err(MessageDigestError::InvalidParameterLayout {
            configured: parameters.m,
            derived: derived_bytes,
        });
    }

    if digest.len() != parameters.m {
        return Err(MessageDigestError::InvalidDigestLength {
            expected: parameters.m,
            actual: digest.len(),
        });
    }

    let tree_start = fors_bytes;
    let leaf_start = tree_start + tree_bytes;

    let fors_digest = &digest[..fors_bytes];
    let encoded_tree_index = &digest[tree_start..leaf_start];
    let encoded_leaf_index = &digest[leaf_start..];

    let tree_index = to_int(encoded_tree_index)? & low_bits_mask(tree_bits);
    let leaf_index = (to_int(encoded_leaf_index)? & low_bits_mask(leaf_bits)) as u32;

    Ok(ParsedMessageDigest {
        fors_digest,
        tree_index,
        leaf_index,
    })
}

fn bytes_for_bits(bits: usize) -> Result<usize, MessageDigestError> {
    bits.checked_add(7)
        .map(|rounded| rounded / 8)
        .ok_or(MessageDigestError::ParameterOverflow)
}

fn low_bits_mask(bits: usize) -> u64 {
    match bits {
        0 => 0,
        64 => u64::MAX,
        _ => (1_u64 << bits) - 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{SlhDsaHashFamily, SlhDsaParameterSet, SlhDsaParameters};

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

    fn parameters_with(h: usize, hp: usize, a: usize, k: usize, m: usize) -> SlhDsaParameters {
        SlhDsaParameters {
            hash_family: SlhDsaHashFamily::Shake,
            n: 16,
            h,
            d: 1,
            hp,
            a,
            k,
            m,
            public_key_bytes: 32,
            private_key_bytes: 64,
            signature_bytes: 0,
            keygen_seed_bytes: 48,
        }
    }

    #[test]
    fn every_fips_parameter_set_has_the_expected_layout() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let digest = [0_u8; 49];

            let parsed = parse_message_digest(&parameters, &digest[..parameters.m]).unwrap();

            let expected_fors_bytes = (parameters.k * parameters.a).div_ceil(8);

            assert_eq!(parsed.fors_digest.len(), expected_fors_bytes);
        }
    }

    #[test]
    fn parser_borrows_the_fors_digest_without_copying() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let digest = [0x5a_u8; 30];

        let parsed = parse_message_digest(&parameters, &digest).unwrap();

        assert_eq!(parsed.fors_digest.as_ptr(), digest.as_ptr());
        assert_eq!(parsed.fors_digest.len(), 21);
    }

    #[test]
    fn parser_masks_unused_high_tree_and_leaf_bits() {
        let parameters = parameters_with(13, 5, 8, 1, 3);
        let digest = [0xaa, 0xff, 0xff];

        let parsed = parse_message_digest(&parameters, &digest).unwrap();

        assert_eq!(parsed.fors_digest, &[0xaa]);
        assert_eq!(parsed.tree_index, 0xff);
        assert_eq!(parsed.leaf_index, 0x1f);
    }

    #[test]
    fn parser_supports_a_64_bit_tree_index() {
        let parameters = parameters_with(68, 4, 8, 1, 10);
        let digest = [0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff];

        let parsed = parse_message_digest(&parameters, &digest).unwrap();

        assert_eq!(parsed.fors_digest, &[0x11]);
        assert_eq!(parsed.tree_index, 0x0102_0304_0506_0708);
        assert_eq!(parsed.leaf_index, 0x0f);
    }

    #[test]
    fn parser_rejects_the_wrong_digest_length() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();

        assert_eq!(
            parse_message_digest(&parameters, &[0_u8; 29]),
            Err(MessageDigestError::InvalidDigestLength {
                expected: 30,
                actual: 29,
            })
        );
    }

    #[test]
    fn parser_rejects_an_inconsistent_parameter_layout() {
        let mut parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        parameters.m = 31;

        assert_eq!(
            parse_message_digest(&parameters, &[0_u8; 31]),
            Err(MessageDigestError::InvalidParameterLayout {
                configured: 31,
                derived: 30,
            })
        );
    }

    #[test]
    fn parser_rejects_invalid_tree_dimensions() {
        let parameters = parameters_with(4, 5, 8, 1, 2);

        assert_eq!(
            parse_message_digest(&parameters, &[0_u8; 2]),
            Err(MessageDigestError::InvalidTreeHeight { h: 4, hp: 5 })
        );
    }
}
