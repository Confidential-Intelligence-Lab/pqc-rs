//! Winternitz one-time-signature parameter and message-digit operations.
//!
//! This module implements the non-cryptographic WOTS+ preprocessing defined
//! by FIPS 205. Hash-chain generation, signing, and public-key reconstruction
//! are introduced in subsequent stages.

use core::fmt;

use crate::{
    address::{Address, AddressType},
    conversion::{base_2b, ConversionError},
    hash::HashError,
    hash_suite::HashSuite,
    params::SlhDsaParameters,
};

/// Winternitz parameter used by every FIPS 205 SLH-DSA parameter set.
pub const WOTS_W: u32 = 16;

/// Base-two logarithm of [`WOTS_W`].
pub const WOTS_LOG_W: usize = 4;

/// Maximum number of WOTS+ chains among the approved FIPS 205 parameter sets.
pub const MAX_WOTS_LEN: usize = 67;

/// Errors returned by WOTS+ preprocessing operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WotsError {
    /// The supplied message has the wrong length.
    InvalidMessageLength {
        /// Required message length in bytes.
        expected: usize,

        /// Supplied message length in bytes.
        actual: usize,
    },

    /// The output slice has the wrong number of base-`w` digits.
    InvalidDigitCount {
        /// Required number of digits.
        expected: usize,

        /// Supplied number of digits.
        actual: usize,
    },

    /// A WOTS+ parameter or checksum calculation overflowed.
    ParameterOverflow,

    /// The supplied byte string has the wrong length.
    InvalidByteLength {
        /// Required byte length.
        expected: usize,

        /// Supplied byte length.
        actual: usize,
    },

    /// The selected WOTS+ chain index is outside the configured chain set.
    InvalidChainIndex {
        /// Supplied chain index.
        index: usize,

        /// Number of WOTS+ chains.
        chain_count: usize,
    },

    /// The requested chain interval exceeds the WOTS+ chain length.
    InvalidChainRange {
        /// Initial hash-chain position.
        start: u32,

        /// Number of requested hash steps.
        steps: u32,
    },

    /// Byte-to-base conversion failed.
    Conversion(ConversionError),

    /// Hash evaluation failed.
    Hash(HashError),
}

impl fmt::Display for WotsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessageLength { expected, actual } => {
                write!(
                    formatter,
                    "invalid WOTS+ message length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidDigitCount { expected, actual } => {
                write!(
                    formatter,
                    "invalid WOTS+ digit count: expected {expected}, got {actual}"
                )
            }
            Self::ParameterOverflow => {
                write!(
                    formatter,
                    "WOTS+ parameter or checksum calculation overflowed"
                )
            }
            Self::InvalidByteLength { expected, actual } => {
                write!(
                    formatter,
                    "invalid WOTS+ byte length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidChainIndex { index, chain_count } => {
                write!(
                    formatter,
                    "WOTS+ chain index {index} is outside the configured {chain_count} chains"
                )
            }
            Self::InvalidChainRange { start, steps } => {
                write!(
                    formatter,
                    "WOTS+ chain interval starting at {start} with {steps} steps exceeds the chain"
                )
            }
            Self::Conversion(error) => {
                write!(formatter, "WOTS+ base conversion failed: {error}")
            }
            Self::Hash(error) => {
                write!(formatter, "WOTS+ hash evaluation failed: {error}")
            }
        }
    }
}

impl From<ConversionError> for WotsError {
    fn from(error: ConversionError) -> Self {
        Self::Conversion(error)
    }
}

impl From<HashError> for WotsError {
    fn from(error: HashError) -> Self {
        Self::Hash(error)
    }
}

/// Return `len_1`, the number of base-`w` digits encoding an `n`-byte message.
///
/// FIPS 205 fixes `w = 16`, so each byte contributes two base-16 digits.
pub fn len_1(parameters: &SlhDsaParameters) -> Result<usize, WotsError> {
    parameters
        .n
        .checked_mul(8)
        .and_then(|message_bits| message_bits.checked_add(WOTS_LOG_W - 1))
        .map(|rounded_bits| rounded_bits / WOTS_LOG_W)
        .ok_or(WotsError::ParameterOverflow)
}

/// Return `len_2`, the number of base-`w` digits encoding the WOTS+ checksum.
///
/// This computes:
///
/// `len_2 = floor(log_w(len_1 * (w - 1))) + 1`.
pub fn len_2(parameters: &SlhDsaParameters) -> Result<usize, WotsError> {
    let maximum_checksum = len_1(parameters)?
        .checked_mul((WOTS_W - 1) as usize)
        .ok_or(WotsError::ParameterOverflow)?;

    let mut value = maximum_checksum;
    let mut digits = 0_usize;

    while value > 0 {
        digits = digits.checked_add(1).ok_or(WotsError::ParameterOverflow)?;
        value /= WOTS_W as usize;
    }

    Ok(digits.max(1))
}

/// Return `len`, the total number of WOTS+ chains.
///
/// `len = len_1 + len_2`.
pub fn len(parameters: &SlhDsaParameters) -> Result<usize, WotsError> {
    len_1(parameters)?
        .checked_add(len_2(parameters)?)
        .ok_or(WotsError::ParameterOverflow)
}

/// Return the number of bytes used to encode the WOTS+ checksum.
pub fn checksum_bytes(parameters: &SlhDsaParameters) -> Result<usize, WotsError> {
    len_2(parameters)?
        .checked_mul(WOTS_LOG_W)
        .and_then(|bits| bits.checked_add(7))
        .map(|rounded_bits| rounded_bits / 8)
        .ok_or(WotsError::ParameterOverflow)
}

/// Apply a segment of a WOTS+ hash chain.
///
/// The supplied address must identify the WOTS+ chain. This function updates
/// only the hash-step word, using consecutive values beginning at `start`.
///
/// The valid WOTS+ chain positions are `0..WOTS_W`; therefore
/// `start + steps` must not exceed `WOTS_W - 1`.
pub fn chain(
    parameters: &SlhDsaParameters,
    public_seed: &[u8],
    address: &Address,
    start_value: &[u8],
    start: u32,
    steps: u32,
    output: &mut [u8],
) -> Result<(), WotsError> {
    if start_value.len() != parameters.n {
        return Err(WotsError::InvalidByteLength {
            expected: parameters.n,
            actual: start_value.len(),
        });
    }

    if output.len() != parameters.n {
        return Err(WotsError::InvalidByteLength {
            expected: parameters.n,
            actual: output.len(),
        });
    }

    let end = start
        .checked_add(steps)
        .ok_or(WotsError::ParameterOverflow)?;

    if end > WOTS_W - 1 {
        return Err(WotsError::InvalidChainRange { start, steps });
    }

    let mut current = [0_u8; 32];
    current[..parameters.n].copy_from_slice(start_value);

    let suite = HashSuite::new(parameters);
    let mut chain_address = *address;

    for hash_step in start..end {
        chain_address.set_hash_address(hash_step);

        let mut next = [0_u8; 32];
        suite.f(
            public_seed,
            &chain_address,
            &current[..parameters.n],
            &mut next[..parameters.n],
        )?;

        current[..parameters.n].copy_from_slice(&next[..parameters.n]);
    }

    output.copy_from_slice(&current[..parameters.n]);

    Ok(())
}

/// Generate one WOTS+ secret-key element.
///
/// This implements the FIPS 205 `wots_skGen` operation for one chain index.
/// The layer, tree, and key-pair components are inherited from `wots_address`.
pub fn secret_key_element(
    parameters: &SlhDsaParameters,
    secret_seed: &[u8],
    public_seed: &[u8],
    wots_address: &Address,
    chain_index: usize,
    output: &mut [u8],
) -> Result<(), WotsError> {
    let chain_count = len(parameters)?;

    if chain_index >= chain_count {
        return Err(WotsError::InvalidChainIndex {
            index: chain_index,
            chain_count,
        });
    }

    let chain_index = u32::try_from(chain_index).map_err(|_| WotsError::ParameterOverflow)?;

    let key_pair_address = wots_address.key_pair_address();
    let mut secret_address = *wots_address;

    secret_address.set_type_and_clear(AddressType::WotsPrf);
    secret_address.set_key_pair_address(key_pair_address);
    secret_address.set_chain_address(chain_index);

    HashSuite::new(parameters).prf(public_seed, secret_seed, &secret_address, output)?;

    Ok(())
}

/// Generate one WOTS+ public-key chain endpoint.
///
/// The corresponding secret-key element is generated with `PRF` and then
/// advanced through all `WOTS_W - 1` applications of `F`.
pub fn public_key_element(
    parameters: &SlhDsaParameters,
    secret_seed: &[u8],
    public_seed: &[u8],
    wots_address: &Address,
    chain_index: usize,
    output: &mut [u8],
) -> Result<(), WotsError> {
    let mut secret_value = [0_u8; 32];

    secret_key_element(
        parameters,
        secret_seed,
        public_seed,
        wots_address,
        chain_index,
        &mut secret_value[..parameters.n],
    )?;

    let chain_index_u32 = u32::try_from(chain_index).map_err(|_| WotsError::ParameterOverflow)?;
    let key_pair_address = wots_address.key_pair_address();

    let mut chain_address = *wots_address;
    chain_address.set_type_and_clear(AddressType::WotsHash);
    chain_address.set_key_pair_address(key_pair_address);
    chain_address.set_chain_address(chain_index_u32);

    chain(
        parameters,
        public_seed,
        &chain_address,
        &secret_value[..parameters.n],
        0,
        WOTS_W - 1,
        output,
    )
}

/// Generate and compress a complete WOTS+ public key.
///
/// All `len` chain endpoints are concatenated and compressed with `T_l` under
/// a `WOTS_PK` address.
pub fn public_key(
    parameters: &SlhDsaParameters,
    secret_seed: &[u8],
    public_seed: &[u8],
    wots_address: &Address,
    output: &mut [u8],
) -> Result<(), WotsError> {
    if output.len() != parameters.n {
        return Err(WotsError::InvalidByteLength {
            expected: parameters.n,
            actual: output.len(),
        });
    }

    let chain_count = len(parameters)?;
    let endpoint_bytes = chain_count
        .checked_mul(parameters.n)
        .ok_or(WotsError::ParameterOverflow)?;

    let mut endpoints = [0_u8; MAX_WOTS_LEN * 32];

    for chain_index in 0..chain_count {
        let start = chain_index
            .checked_mul(parameters.n)
            .ok_or(WotsError::ParameterOverflow)?;
        let end = start
            .checked_add(parameters.n)
            .ok_or(WotsError::ParameterOverflow)?;

        public_key_element(
            parameters,
            secret_seed,
            public_seed,
            wots_address,
            chain_index,
            &mut endpoints[start..end],
        )?;
    }

    let key_pair_address = wots_address.key_pair_address();
    let mut public_key_address = *wots_address;

    public_key_address.set_type_and_clear(AddressType::WotsPublicKey);
    public_key_address.set_key_pair_address(key_pair_address);

    HashSuite::new(parameters).t_l(
        public_seed,
        &public_key_address,
        &endpoints[..endpoint_bytes],
        output,
    )?;

    Ok(())
}

/// Convert an `n`-byte message into its `len_1` base-`w` digits.
pub fn message_digits(
    parameters: &SlhDsaParameters,
    message: &[u8],
    output: &mut [u32],
) -> Result<(), WotsError> {
    if message.len() != parameters.n {
        return Err(WotsError::InvalidMessageLength {
            expected: parameters.n,
            actual: message.len(),
        });
    }

    let expected = len_1(parameters)?;

    if output.len() != expected {
        return Err(WotsError::InvalidDigitCount {
            expected,
            actual: output.len(),
        });
    }

    base_2b(message, WOTS_LOG_W, output)?;

    Ok(())
}

/// Compute the integer WOTS+ checksum for a sequence of message digits.
///
/// The input must contain exactly `len_1` digits. Every digit must have been
/// produced by the base-`w` message conversion and is therefore in
/// `0..WOTS_W`.
pub fn checksum(parameters: &SlhDsaParameters, message_digits: &[u32]) -> Result<u64, WotsError> {
    let expected = len_1(parameters)?;

    if message_digits.len() != expected {
        return Err(WotsError::InvalidDigitCount {
            expected,
            actual: message_digits.len(),
        });
    }

    message_digits.iter().try_fold(0_u64, |sum, digit| {
        let complement = WOTS_W
            .checked_sub(1)
            .and_then(|maximum| maximum.checked_sub(*digit))
            .ok_or(WotsError::ParameterOverflow)?;

        sum.checked_add(u64::from(complement))
            .ok_or(WotsError::ParameterOverflow)
    })
}

/// Convert the WOTS+ checksum into its `len_2` base-`w` digits.
///
/// FIPS 205 left-shifts the checksum so the base-`w` conversion consumes a
/// whole number of bytes.
pub fn checksum_digits(
    parameters: &SlhDsaParameters,
    message_digits: &[u32],
    output: &mut [u32],
) -> Result<(), WotsError> {
    let expected = len_2(parameters)?;

    if output.len() != expected {
        return Err(WotsError::InvalidDigitCount {
            expected,
            actual: output.len(),
        });
    }

    let checksum_bits = expected
        .checked_mul(WOTS_LOG_W)
        .ok_or(WotsError::ParameterOverflow)?;

    let padding_bits = (8 - (checksum_bits % 8)) % 8;
    let shifted_checksum = checksum(parameters, message_digits)?
        .checked_shl(u32::try_from(padding_bits).map_err(|_| WotsError::ParameterOverflow)?)
        .ok_or(WotsError::ParameterOverflow)?;

    let encoded_bytes = checksum_bytes(parameters)?;

    if encoded_bytes > size_of::<u64>() {
        return Err(WotsError::ParameterOverflow);
    }

    let encoded = shifted_checksum.to_be_bytes();
    let start = encoded.len() - encoded_bytes;

    base_2b(&encoded[start..], WOTS_LOG_W, output)?;

    Ok(())
}

/// Convert a message into all `len` WOTS+ chain lengths.
///
/// The first `len_1` entries encode the message. The remaining `len_2`
/// entries encode its checksum.
pub fn chain_lengths(
    parameters: &SlhDsaParameters,
    message: &[u8],
    output: &mut [u32],
) -> Result<(), WotsError> {
    let message_digit_count = len_1(parameters)?;
    let checksum_digit_count = len_2(parameters)?;
    let expected = message_digit_count
        .checked_add(checksum_digit_count)
        .ok_or(WotsError::ParameterOverflow)?;

    if output.len() != expected {
        return Err(WotsError::InvalidDigitCount {
            expected,
            actual: output.len(),
        });
    }

    let (message_output, checksum_output) = output.split_at_mut(message_digit_count);

    message_digits(parameters, message, message_output)?;
    checksum_digits(parameters, message_output, checksum_output)?;

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

    fn test_address(key_pair: u32) -> Address {
        let mut address = Address::new();
        address.set_layer_address(3);
        address.set_tree_address(0x0102_0304_0506_0708);
        address.set_type_and_clear(AddressType::WotsHash);
        address.set_key_pair_address(key_pair);
        address
    }

    #[test]
    fn zero_step_chain_returns_its_start_value() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let public_seed = [0x11_u8; 16];
        let start_value = [0x22_u8; 16];
        let mut output = [0_u8; 16];

        chain(
            &parameters,
            &public_seed,
            &test_address(7),
            &start_value,
            4,
            0,
            &mut output,
        )
        .unwrap();

        assert_eq!(output, start_value);
    }

    #[test]
    fn chain_matches_repeated_direct_f_evaluation() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let public_seed = [0x31_u8; 16];
        let start_value = [0x42_u8; 16];

        let mut address = test_address(9);
        address.set_chain_address(5);

        let mut chained = [0_u8; 16];

        chain(
            &parameters,
            &public_seed,
            &address,
            &start_value,
            2,
            3,
            &mut chained,
        )
        .unwrap();

        let suite = HashSuite::new(&parameters);
        let mut current = start_value;

        for hash_step in 2..5 {
            address.set_hash_address(hash_step);
            let mut next = [0_u8; 16];

            suite
                .f(&public_seed, &address, &current, &mut next)
                .unwrap();

            current = next;
        }

        assert_eq!(chained, current);
    }

    #[test]
    fn chain_rejects_ranges_past_the_endpoint() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let public_seed = [0_u8; 16];
        let start_value = [0_u8; 16];
        let mut output = [0_u8; 16];

        assert_eq!(
            chain(
                &parameters,
                &public_seed,
                &test_address(0),
                &start_value,
                14,
                2,
                &mut output,
            ),
            Err(WotsError::InvalidChainRange {
                start: 14,
                steps: 2,
            })
        );
    }

    #[test]
    fn secret_key_element_matches_direct_prf_evaluation() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0x51_u8; 16];
        let public_seed = [0x62_u8; 16];
        let address = test_address(11);

        let mut generated = [0_u8; 16];

        secret_key_element(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            7,
            &mut generated,
        )
        .unwrap();

        let mut expected_address = address;
        expected_address.set_type_and_clear(AddressType::WotsPrf);
        expected_address.set_key_pair_address(11);
        expected_address.set_chain_address(7);

        let mut expected = [0_u8; 16];

        HashSuite::new(&parameters)
            .prf(&public_seed, &secret_seed, &expected_address, &mut expected)
            .unwrap();

        assert_eq!(generated, expected);
    }

    #[test]
    fn secret_key_elements_are_domain_separated_by_chain_index() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0x71_u8; 16];
        let public_seed = [0x82_u8; 16];
        let address = test_address(13);

        let mut first = [0_u8; 16];
        let mut second = [0_u8; 16];

        secret_key_element(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            0,
            &mut first,
        )
        .unwrap();

        secret_key_element(
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
    fn public_key_element_matches_secret_value_followed_by_full_chain() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0x91_u8; 16];
        let public_seed = [0xa2_u8; 16];
        let address = test_address(15);

        let mut generated = [0_u8; 16];

        public_key_element(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            4,
            &mut generated,
        )
        .unwrap();

        let mut secret = [0_u8; 16];

        secret_key_element(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            4,
            &mut secret,
        )
        .unwrap();

        let mut chain_address = address;
        chain_address.set_type_and_clear(AddressType::WotsHash);
        chain_address.set_key_pair_address(15);
        chain_address.set_chain_address(4);

        let mut expected = [0_u8; 16];

        chain(
            &parameters,
            &public_seed,
            &chain_address,
            &secret,
            0,
            WOTS_W - 1,
            &mut expected,
        )
        .unwrap();

        assert_eq!(generated, expected);
    }

    #[test]
    fn public_key_matches_direct_endpoint_compression() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0xb1_u8; 16];
        let public_seed = [0xc2_u8; 16];
        let address = test_address(17);

        let mut generated = [0_u8; 16];

        public_key(
            &parameters,
            &secret_seed,
            &public_seed,
            &address,
            &mut generated,
        )
        .unwrap();

        let chain_count = len(&parameters).unwrap();
        let mut endpoints = [0_u8; MAX_WOTS_LEN * 32];

        for chain_index in 0..chain_count {
            let start = chain_index * parameters.n;
            let end = start + parameters.n;

            public_key_element(
                &parameters,
                &secret_seed,
                &public_seed,
                &address,
                chain_index,
                &mut endpoints[start..end],
            )
            .unwrap();
        }

        let mut compression_address = address;
        compression_address.set_type_and_clear(AddressType::WotsPublicKey);
        compression_address.set_key_pair_address(17);

        let mut expected = [0_u8; 16];

        HashSuite::new(&parameters)
            .t_l(
                &public_seed,
                &compression_address,
                &endpoints[..chain_count * parameters.n],
                &mut expected,
            )
            .unwrap();

        assert_eq!(generated, expected);
    }

    #[test]
    fn public_key_is_deterministic_for_every_parameter_set() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let secret_seed = [0xd1_u8; 32];
            let public_seed = [0xe2_u8; 32];
            let address = test_address(19);

            let mut first = [0_u8; 32];
            let mut second = [0_u8; 32];

            public_key(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                &mut first[..parameters.n],
            )
            .unwrap();

            public_key(
                &parameters,
                &secret_seed[..parameters.n],
                &public_seed[..parameters.n],
                &address,
                &mut second[..parameters.n],
            )
            .unwrap();

            assert_eq!(&first[..parameters.n], &second[..parameters.n]);
        }
    }

    #[test]
    fn public_key_is_domain_separated_by_key_pair_address() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let secret_seed = [0xf1_u8; 16];
        let public_seed = [0x12_u8; 16];

        let mut first = [0_u8; 16];
        let mut second = [0_u8; 16];

        public_key(
            &parameters,
            &secret_seed,
            &public_seed,
            &test_address(20),
            &mut first,
        )
        .unwrap();

        public_key(
            &parameters,
            &secret_seed,
            &public_seed,
            &test_address(21),
            &mut second,
        )
        .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn fips_parameter_sets_have_the_expected_wots_lengths() {
        let expected = [
            (SlhDsaParameterSet::Sha2_128s, 32, 3, 35),
            (SlhDsaParameterSet::Sha2_128f, 32, 3, 35),
            (SlhDsaParameterSet::Sha2_192s, 48, 3, 51),
            (SlhDsaParameterSet::Sha2_192f, 48, 3, 51),
            (SlhDsaParameterSet::Sha2_256s, 64, 3, 67),
            (SlhDsaParameterSet::Sha2_256f, 64, 3, 67),
            (SlhDsaParameterSet::Shake128s, 32, 3, 35),
            (SlhDsaParameterSet::Shake128f, 32, 3, 35),
            (SlhDsaParameterSet::Shake192s, 48, 3, 51),
            (SlhDsaParameterSet::Shake192f, 48, 3, 51),
            (SlhDsaParameterSet::Shake256s, 64, 3, 67),
            (SlhDsaParameterSet::Shake256f, 64, 3, 67),
        ];

        for (parameter_set, expected_len_1, expected_len_2, expected_len) in expected {
            let parameters = parameter_set.parameters();

            assert_eq!(len_1(&parameters), Ok(expected_len_1));
            assert_eq!(len_2(&parameters), Ok(expected_len_2));
            assert_eq!(len(&parameters), Ok(expected_len));
        }
    }

    #[test]
    fn maximum_fips_wots_length_matches_the_constant() {
        for parameter_set in PARAMETER_SETS {
            assert!(len(&parameter_set.parameters()).unwrap() <= MAX_WOTS_LEN);
        }

        assert_eq!(
            len(&SlhDsaParameterSet::Sha2_256s.parameters()),
            Ok(MAX_WOTS_LEN)
        );
    }

    #[test]
    fn every_fips_checksum_uses_two_bytes() {
        for parameter_set in PARAMETER_SETS {
            assert_eq!(checksum_bytes(&parameter_set.parameters()), Ok(2));
        }
    }

    #[test]
    fn message_digits_are_extracted_most_significant_first() {
        let mut parameters = SlhDsaParameterSet::Shake128s.parameters();
        parameters.n = 2;

        let mut output = [0_u32; 4];

        message_digits(&parameters, &[0xab, 0x4d], &mut output).unwrap();

        assert_eq!(output, [10, 11, 4, 13]);
    }

    #[test]
    fn message_digits_reject_the_wrong_message_length() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let mut output = [0_u32; 32];

        assert_eq!(
            message_digits(&parameters, &[0_u8; 15], &mut output),
            Err(WotsError::InvalidMessageLength {
                expected: 16,
                actual: 15,
            })
        );
    }

    #[test]
    fn message_digits_reject_the_wrong_output_length() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let message = [0_u8; 16];
        let mut output = [0_u32; 31];

        assert_eq!(
            message_digits(&parameters, &message, &mut output),
            Err(WotsError::InvalidDigitCount {
                expected: 32,
                actual: 31,
            })
        );
    }

    #[test]
    fn checksum_is_the_sum_of_digit_complements() {
        let mut parameters = SlhDsaParameterSet::Shake128s.parameters();
        parameters.n = 2;

        let digits = [10, 11, 4, 13];

        assert_eq!(checksum(&parameters, &digits), Ok((5 + 4 + 11 + 2) as u64));
    }

    #[test]
    fn all_zero_message_has_the_maximal_checksum() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let digits = [0_u32; 32];

        assert_eq!(checksum(&parameters, &digits), Ok(32 * 15));
    }

    #[test]
    fn all_maximal_digits_have_zero_checksum() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let digits = [15_u32; 32];

        assert_eq!(checksum(&parameters, &digits), Ok(0));
    }

    #[test]
    fn checksum_rejects_digits_outside_base_w() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let mut digits = [0_u32; 32];
        digits[7] = WOTS_W;

        assert_eq!(
            checksum(&parameters, &digits),
            Err(WotsError::ParameterOverflow)
        );
    }

    #[test]
    fn checksum_digits_include_the_required_left_shift() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let digits = [0_u32; 32];
        let mut output = [0_u32; 3];

        checksum_digits(&parameters, &digits, &mut output).unwrap();

        // checksum = 32 * 15 = 480 = 0x01e0.
        // FIPS 205 shifts it left by four bits before base-16 conversion:
        // 0x1e00 -> [1, 14, 0].
        assert_eq!(output, [1, 14, 0]);
    }

    #[test]
    fn chain_lengths_concatenate_message_and_checksum_digits() {
        let mut parameters = SlhDsaParameterSet::Shake128s.parameters();
        parameters.n = 2;

        let mut output = [0_u32; 6];

        chain_lengths(&parameters, &[0xab, 0x4d], &mut output).unwrap();

        assert_eq!(&output[..4], &[10, 11, 4, 13]);
        assert_eq!(&output[4..], &[1, 6]);
    }

    #[test]
    fn every_chain_length_is_bounded_by_w_minus_one() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let message = [0xa5_u8; 32];
            let mut output = [0_u32; MAX_WOTS_LEN];
            let output_length = len(&parameters).unwrap();

            chain_lengths(
                &parameters,
                &message[..parameters.n],
                &mut output[..output_length],
            )
            .unwrap();

            assert!(output[..output_length].iter().all(|digit| *digit < WOTS_W));
        }
    }

    #[test]
    fn chain_lengths_reject_the_wrong_output_length() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let message = [0_u8; 16];
        let mut output = [0_u32; 34];

        assert_eq!(
            chain_lengths(&parameters, &message, &mut output),
            Err(WotsError::InvalidDigitCount {
                expected: 35,
                actual: 34,
            })
        );
    }
}
