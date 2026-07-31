//! SHAKE-based FIPS 205 tweakable-hash functions.

use core::fmt;

use sha2::{digest::OutputSizeUser, Digest as Sha2Digest, Sha256, Sha512};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::address::Address;

/// Errors returned by the internal tweakable-hash layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashError {
    /// An input that must contain exactly `n` bytes had the wrong length.
    InvalidInputLength {
        /// Name of the invalid input.
        input: &'static str,

        /// Required input length in bytes.
        expected: usize,

        /// Actual input length in bytes.
        actual: usize,
    },

    /// The output buffer did not contain exactly `n` bytes.
    InvalidOutputLength {
        /// Required output length in bytes.
        expected: usize,

        /// Actual output length in bytes.
        actual: usize,
    },

    /// The configured SLH-DSA hash output length is unsupported.
    UnsupportedOutputLength {
        /// Unsupported output length in bytes.
        actual: usize,
    },
}

impl fmt::Display for HashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInputLength {
                input,
                expected,
                actual,
            } => {
                write!(
                    formatter,
                    "invalid {input} length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidOutputLength { expected, actual } => {
                write!(
                    formatter,
                    "invalid output length: expected {expected} bytes, got {actual}"
                )
            }
            Self::UnsupportedOutputLength { actual } => {
                write!(
                    formatter,
                    "unsupported SLH-DSA hash output length: {actual} bytes"
                )
            }
        }
    }
}

/// SHAKE-based tweakable-hash implementation for SLH-DSA.
///
/// This type implements the FIPS 205 `PRF`, `F`, `H`, and `T_l` functions
/// for the SHAKE parameter sets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShakeTweakableHash {
    output_bytes: usize,
}

impl ShakeTweakableHash {
    /// Construct a SHAKE tweakable-hash instance with an `n`-byte output.
    pub const fn new(output_bytes: usize) -> Self {
        Self { output_bytes }
    }

    /// Return the configured output length in bytes.
    pub const fn output_bytes(self) -> usize {
        self.output_bytes
    }

    /// Evaluate the FIPS 205 pseudorandom function.
    ///
    /// The absorbed input is:
    ///
    /// `PK.seed || ADRS || SK.seed`
    pub fn prf(
        self,
        public_seed: &[u8],
        secret_seed: &[u8],
        address: &Address,
        output: &mut [u8],
    ) -> Result<(), HashError> {
        self.validate_fixed_input(public_seed, "public seed")?;
        self.validate_fixed_input(secret_seed, "secret seed")?;
        self.validate_output(output)?;

        shake256_into(&[public_seed, address.as_bytes(), secret_seed], output);

        Ok(())
    }

    /// Evaluate the one-block FIPS 205 tweakable hash `F`.
    ///
    /// The absorbed input is:
    ///
    /// `PK.seed || ADRS || M1`
    pub fn f(
        self,
        public_seed: &[u8],
        address: &Address,
        message: &[u8],
        output: &mut [u8],
    ) -> Result<(), HashError> {
        self.validate_fixed_input(public_seed, "public seed")?;
        self.validate_fixed_input(message, "message block")?;
        self.validate_output(output)?;

        shake256_into(&[public_seed, address.as_bytes(), message], output);

        Ok(())
    }

    /// Evaluate the two-block FIPS 205 tweakable hash `H`.
    ///
    /// The absorbed input is:
    ///
    /// `PK.seed || ADRS || M1 || M2`
    pub fn h(
        self,
        public_seed: &[u8],
        address: &Address,
        left: &[u8],
        right: &[u8],
        output: &mut [u8],
    ) -> Result<(), HashError> {
        self.validate_fixed_input(public_seed, "public seed")?;
        self.validate_fixed_input(left, "left message block")?;
        self.validate_fixed_input(right, "right message block")?;
        self.validate_output(output)?;

        shake256_into(&[public_seed, address.as_bytes(), left, right], output);

        Ok(())
    }

    /// Evaluate the variable-length FIPS 205 tweakable hash `T_l`.
    ///
    /// The absorbed input is:
    ///
    /// `PK.seed || ADRS || M`
    pub fn t_l(
        self,
        public_seed: &[u8],
        address: &Address,
        message: &[u8],
        output: &mut [u8],
    ) -> Result<(), HashError> {
        self.validate_fixed_input(public_seed, "public seed")?;
        self.validate_output(output)?;

        shake256_into(&[public_seed, address.as_bytes(), message], output);

        Ok(())
    }

    fn validate_fixed_input(self, input: &[u8], input_name: &'static str) -> Result<(), HashError> {
        if input.len() != self.output_bytes {
            return Err(HashError::InvalidInputLength {
                input: input_name,
                expected: self.output_bytes,
                actual: input.len(),
            });
        }

        Ok(())
    }

    fn validate_output(self, output: &[u8]) -> Result<(), HashError> {
        if output.len() != self.output_bytes {
            return Err(HashError::InvalidOutputLength {
                expected: self.output_bytes,
                actual: output.len(),
            });
        }

        Ok(())
    }
}

/// SHA2-based tweakable-hash implementation for SLH-DSA.
///
/// FIPS 205 uses the compressed 22-byte address encoding for all SHA2
/// parameter sets. `PRF` and `F` use SHA-256. `H` and `T_l` use SHA-256
/// when `n = 16`, and SHA-512 when `n` is 24 or 32.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha2TweakableHash {
    output_bytes: usize,
}

impl Sha2TweakableHash {
    /// Construct a SHA2 tweakable-hash instance with an `n`-byte output.
    pub const fn new(output_bytes: usize) -> Self {
        Self { output_bytes }
    }

    /// Return the configured output length in bytes.
    pub const fn output_bytes(self) -> usize {
        self.output_bytes
    }

    /// Evaluate the FIPS 205 pseudorandom function.
    ///
    /// SHA-256 absorbs:
    ///
    /// `PK.seed || zero padding || ADRS^c || SK.seed`
    pub fn prf(
        self,
        public_seed: &[u8],
        secret_seed: &[u8],
        address: &Address,
        output: &mut [u8],
    ) -> Result<(), HashError> {
        self.validate_configuration()?;
        self.validate_fixed_input(public_seed, "public seed")?;
        self.validate_fixed_input(secret_seed, "secret seed")?;
        self.validate_output(output)?;

        let padding = [0_u8; 64];
        let compressed = address.compressed();
        let padding_bytes = 64 - self.output_bytes;

        sha256_truncated(
            &[
                public_seed,
                &padding[..padding_bytes],
                &compressed,
                secret_seed,
            ],
            output,
        );

        Ok(())
    }

    /// Evaluate the one-block FIPS 205 tweakable hash `F`.
    ///
    /// SHA-256 absorbs:
    ///
    /// `PK.seed || zero padding || ADRS^c || M1`
    pub fn f(
        self,
        public_seed: &[u8],
        address: &Address,
        message: &[u8],
        output: &mut [u8],
    ) -> Result<(), HashError> {
        self.validate_configuration()?;
        self.validate_fixed_input(public_seed, "public seed")?;
        self.validate_fixed_input(message, "message block")?;
        self.validate_output(output)?;

        let padding = [0_u8; 64];
        let compressed = address.compressed();
        let padding_bytes = 64 - self.output_bytes;

        sha256_truncated(
            &[public_seed, &padding[..padding_bytes], &compressed, message],
            output,
        );

        Ok(())
    }

    /// Evaluate the two-block FIPS 205 tweakable hash `H`.
    pub fn h(
        self,
        public_seed: &[u8],
        address: &Address,
        left: &[u8],
        right: &[u8],
        output: &mut [u8],
    ) -> Result<(), HashError> {
        self.validate_configuration()?;
        self.validate_fixed_input(public_seed, "public seed")?;
        self.validate_fixed_input(left, "left message block")?;
        self.validate_fixed_input(right, "right message block")?;
        self.validate_output(output)?;

        self.hash_variable(public_seed, address, &[left, right], output);

        Ok(())
    }

    /// Evaluate the variable-length FIPS 205 tweakable hash `T_l`.
    pub fn t_l(
        self,
        public_seed: &[u8],
        address: &Address,
        message: &[u8],
        output: &mut [u8],
    ) -> Result<(), HashError> {
        self.validate_configuration()?;
        self.validate_fixed_input(public_seed, "public seed")?;
        self.validate_output(output)?;

        self.hash_variable(public_seed, address, &[message], output);

        Ok(())
    }

    fn hash_variable(
        self,
        public_seed: &[u8],
        address: &Address,
        message_parts: &[&[u8]],
        output: &mut [u8],
    ) {
        let compressed = address.compressed();

        if self.output_bytes == 16 {
            let padding = [0_u8; 64];
            let padding_bytes = 64 - self.output_bytes;
            let mut hasher = Sha256::new();

            Sha2Digest::update(&mut hasher, public_seed);
            Sha2Digest::update(&mut hasher, &padding[..padding_bytes]);
            Sha2Digest::update(&mut hasher, compressed);

            for part in message_parts {
                Sha2Digest::update(&mut hasher, part);
            }

            let digest = hasher.finalize();
            output.copy_from_slice(&digest[..output.len()]);
        } else {
            let padding = [0_u8; 128];
            let padding_bytes = 128 - self.output_bytes;
            let mut hasher = Sha512::new();

            Sha2Digest::update(&mut hasher, public_seed);
            Sha2Digest::update(&mut hasher, &padding[..padding_bytes]);
            Sha2Digest::update(&mut hasher, compressed);

            for part in message_parts {
                Sha2Digest::update(&mut hasher, part);
            }

            let digest = hasher.finalize();
            output.copy_from_slice(&digest[..output.len()]);
        }
    }

    fn validate_configuration(self) -> Result<(), HashError> {
        if !matches!(self.output_bytes, 16 | 24 | 32) {
            return Err(HashError::UnsupportedOutputLength {
                actual: self.output_bytes,
            });
        }

        Ok(())
    }

    fn validate_fixed_input(self, input: &[u8], input_name: &'static str) -> Result<(), HashError> {
        if input.len() != self.output_bytes {
            return Err(HashError::InvalidInputLength {
                input: input_name,
                expected: self.output_bytes,
                actual: input.len(),
            });
        }

        Ok(())
    }

    fn validate_output(self, output: &[u8]) -> Result<(), HashError> {
        if output.len() != self.output_bytes {
            return Err(HashError::InvalidOutputLength {
                expected: self.output_bytes,
                actual: output.len(),
            });
        }

        Ok(())
    }
}

fn sha256_truncated(inputs: &[&[u8]], output: &mut [u8]) {
    let mut hasher = Sha256::new();

    for input in inputs {
        Sha2Digest::update(&mut hasher, input);
    }

    let digest = hasher.finalize();
    output.copy_from_slice(&digest[..output.len()]);
}

/// Errors returned by an MGF1 operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mgf1Error {
    /// The requested output would exhaust the four-byte MGF1 counter.
    OutputTooLong {
        /// Requested mask length in bytes.
        output_bytes: usize,

        /// Output length of the underlying digest in bytes.
        digest_bytes: usize,
    },
}

impl fmt::Display for Mgf1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooLong {
                output_bytes,
                digest_bytes,
            } => {
                write!(
                    formatter,
                    "MGF1 output length {output_bytes} exhausts the \
                     four-byte counter for a {digest_bytes}-byte digest"
                )
            }
        }
    }
}

/// Expand `seed` using MGF1 with SHA-256.
///
/// MGF1 evaluates SHA-256 over `seed || I2OSP(counter, 4)` for consecutive
/// counter values beginning at zero and concatenates the resulting digest
/// blocks until `output` is filled.
pub fn mgf1_sha256(seed: &[u8], output: &mut [u8]) -> Result<(), Mgf1Error> {
    mgf1::<Sha256>(seed, output)
}

/// Expand `seed` using MGF1 with SHA-512.
///
/// MGF1 evaluates SHA-512 over `seed || I2OSP(counter, 4)` for consecutive
/// counter values beginning at zero and concatenates the resulting digest
/// blocks until `output` is filled.
pub fn mgf1_sha512(seed: &[u8], output: &mut [u8]) -> Result<(), Mgf1Error> {
    mgf1::<Sha512>(seed, output)
}

fn mgf1<D>(seed: &[u8], output: &mut [u8]) -> Result<(), Mgf1Error>
where
    D: Sha2Digest + Default,
{
    let digest_bytes = <D as OutputSizeUser>::output_size();
    let output_bytes = output.len();
    let mut counter = 0_u32;
    let mut chunks = output.chunks_mut(digest_bytes).peekable();

    while let Some(chunk) = chunks.next() {
        let mut digest = D::new();
        Sha2Digest::update(&mut digest, seed);
        Sha2Digest::update(&mut digest, counter.to_be_bytes());

        let block = digest.finalize();
        chunk.copy_from_slice(&block[..chunk.len()]);

        if chunks.peek().is_some() {
            counter = counter.checked_add(1).ok_or(Mgf1Error::OutputTooLong {
                output_bytes,
                digest_bytes,
            })?;
        }
    }

    Ok(())
}

fn shake256_into(inputs: &[&[u8]], output: &mut [u8]) {
    let mut hasher = Shake256::default();

    for input in inputs {
        hasher.update(input);
    }

    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::AddressType;

    fn configured_address() -> Address {
        let mut address = Address::new();
        address.set_layer_address(3);
        address.set_tree_address(0x0102_0304_0506_0708);
        address.set_type_and_clear(AddressType::WotsHash);
        address.set_key_pair_address(9);
        address.set_chain_address(10);
        address.set_hash_address(11);
        address
    }

    fn reference_shake(inputs: &[&[u8]], output: &mut [u8]) {
        let mut hasher = Shake256::default();

        for input in inputs {
            hasher.update(input);
        }

        let mut reader = hasher.finalize_xof();
        reader.read(output);
    }

    #[test]
    fn output_length_is_reported() {
        assert_eq!(ShakeTweakableHash::new(16).output_bytes(), 16);
        assert_eq!(ShakeTweakableHash::new(24).output_bytes(), 24);
        assert_eq!(ShakeTweakableHash::new(32).output_bytes(), 32);
    }

    #[test]
    fn prf_matches_direct_shake256_absorption() {
        let hash = ShakeTweakableHash::new(16);
        let public_seed = [0x11_u8; 16];
        let secret_seed = [0x22_u8; 16];
        let address = configured_address();
        let mut actual = [0_u8; 16];
        let mut expected = [0_u8; 16];

        hash.prf(&public_seed, &secret_seed, &address, &mut actual)
            .unwrap();

        reference_shake(
            &[&public_seed, address.as_bytes(), &secret_seed],
            &mut expected,
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn f_matches_direct_shake256_absorption() {
        let hash = ShakeTweakableHash::new(24);
        let public_seed = [0x33_u8; 24];
        let message = [0x44_u8; 24];
        let address = configured_address();
        let mut actual = [0_u8; 24];
        let mut expected = [0_u8; 24];

        hash.f(&public_seed, &address, &message, &mut actual)
            .unwrap();

        reference_shake(&[&public_seed, address.as_bytes(), &message], &mut expected);

        assert_eq!(actual, expected);
    }

    #[test]
    fn h_matches_direct_shake256_absorption() {
        let hash = ShakeTweakableHash::new(32);
        let public_seed = [0x55_u8; 32];
        let left = [0x66_u8; 32];
        let right = [0x77_u8; 32];
        let address = configured_address();
        let mut actual = [0_u8; 32];
        let mut expected = [0_u8; 32];

        hash.h(&public_seed, &address, &left, &right, &mut actual)
            .unwrap();

        reference_shake(
            &[&public_seed, address.as_bytes(), &left, &right],
            &mut expected,
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn t_l_accepts_variable_length_messages() {
        let hash = ShakeTweakableHash::new(16);
        let public_seed = [0x88_u8; 16];
        let message = [0x99_u8; 48];
        let address = configured_address();
        let mut actual = [0_u8; 16];
        let mut expected = [0_u8; 16];

        hash.t_l(&public_seed, &address, &message, &mut actual)
            .unwrap();

        reference_shake(&[&public_seed, address.as_bytes(), &message], &mut expected);

        assert_eq!(actual, expected);
    }

    #[test]
    fn domain_separation_changes_the_output() {
        let hash = ShakeTweakableHash::new(16);
        let public_seed = [0xaa_u8; 16];
        let message = [0xbb_u8; 16];
        let mut first_address = Address::new();
        let mut second_address = Address::new();
        let mut first = [0_u8; 16];
        let mut second = [0_u8; 16];

        first_address.set_type_and_clear(AddressType::WotsHash);
        second_address.set_type_and_clear(AddressType::Tree);

        hash.f(&public_seed, &first_address, &message, &mut first)
            .unwrap();

        hash.f(&public_seed, &second_address, &message, &mut second)
            .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn fixed_length_inputs_are_validated() {
        let hash = ShakeTweakableHash::new(16);
        let address = Address::new();
        let mut output = [0_u8; 16];

        assert_eq!(
            hash.f(&[0_u8; 15], &address, &[0_u8; 16], &mut output),
            Err(HashError::InvalidInputLength {
                input: "public seed",
                expected: 16,
                actual: 15,
            })
        );

        assert_eq!(
            hash.f(&[0_u8; 16], &address, &[0_u8; 15], &mut output),
            Err(HashError::InvalidInputLength {
                input: "message block",
                expected: 16,
                actual: 15,
            })
        );
    }

    #[test]
    fn output_length_is_validated() {
        let hash = ShakeTweakableHash::new(16);
        let address = Address::new();
        let mut output = [0_u8; 15];

        assert_eq!(
            hash.f(&[0_u8; 16], &address, &[0_u8; 16], &mut output),
            Err(HashError::InvalidOutputLength {
                expected: 16,
                actual: 15,
            })
        );
    }
}

#[cfg(test)]
mod mgf1_tests {
    use super::*;

    #[test]
    fn sha256_matches_known_multi_block_result() {
        let mut output = [0_u8; 50];

        mgf1_sha256(b"seed", &mut output).unwrap();

        assert_eq!(
            output,
            [
                0x33, 0x6f, 0x28, 0xa0, 0x22, 0x19, 0x39, 0x39, 0x58, 0x5a, 0x1b, 0x4e, 0xdc, 0x98,
                0x9f, 0x87, 0x09, 0x17, 0xf3, 0xa5, 0xf6, 0xdd, 0xd1, 0x6e, 0x4f, 0xb3, 0x57, 0x08,
                0x4a, 0x6b, 0xdf, 0xc2, 0x73, 0xa6, 0x49, 0x42, 0x76, 0x64, 0xd0, 0x3b, 0xbb, 0x06,
                0x2e, 0x45, 0x64, 0x25, 0x48, 0x84, 0x16, 0xc5,
            ]
        );
    }

    #[test]
    fn sha512_matches_known_multi_block_result() {
        let mut output = [0_u8; 80];

        mgf1_sha512(b"seed", &mut output).unwrap();

        assert_eq!(
            output,
            [
                0xb7, 0x6f, 0x0d, 0x50, 0x7a, 0xaf, 0xec, 0xd1, 0x0f, 0x1a, 0x1f, 0x98, 0x93, 0x05,
                0x9f, 0x9d, 0x69, 0x1d, 0xe2, 0x20, 0x82, 0xc5, 0x6b, 0x90, 0x57, 0xc3, 0x8e, 0xa5,
                0x55, 0xa5, 0x06, 0x14, 0x8f, 0xda, 0x31, 0x3e, 0x51, 0x51, 0x5d, 0x18, 0x52, 0x2c,
                0x4e, 0x70, 0x06, 0x6f, 0x8a, 0xdf, 0xc7, 0x73, 0xcd, 0xe3, 0x14, 0xd4, 0x80, 0xb9,
                0x52, 0x17, 0x73, 0x49, 0x5e, 0x30, 0x69, 0xad, 0x24, 0xcb, 0x16, 0xe3, 0xee, 0xbf,
                0xe8, 0x44, 0x4a, 0xca, 0x93, 0xa8, 0x0c, 0xfd, 0x96, 0xb1,
            ]
        );
    }

    #[test]
    fn empty_outputs_are_accepted() {
        let mut output = [];

        assert_eq!(mgf1_sha256(b"seed", &mut output), Ok(()));
        assert_eq!(mgf1_sha512(b"seed", &mut output), Ok(()));
    }

    #[test]
    fn digest_selection_changes_the_mask() {
        let mut sha256_output = [0_u8; 32];
        let mut sha512_output = [0_u8; 32];

        mgf1_sha256(b"seed", &mut sha256_output).unwrap();
        mgf1_sha512(b"seed", &mut sha512_output).unwrap();

        assert_ne!(sha256_output, sha512_output);
    }

    #[test]
    fn changing_the_seed_changes_the_mask() {
        let mut first = [0_u8; 65];
        let mut second = [0_u8; 65];

        mgf1_sha512(b"first seed", &mut first).unwrap();
        mgf1_sha512(b"second seed", &mut second).unwrap();

        assert_ne!(first, second);
    }
}

#[cfg(test)]
mod sha2_tweakable_hash_tests {
    use super::*;
    use crate::address::AddressType;

    fn configured_address() -> Address {
        let mut address = Address::new();
        address.set_layer_address(3);
        address.set_tree_address(0x0102_0304_0506_0708);
        address.set_type_and_clear(AddressType::WotsHash);
        address.set_key_pair_address(9);
        address.set_chain_address(10);
        address.set_hash_address(11);
        address
    }

    fn reference_sha256(inputs: &[&[u8]], output: &mut [u8]) {
        let mut hasher = Sha256::new();

        for input in inputs {
            Sha2Digest::update(&mut hasher, input);
        }

        let digest = hasher.finalize();
        output.copy_from_slice(&digest[..output.len()]);
    }

    fn reference_sha512(inputs: &[&[u8]], output: &mut [u8]) {
        let mut hasher = Sha512::new();

        for input in inputs {
            Sha2Digest::update(&mut hasher, input);
        }

        let digest = hasher.finalize();
        output.copy_from_slice(&digest[..output.len()]);
    }

    #[test]
    fn output_length_is_reported() {
        assert_eq!(Sha2TweakableHash::new(16).output_bytes(), 16);
        assert_eq!(Sha2TweakableHash::new(24).output_bytes(), 24);
        assert_eq!(Sha2TweakableHash::new(32).output_bytes(), 32);
    }

    #[test]
    fn prf_uses_sha256_padding_and_compressed_address() {
        let hash = Sha2TweakableHash::new(16);
        let public_seed = [0x11_u8; 16];
        let secret_seed = [0x22_u8; 16];
        let address = configured_address();
        let compressed = address.compressed();
        let padding = [0_u8; 48];
        let mut actual = [0_u8; 16];
        let mut expected = [0_u8; 16];

        hash.prf(&public_seed, &secret_seed, &address, &mut actual)
            .unwrap();

        reference_sha256(
            &[&public_seed, &padding, &compressed, &secret_seed],
            &mut expected,
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn f_uses_sha256_for_24_byte_parameter_sets() {
        let hash = Sha2TweakableHash::new(24);
        let public_seed = [0x33_u8; 24];
        let message = [0x44_u8; 24];
        let address = configured_address();
        let compressed = address.compressed();
        let padding = [0_u8; 40];
        let mut actual = [0_u8; 24];
        let mut expected = [0_u8; 24];

        hash.f(&public_seed, &address, &message, &mut actual)
            .unwrap();

        reference_sha256(
            &[&public_seed, &padding, &compressed, &message],
            &mut expected,
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn h_uses_sha256_for_16_byte_parameter_sets() {
        let hash = Sha2TweakableHash::new(16);
        let public_seed = [0x55_u8; 16];
        let left = [0x66_u8; 16];
        let right = [0x77_u8; 16];
        let address = configured_address();
        let compressed = address.compressed();
        let padding = [0_u8; 48];
        let mut actual = [0_u8; 16];
        let mut expected = [0_u8; 16];

        hash.h(&public_seed, &address, &left, &right, &mut actual)
            .unwrap();

        reference_sha256(
            &[&public_seed, &padding, &compressed, &left, &right],
            &mut expected,
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn h_uses_sha512_for_24_byte_parameter_sets() {
        let hash = Sha2TweakableHash::new(24);
        let public_seed = [0x88_u8; 24];
        let left = [0x99_u8; 24];
        let right = [0xaa_u8; 24];
        let address = configured_address();
        let compressed = address.compressed();
        let padding = [0_u8; 104];
        let mut actual = [0_u8; 24];
        let mut expected = [0_u8; 24];

        hash.h(&public_seed, &address, &left, &right, &mut actual)
            .unwrap();

        reference_sha512(
            &[&public_seed, &padding, &compressed, &left, &right],
            &mut expected,
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn t_l_uses_sha512_for_32_byte_parameter_sets() {
        let hash = Sha2TweakableHash::new(32);
        let public_seed = [0xbb_u8; 32];
        let message = [0xcc_u8; 96];
        let address = configured_address();
        let compressed = address.compressed();
        let padding = [0_u8; 96];
        let mut actual = [0_u8; 32];
        let mut expected = [0_u8; 32];

        hash.t_l(&public_seed, &address, &message, &mut actual)
            .unwrap();

        reference_sha512(
            &[&public_seed, &padding, &compressed, &message],
            &mut expected,
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn unsupported_output_lengths_are_rejected() {
        let hash = Sha2TweakableHash::new(20);
        let address = Address::new();
        let mut output = [0_u8; 20];

        assert_eq!(
            hash.f(&[0_u8; 20], &address, &[0_u8; 20], &mut output),
            Err(HashError::UnsupportedOutputLength { actual: 20 })
        );
    }
}
