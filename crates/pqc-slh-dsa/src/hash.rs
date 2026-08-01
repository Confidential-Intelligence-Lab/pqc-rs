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

    /// MGF1 could not generate the requested output.
    MaskGeneration(Mgf1Error),
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
            Self::MaskGeneration(error) => {
                write!(formatter, "message-digest expansion failed: {error}")
            }
        }
    }
}

impl From<Mgf1Error> for HashError {
    fn from(error: Mgf1Error) -> Self {
        Self::MaskGeneration(error)
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

    /// Generate the FIPS 205 per-message randomization value.
    ///
    /// SHAKE256 absorbs:
    ///
    /// `SK.prf || opt_rand || M`
    ///
    /// and returns `n` bytes.
    pub fn prf_msg(
        self,
        secret_prf: &[u8],
        optional_randomness: &[u8],
        message: &[u8],
        output: &mut [u8],
    ) -> Result<(), HashError> {
        self.validate_fixed_input(secret_prf, "secret PRF key")?;
        self.validate_fixed_input(optional_randomness, "optional randomness")?;
        self.validate_output(output)?;

        shake256_into(&[secret_prf, optional_randomness, message], output);

        Ok(())
    }

    /// Generate the FIPS 205 message digest.
    ///
    /// SHAKE256 absorbs:
    ///
    /// `R || PK.seed || PK.root || M`
    ///
    /// and fills the caller-provided output buffer.
    pub fn h_msg(
        self,
        randomizer: &[u8],
        public_seed: &[u8],
        public_root: &[u8],
        message: &[u8],
        output: &mut [u8],
    ) -> Result<(), HashError> {
        self.validate_fixed_input(randomizer, "message randomizer")?;
        self.validate_fixed_input(public_seed, "public seed")?;
        self.validate_fixed_input(public_root, "public root")?;

        shake256_into(&[randomizer, public_seed, public_root, message], output);

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

    /// Generate the FIPS 205 per-message randomization value.
    ///
    /// For `n = 16`, this evaluates HMAC-SHA-256 over
    /// `opt_rand || M` using `SK.prf` as the key. For `n = 24` or `n = 32`,
    /// it evaluates HMAC-SHA-512 instead. The result is truncated to `n`
    /// bytes.
    pub fn prf_msg(
        self,
        secret_prf: &[u8],
        optional_randomness: &[u8],
        message: &[u8],
        output: &mut [u8],
    ) -> Result<(), HashError> {
        self.validate_configuration()?;
        self.validate_fixed_input(secret_prf, "secret PRF key")?;
        self.validate_fixed_input(optional_randomness, "optional randomness")?;
        self.validate_output(output)?;

        if self.output_bytes == 16 {
            hmac_sha256_truncated(secret_prf, &[optional_randomness, message], output);
        } else {
            hmac_sha512_truncated(secret_prf, &[optional_randomness, message], output);
        }

        Ok(())
    }

    /// Generate the FIPS 205 message digest.
    ///
    /// For `n = 16`, SHA-256 hashes
    /// `R || PK.seed || PK.root || M`, and MGF1-SHA-256 expands
    /// `R || PK.seed || digest`.
    ///
    /// For `n = 24` or `n = 32`, SHA-512 and MGF1-SHA-512 are used.
    pub fn h_msg(
        self,
        randomizer: &[u8],
        public_seed: &[u8],
        public_root: &[u8],
        message: &[u8],
        output: &mut [u8],
    ) -> Result<(), HashError> {
        self.validate_configuration()?;
        self.validate_fixed_input(randomizer, "message randomizer")?;
        self.validate_fixed_input(public_seed, "public seed")?;
        self.validate_fixed_input(public_root, "public root")?;

        if self.output_bytes == 16 {
            let mut hasher = Sha256::new();
            Sha2Digest::update(&mut hasher, randomizer);
            Sha2Digest::update(&mut hasher, public_seed);
            Sha2Digest::update(&mut hasher, public_root);
            Sha2Digest::update(&mut hasher, message);
            let digest = hasher.finalize();

            let mut seed = [0_u8; 64];
            let seed_bytes = 2 * self.output_bytes + digest.len();

            seed[..self.output_bytes].copy_from_slice(randomizer);
            seed[self.output_bytes..2 * self.output_bytes].copy_from_slice(public_seed);
            seed[2 * self.output_bytes..seed_bytes].copy_from_slice(&digest);

            mgf1_sha256(&seed[..seed_bytes], output)?;
        } else {
            let mut hasher = Sha512::new();
            Sha2Digest::update(&mut hasher, randomizer);
            Sha2Digest::update(&mut hasher, public_seed);
            Sha2Digest::update(&mut hasher, public_root);
            Sha2Digest::update(&mut hasher, message);
            let digest = hasher.finalize();

            let mut seed = [0_u8; 128];
            let seed_bytes = 2 * self.output_bytes + digest.len();

            seed[..self.output_bytes].copy_from_slice(randomizer);
            seed[self.output_bytes..2 * self.output_bytes].copy_from_slice(public_seed);
            seed[2 * self.output_bytes..seed_bytes].copy_from_slice(&digest);

            mgf1_sha512(&seed[..seed_bytes], output)?;
        }

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

fn hmac_sha256_truncated(key: &[u8], inputs: &[&[u8]], output: &mut [u8]) {
    const BLOCK_BYTES: usize = 64;

    let mut inner_pad = [0x36_u8; BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; BLOCK_BYTES];

    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }

    let mut inner = Sha256::new();
    Sha2Digest::update(&mut inner, inner_pad);

    for input in inputs {
        Sha2Digest::update(&mut inner, input);
    }

    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    Sha2Digest::update(&mut outer, outer_pad);
    Sha2Digest::update(&mut outer, inner_digest);

    let digest = outer.finalize();
    output.copy_from_slice(&digest[..output.len()]);
}

fn hmac_sha512_truncated(key: &[u8], inputs: &[&[u8]], output: &mut [u8]) {
    const BLOCK_BYTES: usize = 128;

    let mut inner_pad = [0x36_u8; BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; BLOCK_BYTES];

    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }

    let mut inner = Sha512::new();
    Sha2Digest::update(&mut inner, inner_pad);

    for input in inputs {
        Sha2Digest::update(&mut inner, input);
    }

    let inner_digest = inner.finalize();

    let mut outer = Sha512::new();
    Sha2Digest::update(&mut outer, outer_pad);
    Sha2Digest::update(&mut outer, inner_digest);

    let digest = outer.finalize();
    output.copy_from_slice(&digest[..output.len()]);
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

#[cfg(test)]
mod prf_msg_tests {
    use super::*;

    fn reference_hmac_sha256(key: &[u8], inputs: &[&[u8]], output: &mut [u8]) {
        const BLOCK_BYTES: usize = 64;

        let mut inner_pad = [0x36_u8; BLOCK_BYTES];
        let mut outer_pad = [0x5c_u8; BLOCK_BYTES];

        for (index, byte) in key.iter().enumerate() {
            inner_pad[index] ^= byte;
            outer_pad[index] ^= byte;
        }

        let mut inner = Sha256::new();
        Sha2Digest::update(&mut inner, inner_pad);

        for input in inputs {
            Sha2Digest::update(&mut inner, input);
        }

        let inner_digest = inner.finalize();

        let mut outer = Sha256::new();
        Sha2Digest::update(&mut outer, outer_pad);
        Sha2Digest::update(&mut outer, inner_digest);

        let digest = outer.finalize();
        output.copy_from_slice(&digest[..output.len()]);
    }

    fn reference_hmac_sha512(key: &[u8], inputs: &[&[u8]], output: &mut [u8]) {
        const BLOCK_BYTES: usize = 128;

        let mut inner_pad = [0x36_u8; BLOCK_BYTES];
        let mut outer_pad = [0x5c_u8; BLOCK_BYTES];

        for (index, byte) in key.iter().enumerate() {
            inner_pad[index] ^= byte;
            outer_pad[index] ^= byte;
        }

        let mut inner = Sha512::new();
        Sha2Digest::update(&mut inner, inner_pad);

        for input in inputs {
            Sha2Digest::update(&mut inner, input);
        }

        let inner_digest = inner.finalize();

        let mut outer = Sha512::new();
        Sha2Digest::update(&mut outer, outer_pad);
        Sha2Digest::update(&mut outer, inner_digest);

        let digest = outer.finalize();
        output.copy_from_slice(&digest[..output.len()]);
    }

    #[test]
    fn shake_prf_msg_matches_direct_absorption() {
        let hash = ShakeTweakableHash::new(16);
        let secret_prf = [0x11_u8; 16];
        let optional_randomness = [0x22_u8; 16];
        let message = b"SLH-DSA message";
        let mut actual = [0_u8; 16];
        let mut expected = [0_u8; 16];

        hash.prf_msg(&secret_prf, &optional_randomness, message, &mut actual)
            .unwrap();

        shake256_into(&[&secret_prf, &optional_randomness, message], &mut expected);

        assert_eq!(actual, expected);
    }

    #[test]
    fn shake_prf_msg_supports_32_byte_outputs() {
        let hash = ShakeTweakableHash::new(32);
        let secret_prf = [0x33_u8; 32];
        let optional_randomness = [0x44_u8; 32];
        let message = [0x55_u8; 97];
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];

        hash.prf_msg(&secret_prf, &optional_randomness, &message, &mut first)
            .unwrap();

        shake256_into(&[&secret_prf, &optional_randomness, &message], &mut second);

        assert_eq!(first, second);
    }

    #[test]
    fn sha2_category_one_uses_hmac_sha256() {
        let hash = Sha2TweakableHash::new(16);
        let secret_prf = [0x66_u8; 16];
        let optional_randomness = [0x77_u8; 16];
        let message = b"category one message";
        let mut actual = [0_u8; 16];
        let mut expected = [0_u8; 16];

        hash.prf_msg(&secret_prf, &optional_randomness, message, &mut actual)
            .unwrap();

        reference_hmac_sha256(&secret_prf, &[&optional_randomness, message], &mut expected);

        assert_eq!(actual, expected);
    }

    #[test]
    fn sha2_category_three_uses_hmac_sha512() {
        let hash = Sha2TweakableHash::new(24);
        let secret_prf = [0x88_u8; 24];
        let optional_randomness = [0x99_u8; 24];
        let message = b"category three message";
        let mut actual = [0_u8; 24];
        let mut expected = [0_u8; 24];

        hash.prf_msg(&secret_prf, &optional_randomness, message, &mut actual)
            .unwrap();

        reference_hmac_sha512(&secret_prf, &[&optional_randomness, message], &mut expected);

        assert_eq!(actual, expected);
    }

    #[test]
    fn sha2_category_five_uses_hmac_sha512() {
        let hash = Sha2TweakableHash::new(32);
        let secret_prf = [0xaa_u8; 32];
        let optional_randomness = [0xbb_u8; 32];
        let message = [0xcc_u8; 129];
        let mut actual = [0_u8; 32];
        let mut expected = [0_u8; 32];

        hash.prf_msg(&secret_prf, &optional_randomness, &message, &mut actual)
            .unwrap();

        reference_hmac_sha512(
            &secret_prf,
            &[&optional_randomness, &message],
            &mut expected,
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn prf_msg_validates_fixed_length_inputs() {
        let shake = ShakeTweakableHash::new(16);
        let sha2 = Sha2TweakableHash::new(16);
        let mut output = [0_u8; 16];

        assert_eq!(
            shake.prf_msg(&[0_u8; 15], &[0_u8; 16], b"", &mut output),
            Err(HashError::InvalidInputLength {
                input: "secret PRF key",
                expected: 16,
                actual: 15,
            })
        );

        assert_eq!(
            sha2.prf_msg(&[0_u8; 16], &[0_u8; 15], b"", &mut output),
            Err(HashError::InvalidInputLength {
                input: "optional randomness",
                expected: 16,
                actual: 15,
            })
        );
    }
}

#[cfg(test)]
mod h_msg_tests {
    use super::*;

    fn reference_mgf1_sha256(seed: &[u8], output: &mut [u8]) {
        for (counter, chunk) in output.chunks_mut(32).enumerate() {
            let mut hasher = Sha256::new();
            Sha2Digest::update(&mut hasher, seed);
            Sha2Digest::update(&mut hasher, u32::try_from(counter).unwrap().to_be_bytes());

            let digest = hasher.finalize();
            chunk.copy_from_slice(&digest[..chunk.len()]);
        }
    }

    fn reference_mgf1_sha512(seed: &[u8], output: &mut [u8]) {
        for (counter, chunk) in output.chunks_mut(64).enumerate() {
            let mut hasher = Sha512::new();
            Sha2Digest::update(&mut hasher, seed);
            Sha2Digest::update(&mut hasher, u32::try_from(counter).unwrap().to_be_bytes());

            let digest = hasher.finalize();
            chunk.copy_from_slice(&digest[..chunk.len()]);
        }
    }

    #[test]
    fn shake_h_msg_matches_direct_xof_absorption() {
        let hash = ShakeTweakableHash::new(16);
        let randomizer = [0x11_u8; 16];
        let public_seed = [0x22_u8; 16];
        let public_root = [0x33_u8; 16];
        let message = b"SLH-DSA message digest input";
        let mut actual = [0_u8; 30];
        let mut expected = [0_u8; 30];

        hash.h_msg(
            &randomizer,
            &public_seed,
            &public_root,
            message,
            &mut actual,
        )
        .unwrap();

        shake256_into(
            &[&randomizer, &public_seed, &public_root, message],
            &mut expected,
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn shake_h_msg_supports_all_fips_digest_lengths() {
        for digest_bytes in [30_usize, 34, 39, 42, 47, 49] {
            let hash = ShakeTweakableHash::new(32);
            let randomizer = [0x44_u8; 32];
            let public_seed = [0x55_u8; 32];
            let public_root = [0x66_u8; 32];
            let message = [0x77_u8; 73];
            let mut output = [0_u8; 49];

            hash.h_msg(
                &randomizer,
                &public_seed,
                &public_root,
                &message,
                &mut output[..digest_bytes],
            )
            .unwrap();

            assert!(output[..digest_bytes].iter().any(|byte| *byte != 0));
        }
    }

    #[test]
    fn sha2_category_one_matches_sha256_and_mgf1_sha256() {
        let hash = Sha2TweakableHash::new(16);
        let randomizer = [0x10_u8; 16];
        let public_seed = [0x20_u8; 16];
        let public_root = [0x30_u8; 16];
        let message = b"category one message digest";
        let mut actual = [0_u8; 34];
        let mut expected = [0_u8; 34];

        hash.h_msg(
            &randomizer,
            &public_seed,
            &public_root,
            message,
            &mut actual,
        )
        .unwrap();

        let mut hasher = Sha256::new();
        Sha2Digest::update(&mut hasher, randomizer);
        Sha2Digest::update(&mut hasher, public_seed);
        Sha2Digest::update(&mut hasher, public_root);
        Sha2Digest::update(&mut hasher, message);
        let digest = hasher.finalize();

        let mut seed = [0_u8; 64];
        seed[..16].copy_from_slice(&randomizer);
        seed[16..32].copy_from_slice(&public_seed);
        seed[32..64].copy_from_slice(&digest);

        reference_mgf1_sha256(&seed, &mut expected);

        assert_eq!(actual, expected);
    }

    #[test]
    fn sha2_category_three_matches_sha512_and_mgf1_sha512() {
        let hash = Sha2TweakableHash::new(24);
        let randomizer = [0x40_u8; 24];
        let public_seed = [0x50_u8; 24];
        let public_root = [0x60_u8; 24];
        let message = b"category three message digest";
        let mut actual = [0_u8; 42];
        let mut expected = [0_u8; 42];

        hash.h_msg(
            &randomizer,
            &public_seed,
            &public_root,
            message,
            &mut actual,
        )
        .unwrap();

        let mut hasher = Sha512::new();
        Sha2Digest::update(&mut hasher, randomizer);
        Sha2Digest::update(&mut hasher, public_seed);
        Sha2Digest::update(&mut hasher, public_root);
        Sha2Digest::update(&mut hasher, message);
        let digest = hasher.finalize();

        let mut seed = [0_u8; 112];
        seed[..24].copy_from_slice(&randomizer);
        seed[24..48].copy_from_slice(&public_seed);
        seed[48..112].copy_from_slice(&digest);

        reference_mgf1_sha512(&seed, &mut expected);

        assert_eq!(actual, expected);
    }

    #[test]
    fn sha2_category_five_matches_sha512_and_mgf1_sha512() {
        let hash = Sha2TweakableHash::new(32);
        let randomizer = [0x70_u8; 32];
        let public_seed = [0x80_u8; 32];
        let public_root = [0x90_u8; 32];
        let message = [0xa0_u8; 129];
        let mut actual = [0_u8; 49];
        let mut expected = [0_u8; 49];

        hash.h_msg(
            &randomizer,
            &public_seed,
            &public_root,
            &message,
            &mut actual,
        )
        .unwrap();

        let mut hasher = Sha512::new();
        Sha2Digest::update(&mut hasher, randomizer);
        Sha2Digest::update(&mut hasher, public_seed);
        Sha2Digest::update(&mut hasher, public_root);
        Sha2Digest::update(&mut hasher, message);
        let digest = hasher.finalize();

        let mut seed = [0_u8; 128];
        seed[..32].copy_from_slice(&randomizer);
        seed[32..64].copy_from_slice(&public_seed);
        seed[64..128].copy_from_slice(&digest);

        reference_mgf1_sha512(&seed, &mut expected);

        assert_eq!(actual, expected);
    }

    #[test]
    fn h_msg_validates_all_fixed_length_inputs() {
        let hash = Sha2TweakableHash::new(16);
        let mut output = [0_u8; 30];

        assert_eq!(
            hash.h_msg(&[0_u8; 15], &[0_u8; 16], &[0_u8; 16], b"", &mut output,),
            Err(HashError::InvalidInputLength {
                input: "message randomizer",
                expected: 16,
                actual: 15,
            })
        );

        assert_eq!(
            hash.h_msg(&[0_u8; 16], &[0_u8; 15], &[0_u8; 16], b"", &mut output,),
            Err(HashError::InvalidInputLength {
                input: "public seed",
                expected: 16,
                actual: 15,
            })
        );

        assert_eq!(
            hash.h_msg(&[0_u8; 16], &[0_u8; 16], &[0_u8; 15], b"", &mut output,),
            Err(HashError::InvalidInputLength {
                input: "public root",
                expected: 16,
                actual: 15,
            })
        );
    }
}
