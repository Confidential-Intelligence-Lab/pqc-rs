//! SHAKE-based FIPS 205 tweakable-hash functions.

use core::fmt;

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
