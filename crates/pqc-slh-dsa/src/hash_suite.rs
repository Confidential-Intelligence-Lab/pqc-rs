//! Parameter-driven dispatch for the FIPS 205 hash-function families.

use crate::{
    address::Address,
    hash::{HashError, Sha2TweakableHash, ShakeTweakableHash},
    params::{SlhDsaHashFamily, SlhDsaParameters},
};

/// Internal hash suite selected by an SLH-DSA parameter set.
///
/// This enum centralizes the distinction between the SHA2 and SHAKE
/// instantiations. Higher-level algorithms can therefore invoke the FIPS 205
/// hash primitives without independently dispatching on the hash family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashSuite {
    /// SHA2-based FIPS 205 hash functions.
    Sha2(Sha2TweakableHash),

    /// SHAKE-based FIPS 205 hash functions.
    Shake(ShakeTweakableHash),
}

impl HashSuite {
    /// Construct the hash suite required by `parameters`.
    pub const fn new(parameters: &SlhDsaParameters) -> Self {
        match parameters.hash_family {
            SlhDsaHashFamily::Sha2 => Self::Sha2(Sha2TweakableHash::new(parameters.n)),
            SlhDsaHashFamily::Shake => Self::Shake(ShakeTweakableHash::new(parameters.n)),
        }
    }

    /// Return the configured hash-output length in bytes.
    pub const fn output_bytes(self) -> usize {
        match self {
            Self::Sha2(hash) => hash.output_bytes(),
            Self::Shake(hash) => hash.output_bytes(),
        }
    }

    /// Evaluate the FIPS 205 pseudorandom function `PRF`.
    pub fn prf(
        self,
        public_seed: &[u8],
        secret_seed: &[u8],
        address: &Address,
        output: &mut [u8],
    ) -> Result<(), HashError> {
        match self {
            Self::Sha2(hash) => hash.prf(public_seed, secret_seed, address, output),
            Self::Shake(hash) => hash.prf(public_seed, secret_seed, address, output),
        }
    }

    /// Generate the FIPS 205 per-message randomization value `PRF_msg`.
    pub fn prf_msg(
        self,
        secret_prf: &[u8],
        optional_randomness: &[u8],
        message: &[u8],
        output: &mut [u8],
    ) -> Result<(), HashError> {
        match self {
            Self::Sha2(hash) => hash.prf_msg(secret_prf, optional_randomness, message, output),
            Self::Shake(hash) => hash.prf_msg(secret_prf, optional_randomness, message, output),
        }
    }

    /// Generate the FIPS 205 message digest `H_msg`.
    pub fn h_msg(
        self,
        randomizer: &[u8],
        public_seed: &[u8],
        public_root: &[u8],
        message: &[u8],
        output: &mut [u8],
    ) -> Result<(), HashError> {
        match self {
            Self::Sha2(hash) => hash.h_msg(randomizer, public_seed, public_root, message, output),
            Self::Shake(hash) => hash.h_msg(randomizer, public_seed, public_root, message, output),
        }
    }

    /// Evaluate the one-block FIPS 205 tweakable hash `F`.
    pub fn f(
        self,
        public_seed: &[u8],
        address: &Address,
        message: &[u8],
        output: &mut [u8],
    ) -> Result<(), HashError> {
        match self {
            Self::Sha2(hash) => hash.f(public_seed, address, message, output),
            Self::Shake(hash) => hash.f(public_seed, address, message, output),
        }
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
        match self {
            Self::Sha2(hash) => hash.h(public_seed, address, left, right, output),
            Self::Shake(hash) => hash.h(public_seed, address, left, right, output),
        }
    }

    /// Evaluate the variable-length FIPS 205 tweakable hash `T_l`.
    pub fn t_l(
        self,
        public_seed: &[u8],
        address: &Address,
        message: &[u8],
        output: &mut [u8],
    ) -> Result<(), HashError> {
        match self {
            Self::Sha2(hash) => hash.t_l(public_seed, address, message, output),
            Self::Shake(hash) => hash.t_l(public_seed, address, message, output),
        }
    }
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
        address.set_layer_address(3);
        address.set_tree_address(0x0102_0304_0506_0708);
        address.set_type_and_clear(AddressType::ForsTree);
        address.set_key_pair_address(9);
        address.set_tree_height(10);
        address.set_tree_index(11);
        address
    }

    #[test]
    fn every_parameter_set_selects_the_required_family_and_length() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let suite = HashSuite::new(&parameters);

            assert_eq!(suite.output_bytes(), parameters.n);

            match (parameters.hash_family, suite) {
                (SlhDsaHashFamily::Sha2, HashSuite::Sha2(hash)) => {
                    assert_eq!(hash.output_bytes(), parameters.n);
                }
                (SlhDsaHashFamily::Shake, HashSuite::Shake(hash)) => {
                    assert_eq!(hash.output_bytes(), parameters.n);
                }
                _ => panic!("hash suite did not match the parameter family"),
            }
        }
    }

    #[test]
    fn prf_dispatch_matches_concrete_implementations() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let suite = HashSuite::new(&parameters);
            let public_seed = [0x11_u8; 32];
            let secret_seed = [0x22_u8; 32];
            let address = test_address();
            let mut dispatched = [0_u8; 32];
            let mut direct = [0_u8; 32];

            suite
                .prf(
                    &public_seed[..parameters.n],
                    &secret_seed[..parameters.n],
                    &address,
                    &mut dispatched[..parameters.n],
                )
                .unwrap();

            match suite {
                HashSuite::Sha2(hash) => hash
                    .prf(
                        &public_seed[..parameters.n],
                        &secret_seed[..parameters.n],
                        &address,
                        &mut direct[..parameters.n],
                    )
                    .unwrap(),
                HashSuite::Shake(hash) => hash
                    .prf(
                        &public_seed[..parameters.n],
                        &secret_seed[..parameters.n],
                        &address,
                        &mut direct[..parameters.n],
                    )
                    .unwrap(),
            }

            assert_eq!(&dispatched[..parameters.n], &direct[..parameters.n]);
        }
    }

    #[test]
    fn f_dispatch_matches_concrete_implementations() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let suite = HashSuite::new(&parameters);
            let public_seed = [0x31_u8; 32];
            let message = [0x42_u8; 32];
            let address = test_address();
            let mut dispatched = [0_u8; 32];
            let mut direct = [0_u8; 32];

            suite
                .f(
                    &public_seed[..parameters.n],
                    &address,
                    &message[..parameters.n],
                    &mut dispatched[..parameters.n],
                )
                .unwrap();

            match suite {
                HashSuite::Sha2(hash) => hash
                    .f(
                        &public_seed[..parameters.n],
                        &address,
                        &message[..parameters.n],
                        &mut direct[..parameters.n],
                    )
                    .unwrap(),
                HashSuite::Shake(hash) => hash
                    .f(
                        &public_seed[..parameters.n],
                        &address,
                        &message[..parameters.n],
                        &mut direct[..parameters.n],
                    )
                    .unwrap(),
            }

            assert_eq!(&dispatched[..parameters.n], &direct[..parameters.n]);
        }
    }

    #[test]
    fn h_dispatch_matches_concrete_implementations() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let suite = HashSuite::new(&parameters);
            let public_seed = [0x51_u8; 32];
            let left = [0x62_u8; 32];
            let right = [0x73_u8; 32];
            let address = test_address();
            let mut dispatched = [0_u8; 32];
            let mut direct = [0_u8; 32];

            suite
                .h(
                    &public_seed[..parameters.n],
                    &address,
                    &left[..parameters.n],
                    &right[..parameters.n],
                    &mut dispatched[..parameters.n],
                )
                .unwrap();

            match suite {
                HashSuite::Sha2(hash) => hash
                    .h(
                        &public_seed[..parameters.n],
                        &address,
                        &left[..parameters.n],
                        &right[..parameters.n],
                        &mut direct[..parameters.n],
                    )
                    .unwrap(),
                HashSuite::Shake(hash) => hash
                    .h(
                        &public_seed[..parameters.n],
                        &address,
                        &left[..parameters.n],
                        &right[..parameters.n],
                        &mut direct[..parameters.n],
                    )
                    .unwrap(),
            }

            assert_eq!(&dispatched[..parameters.n], &direct[..parameters.n]);
        }
    }

    #[test]
    fn t_l_dispatch_matches_concrete_implementations() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let suite = HashSuite::new(&parameters);
            let public_seed = [0x81_u8; 32];
            let message = [0x92_u8; 96];
            let address = test_address();
            let mut dispatched = [0_u8; 32];
            let mut direct = [0_u8; 32];

            suite
                .t_l(
                    &public_seed[..parameters.n],
                    &address,
                    &message,
                    &mut dispatched[..parameters.n],
                )
                .unwrap();

            match suite {
                HashSuite::Sha2(hash) => hash
                    .t_l(
                        &public_seed[..parameters.n],
                        &address,
                        &message,
                        &mut direct[..parameters.n],
                    )
                    .unwrap(),
                HashSuite::Shake(hash) => hash
                    .t_l(
                        &public_seed[..parameters.n],
                        &address,
                        &message,
                        &mut direct[..parameters.n],
                    )
                    .unwrap(),
            }

            assert_eq!(&dispatched[..parameters.n], &direct[..parameters.n]);
        }
    }

    #[test]
    fn prf_msg_dispatch_matches_concrete_implementations() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let suite = HashSuite::new(&parameters);
            let secret_prf = [0xa1_u8; 32];
            let randomness = [0xb2_u8; 32];
            let message = b"parameter-driven PRF_msg dispatch";
            let mut dispatched = [0_u8; 32];
            let mut direct = [0_u8; 32];

            suite
                .prf_msg(
                    &secret_prf[..parameters.n],
                    &randomness[..parameters.n],
                    message,
                    &mut dispatched[..parameters.n],
                )
                .unwrap();

            match suite {
                HashSuite::Sha2(hash) => hash
                    .prf_msg(
                        &secret_prf[..parameters.n],
                        &randomness[..parameters.n],
                        message,
                        &mut direct[..parameters.n],
                    )
                    .unwrap(),
                HashSuite::Shake(hash) => hash
                    .prf_msg(
                        &secret_prf[..parameters.n],
                        &randomness[..parameters.n],
                        message,
                        &mut direct[..parameters.n],
                    )
                    .unwrap(),
            }

            assert_eq!(&dispatched[..parameters.n], &direct[..parameters.n]);
        }
    }

    #[test]
    fn h_msg_dispatch_matches_concrete_implementations() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let suite = HashSuite::new(&parameters);
            let randomizer = [0xc1_u8; 32];
            let public_seed = [0xd2_u8; 32];
            let public_root = [0xe3_u8; 32];
            let message = b"parameter-driven H_msg dispatch";
            let mut dispatched = [0_u8; 49];
            let mut direct = [0_u8; 49];

            suite
                .h_msg(
                    &randomizer[..parameters.n],
                    &public_seed[..parameters.n],
                    &public_root[..parameters.n],
                    message,
                    &mut dispatched[..parameters.m],
                )
                .unwrap();

            match suite {
                HashSuite::Sha2(hash) => hash
                    .h_msg(
                        &randomizer[..parameters.n],
                        &public_seed[..parameters.n],
                        &public_root[..parameters.n],
                        message,
                        &mut direct[..parameters.m],
                    )
                    .unwrap(),
                HashSuite::Shake(hash) => hash
                    .h_msg(
                        &randomizer[..parameters.n],
                        &public_seed[..parameters.n],
                        &public_root[..parameters.n],
                        message,
                        &mut direct[..parameters.m],
                    )
                    .unwrap(),
            }

            assert_eq!(&dispatched[..parameters.m], &direct[..parameters.m]);
        }
    }

    #[test]
    fn dispatch_preserves_hash_errors() {
        let parameters = SlhDsaParameterSet::Sha2_128s.parameters();
        let suite = HashSuite::new(&parameters);
        let address = Address::new();
        let public_seed = [0_u8; 15];
        let secret_seed = [0_u8; 16];
        let mut output = [0_u8; 16];

        assert_eq!(
            suite.prf(&public_seed, &secret_seed, &address, &mut output,),
            Err(HashError::InvalidInputLength {
                input: "public seed",
                expected: 16,
                actual: 15,
            })
        );
    }
}
