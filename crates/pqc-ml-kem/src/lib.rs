#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Typed public API and FIPS 203 ML-KEM implementation.
//!
//! The public API delegates to the validated key-generation,
//! encapsulation, and decapsulation implementation.

extern crate alloc;

pub mod arithmetic;
pub mod conformance;
pub mod encoding;
pub mod fips_ntt;
pub mod intermediate_values;
pub mod kpke;
pub mod kpke_arithmetic;
pub mod kpke_decrypt;
pub mod kpke_encrypt;
pub mod kpke_keygen;
pub mod kpke_ntt_domain;
pub mod kpke_structural;
pub mod matrix;
pub mod ml_kem_decaps;
pub mod ml_kem_encaps;
pub mod ml_kem_key_check;
pub mod ml_kem_keygen;
#[cfg(feature = "std")]
pub mod ml_kem_trace;
pub mod ntt;
pub mod packing;
pub mod poly;
pub mod polyvec;
pub mod sampling;
pub mod symmetric;
pub mod zetas;

use pqc_core::{
    CiphertextBytes, Kem, PqcError, PqcResult, PublicKeyBytes, SecretKeyBytes, SharedSecretBytes,
};
use rand_core::{CryptoRng, RngCore};

/// ML-KEM shared-secret size in bytes.
pub const SHARED_SECRET_BYTES: usize = 32;

/// ML-KEM-512 public-key size.
pub const ML_KEM_512_PUBLIC_KEY_BYTES: usize = 800;
/// ML-KEM-512 secret-key size.
pub const ML_KEM_512_SECRET_KEY_BYTES: usize = 1632;
/// ML-KEM-512 ciphertext size.
pub const ML_KEM_512_CIPHERTEXT_BYTES: usize = 768;

/// ML-KEM-768 public-key size.
pub const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1184;
/// ML-KEM-768 secret-key size.
pub const ML_KEM_768_SECRET_KEY_BYTES: usize = 2400;
/// ML-KEM-768 ciphertext size.
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;

/// ML-KEM-1024 public-key size.
pub const ML_KEM_1024_PUBLIC_KEY_BYTES: usize = 1568;
/// ML-KEM-1024 secret-key size.
pub const ML_KEM_1024_SECRET_KEY_BYTES: usize = 3168;
/// ML-KEM-1024 ciphertext size.
pub const ML_KEM_1024_CIPHERTEXT_BYTES: usize = 1568;

/// ML-KEM shared secret.
pub type MlKemSharedSecret = SharedSecretBytes<SHARED_SECRET_BYTES>;

/// ML-KEM parameter set identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlKemParameterSet {
    /// ML-KEM-512.
    MlKem512,
    /// ML-KEM-768.
    MlKem768,
    /// ML-KEM-1024.
    MlKem1024,
}

impl MlKemParameterSet {
    /// Return the parameter-set name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// Return the ML-KEM module rank `k`.
    pub const fn k(self) -> usize {
        match self {
            Self::MlKem512 => 2,
            Self::MlKem768 => 3,
            Self::MlKem1024 => 4,
        }
    }

    /// Return `eta1`.
    pub const fn eta1(self) -> usize {
        match self {
            Self::MlKem512 => 3,
            Self::MlKem768 => 2,
            Self::MlKem1024 => 2,
        }
    }

    /// Return `eta2`.
    pub const fn eta2(self) -> usize {
        2
    }

    /// Return `du`, the compression width for the `u` ciphertext vector.
    pub const fn du(self) -> u32 {
        match self {
            Self::MlKem512 => 10,
            Self::MlKem768 => 10,
            Self::MlKem1024 => 11,
        }
    }

    /// Return `dv`, the compression width for the `v` ciphertext polynomial.
    pub const fn dv(self) -> u32 {
        match self {
            Self::MlKem512 => 4,
            Self::MlKem768 => 4,
            Self::MlKem1024 => 5,
        }
    }

    /// Return the public-key byte length.
    pub const fn public_key_bytes(self) -> usize {
        match self {
            Self::MlKem512 => ML_KEM_512_PUBLIC_KEY_BYTES,
            Self::MlKem768 => ML_KEM_768_PUBLIC_KEY_BYTES,
            Self::MlKem1024 => ML_KEM_1024_PUBLIC_KEY_BYTES,
        }
    }

    /// Return the secret-key byte length.
    pub const fn secret_key_bytes(self) -> usize {
        match self {
            Self::MlKem512 => ML_KEM_512_SECRET_KEY_BYTES,
            Self::MlKem768 => ML_KEM_768_SECRET_KEY_BYTES,
            Self::MlKem1024 => ML_KEM_1024_SECRET_KEY_BYTES,
        }
    }

    /// Return the ciphertext byte length.
    pub const fn ciphertext_bytes(self) -> usize {
        match self {
            Self::MlKem512 => ML_KEM_512_CIPHERTEXT_BYTES,
            Self::MlKem768 => ML_KEM_768_CIPHERTEXT_BYTES,
            Self::MlKem1024 => ML_KEM_1024_CIPHERTEXT_BYTES,
        }
    }
}

/// ML-KEM-512 implementation marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlKem512;

/// ML-KEM-768 implementation marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlKem768;

/// ML-KEM-1024 implementation marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlKem1024;

/// ML-KEM-512 public key.
pub type MlKem512PublicKey = PublicKeyBytes<ML_KEM_512_PUBLIC_KEY_BYTES>;
/// ML-KEM-512 secret key.
pub type MlKem512SecretKey = SecretKeyBytes<ML_KEM_512_SECRET_KEY_BYTES>;
/// ML-KEM-512 ciphertext.
pub type MlKem512Ciphertext = CiphertextBytes<ML_KEM_512_CIPHERTEXT_BYTES>;

/// ML-KEM-768 public key.
pub type MlKem768PublicKey = PublicKeyBytes<ML_KEM_768_PUBLIC_KEY_BYTES>;
/// ML-KEM-768 secret key.
pub type MlKem768SecretKey = SecretKeyBytes<ML_KEM_768_SECRET_KEY_BYTES>;
/// ML-KEM-768 ciphertext.
pub type MlKem768Ciphertext = CiphertextBytes<ML_KEM_768_CIPHERTEXT_BYTES>;

/// ML-KEM-1024 public key.
pub type MlKem1024PublicKey = PublicKeyBytes<ML_KEM_1024_PUBLIC_KEY_BYTES>;
/// ML-KEM-1024 secret key.
pub type MlKem1024SecretKey = SecretKeyBytes<ML_KEM_1024_SECRET_KEY_BYTES>;
/// ML-KEM-1024 ciphertext.
pub type MlKem1024Ciphertext = CiphertextBytes<ML_KEM_1024_CIPHERTEXT_BYTES>;

macro_rules! impl_ml_kem {
    (
        $scheme:ident,
        $parameter_set:expr,
        $keygen:path,
        $public_key:ty,
        $secret_key:ty,
        $ciphertext:ty,
        $ciphertext_bytes:expr
    ) => {
        impl $scheme {
            /// Parameter set.
            pub const PARAMETER_SET: MlKemParameterSet = $parameter_set;

            /// Generate a FIPS 203 ML-KEM key pair.
            pub fn keygen<R>(rng: &mut R) -> PqcResult<($public_key, $secret_key)>
            where
                R: CryptoRng + RngCore,
            {
                <Self as Kem>::keygen(rng)
            }

            /// Encapsulate to a public key.
            pub fn encaps<R>(
                public_key: &$public_key,
                rng: &mut R,
            ) -> PqcResult<($ciphertext, MlKemSharedSecret)>
            where
                R: CryptoRng + RngCore,
            {
                <Self as Kem>::encaps(public_key, rng)
            }

            /// Decapsulate a ciphertext.
            pub fn decaps(
                secret_key: &$secret_key,
                ciphertext: &$ciphertext,
            ) -> PqcResult<MlKemSharedSecret> {
                <Self as Kem>::decaps(secret_key, ciphertext)
            }
        }

        impl Kem for $scheme {
            type PublicKey = $public_key;
            type SecretKey = $secret_key;
            type Ciphertext = $ciphertext;
            type SharedSecret = MlKemSharedSecret;

            fn keygen<R>(rng: &mut R) -> PqcResult<(Self::PublicKey, Self::SecretKey)>
            where
                R: CryptoRng + RngCore,
            {
                let mut d = [0u8; 32];
                let mut z = [0u8; 32];

                rng.fill_bytes(&mut d);
                rng.fill_bytes(&mut z);

                let output = $keygen(&d, &z)?;

                Ok((
                    PublicKeyBytes::new(output.encapsulation_key),
                    SecretKeyBytes::new(output.decapsulation_key),
                ))
            }

            fn encaps<R>(
                public_key: &Self::PublicKey,
                rng: &mut R,
            ) -> PqcResult<(Self::Ciphertext, Self::SharedSecret)>
            where
                R: CryptoRng + RngCore,
            {
                let mut m = [0u8; 32];
                rng.fill_bytes(&mut m);

                let output = crate::ml_kem_encaps::encaps_internal(
                    $parameter_set,
                    public_key.as_bytes(),
                    &m,
                )?;

                let actual = output.ciphertext.len();
                let ciphertext =
                    output
                        .ciphertext
                        .try_into()
                        .map_err(|_| PqcError::InvalidLength {
                            expected: $ciphertext_bytes,
                            actual,
                        })?;

                Ok((CiphertextBytes::new(ciphertext), output.shared_secret))
            }

            fn decaps(
                secret_key: &Self::SecretKey,
                ciphertext: &Self::Ciphertext,
            ) -> PqcResult<Self::SharedSecret> {
                let output = crate::ml_kem_decaps::decaps_internal(
                    $parameter_set,
                    secret_key.as_bytes(),
                    ciphertext.as_bytes(),
                )?;

                Ok(output.shared_secret)
            }
        }
    };
}

impl_ml_kem!(
    MlKem512,
    MlKemParameterSet::MlKem512,
    crate::ml_kem_keygen::ml_kem_512_keygen_internal,
    MlKem512PublicKey,
    MlKem512SecretKey,
    MlKem512Ciphertext,
    ML_KEM_512_CIPHERTEXT_BYTES
);

impl_ml_kem!(
    MlKem768,
    MlKemParameterSet::MlKem768,
    crate::ml_kem_keygen::ml_kem_768_keygen_internal,
    MlKem768PublicKey,
    MlKem768SecretKey,
    MlKem768Ciphertext,
    ML_KEM_768_CIPHERTEXT_BYTES
);

impl_ml_kem!(
    MlKem1024,
    MlKemParameterSet::MlKem1024,
    crate::ml_kem_keygen::ml_kem_1024_keygen_internal,
    MlKem1024PublicKey,
    MlKem1024SecretKey,
    MlKem1024Ciphertext,
    ML_KEM_1024_CIPHERTEXT_BYTES
);

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use subtle::ConstantTimeEq;

    #[test]
    fn parameter_sizes_are_exposed() {
        assert_eq!(MlKemParameterSet::MlKem512.public_key_bytes(), 800);
        assert_eq!(MlKemParameterSet::MlKem768.ciphertext_bytes(), 1088);
        assert_eq!(MlKemParameterSet::MlKem1024.secret_key_bytes(), 3168);
    }

    #[test]
    fn parameter_algorithm_values_are_exposed() {
        assert_eq!(MlKemParameterSet::MlKem512.k(), 2);
        assert_eq!(MlKemParameterSet::MlKem768.k(), 3);
        assert_eq!(MlKemParameterSet::MlKem1024.k(), 4);
        assert_eq!(MlKemParameterSet::MlKem512.eta1(), 3);
        assert_eq!(MlKemParameterSet::MlKem768.eta1(), 2);
        assert_eq!(MlKemParameterSet::MlKem1024.du(), 11);
        assert_eq!(MlKemParameterSet::MlKem1024.dv(), 5);
    }

    #[test]
    fn ml_kem_512_public_api_round_trip() {
        let mut rng = OsRng;
        let (pk, sk) = MlKem512::keygen(&mut rng).unwrap();
        let (ct, ss1) = MlKem512::encaps(&pk, &mut rng).unwrap();
        let ss2 = MlKem512::decaps(&sk, &ct).unwrap();
        assert_eq!(ss1.ct_eq(&ss2).unwrap_u8(), 1);
    }

    #[test]
    fn ml_kem_768_public_api_round_trip() {
        let mut rng = OsRng;
        let (pk, sk) = MlKem768::keygen(&mut rng).unwrap();
        let (ct, ss1) = MlKem768::encaps(&pk, &mut rng).unwrap();
        let ss2 = MlKem768::decaps(&sk, &ct).unwrap();
        assert_eq!(ss1.ct_eq(&ss2).unwrap_u8(), 1);
    }

    #[test]
    fn ml_kem_1024_public_api_round_trip() {
        let mut rng = OsRng;
        let (pk, sk) = MlKem1024::keygen(&mut rng).unwrap();
        let (ct, ss1) = MlKem1024::encaps(&pk, &mut rng).unwrap();
        let ss2 = MlKem1024::decaps(&sk, &ct).unwrap();
        assert_eq!(ss1.ct_eq(&ss2).unwrap_u8(), 1);
    }
}
