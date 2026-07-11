#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! ML-KEM API and implementation scaffold.
//!
//! Stage 6.3 adds opt-in normative KeyGen tracing while the verified ML-KEM
//! arithmetic and public APIs remain unchanged.

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
pub mod ml_kem_encaps;
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
    CiphertextBytes, Kem, PqcResult, PublicKeyBytes, SecretKeyBytes, SharedSecretBytes,
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

macro_rules! impl_ml_kem_scaffold {
    ($scheme:ident, $param:expr, $pk:ty, $sk:ty, $ct:ty, $pk_len:expr, $sk_len:expr, $ct_len:expr) => {
        impl $scheme {
            /// Parameter set.
            pub const PARAMETER_SET: MlKemParameterSet = $param;

            /// Generate a key pair.
            pub fn keygen<R>(rng: &mut R) -> PqcResult<($pk, $sk)>
            where
                R: CryptoRng + RngCore,
            {
                <Self as Kem>::keygen(rng)
            }

            /// Encapsulate to a public key.
            pub fn encaps<R>(public_key: &$pk, rng: &mut R) -> PqcResult<($ct, MlKemSharedSecret)>
            where
                R: CryptoRng + RngCore,
            {
                <Self as Kem>::encaps(public_key, rng)
            }

            /// Decapsulate a ciphertext.
            pub fn decaps(secret_key: &$sk, ciphertext: &$ct) -> PqcResult<MlKemSharedSecret> {
                <Self as Kem>::decaps(secret_key, ciphertext)
            }
        }

        impl Kem for $scheme {
            type PublicKey = $pk;
            type SecretKey = $sk;
            type Ciphertext = $ct;
            type SharedSecret = MlKemSharedSecret;

            fn keygen<R>(rng: &mut R) -> PqcResult<(Self::PublicKey, Self::SecretKey)>
            where
                R: CryptoRng + RngCore,
            {
                let mut public_key = [0u8; $pk_len];
                let mut secret_key = [0u8; $sk_len];

                rng.fill_bytes(&mut public_key);
                rng.fill_bytes(&mut secret_key);

                let copy_len = core::cmp::min($pk_len, $sk_len);
                secret_key[..copy_len].copy_from_slice(&public_key[..copy_len]);

                Ok((
                    PublicKeyBytes::new(public_key),
                    SecretKeyBytes::new(secret_key),
                ))
            }

            fn encaps<R>(
                public_key: &Self::PublicKey,
                rng: &mut R,
            ) -> PqcResult<(Self::Ciphertext, Self::SharedSecret)>
            where
                R: CryptoRng + RngCore,
            {
                let mut ciphertext = [0u8; $ct_len];
                rng.fill_bytes(&mut ciphertext);

                let shared_secret =
                    placeholder_shared_secret($param.name(), public_key.as_bytes(), &ciphertext);

                Ok((CiphertextBytes::new(ciphertext), shared_secret))
            }

            fn decaps(
                secret_key: &Self::SecretKey,
                ciphertext: &Self::Ciphertext,
            ) -> PqcResult<Self::SharedSecret> {
                let public_key_bytes = &secret_key.as_bytes()[..$pk_len];
                Ok(placeholder_shared_secret(
                    $param.name(),
                    public_key_bytes,
                    ciphertext.as_bytes(),
                ))
            }
        }
    };
}

impl_ml_kem_scaffold!(
    MlKem512,
    MlKemParameterSet::MlKem512,
    MlKem512PublicKey,
    MlKem512SecretKey,
    MlKem512Ciphertext,
    ML_KEM_512_PUBLIC_KEY_BYTES,
    ML_KEM_512_SECRET_KEY_BYTES,
    ML_KEM_512_CIPHERTEXT_BYTES
);

impl_ml_kem_scaffold!(
    MlKem768,
    MlKemParameterSet::MlKem768,
    MlKem768PublicKey,
    MlKem768SecretKey,
    MlKem768Ciphertext,
    ML_KEM_768_PUBLIC_KEY_BYTES,
    ML_KEM_768_SECRET_KEY_BYTES,
    ML_KEM_768_CIPHERTEXT_BYTES
);

impl_ml_kem_scaffold!(
    MlKem1024,
    MlKemParameterSet::MlKem1024,
    MlKem1024PublicKey,
    MlKem1024SecretKey,
    MlKem1024Ciphertext,
    ML_KEM_1024_PUBLIC_KEY_BYTES,
    ML_KEM_1024_SECRET_KEY_BYTES,
    ML_KEM_1024_CIPHERTEXT_BYTES
);

fn placeholder_shared_secret(
    parameter_name: &str,
    public_key: &[u8],
    ciphertext: &[u8],
) -> MlKemSharedSecret {
    let mut input = [0u8; 64];
    let domain = symmetric::h(b"pqc-rfc9958-rs stage6_1 ml-kem scaffold");
    input[..32].copy_from_slice(&domain);

    let pk_hash = symmetric::h(public_key);
    let ct_hash = symmetric::h(ciphertext);

    let mut i = 0;
    while i < 32 {
        input[32 + i] =
            pk_hash[i] ^ ct_hash[i] ^ parameter_name.as_bytes()[i % parameter_name.len()];
        i += 1;
    }

    let digest = symmetric::h(&input);
    SharedSecretBytes::new(digest)
}

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
    fn ml_kem_512_round_trip_scaffold() {
        let mut rng = OsRng;
        let (pk, sk) = MlKem512::keygen(&mut rng).unwrap();
        let (ct, ss1) = MlKem512::encaps(&pk, &mut rng).unwrap();
        let ss2 = MlKem512::decaps(&sk, &ct).unwrap();
        assert_eq!(ss1.ct_eq(&ss2).unwrap_u8(), 1);
    }

    #[test]
    fn ml_kem_768_round_trip_scaffold() {
        let mut rng = OsRng;
        let (pk, sk) = MlKem768::keygen(&mut rng).unwrap();
        let (ct, ss1) = MlKem768::encaps(&pk, &mut rng).unwrap();
        let ss2 = MlKem768::decaps(&sk, &ct).unwrap();
        assert_eq!(ss1.ct_eq(&ss2).unwrap_u8(), 1);
    }

    #[test]
    fn ml_kem_1024_round_trip_scaffold() {
        let mut rng = OsRng;
        let (pk, sk) = MlKem1024::keygen(&mut rng).unwrap();
        let (ct, ss1) = MlKem1024::encaps(&pk, &mut rng).unwrap();
        let ss2 = MlKem1024::decaps(&sk, &ct).unwrap();
        assert_eq!(ss1.ct_eq(&ss2).unwrap_u8(), 1);
    }
}
