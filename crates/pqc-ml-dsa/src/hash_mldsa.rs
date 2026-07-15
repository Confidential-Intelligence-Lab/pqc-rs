//! HashML-DSA prehash construction from FIPS 204.

use sha2::{Digest as Sha2Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256,
};

use crate::params::MlDsaParameterSet;
use crate::signature::{sign_internal_message, SignatureError};
use crate::signing::SIGNING_RANDOMNESS_BYTES;
use crate::verification::{verify_internal_message, VerificationError};

/// Approved prehash algorithms supported by ACVP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreHashAlgorithm {
    /// SHA2-224.
    Sha2_224,
    /// SHA2-256.
    Sha2_256,
    /// SHA2-384.
    Sha2_384,
    /// SHA2-512.
    Sha2_512,
    /// SHA2-512/224.
    Sha2_512_224,
    /// SHA2-512/256.
    Sha2_512_256,
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// SHAKE-128 with 256-bit output.
    Shake128,
    /// SHAKE-256 with 512-bit output.
    Shake256,
}

/// HashML-DSA construction error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashMlDsaError {
    /// Context exceeds 255 bytes.
    ContextTooLong,
    /// Hash identifier is unsupported.
    UnsupportedHashAlgorithm,
    /// Signature generation failed.
    Signing,
    /// Signature verification failed.
    Verification,
}

impl PreHashAlgorithm {
    /// Parse an ACVP hash identifier.
    pub fn from_acvp_name(name: &str) -> Result<Self, HashMlDsaError> {
        match name {
            "SHA2-224" => Ok(Self::Sha2_224),
            "SHA2-256" => Ok(Self::Sha2_256),
            "SHA2-384" => Ok(Self::Sha2_384),
            "SHA2-512" => Ok(Self::Sha2_512),
            "SHA2-512/224" => Ok(Self::Sha2_512_224),
            "SHA2-512/256" => Ok(Self::Sha2_512_256),
            "SHA3-224" => Ok(Self::Sha3_224),
            "SHA3-256" => Ok(Self::Sha3_256),
            "SHA3-384" => Ok(Self::Sha3_384),
            "SHA3-512" => Ok(Self::Sha3_512),
            "SHAKE-128" => Ok(Self::Shake128),
            "SHAKE-256" => Ok(Self::Shake256),
            _ => Err(HashMlDsaError::UnsupportedHashAlgorithm),
        }
    }

    fn oid_der(self) -> [u8; 11] {
        let final_arc = match self {
            Self::Sha2_256 => 1,
            Self::Sha2_384 => 2,
            Self::Sha2_512 => 3,
            Self::Sha2_224 => 4,
            Self::Sha2_512_224 => 5,
            Self::Sha2_512_256 => 6,
            Self::Sha3_224 => 7,
            Self::Sha3_256 => 8,
            Self::Sha3_384 => 9,
            Self::Sha3_512 => 10,
            Self::Shake128 => 11,
            Self::Shake256 => 12,
        };

        [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, final_arc,
        ]
    }

    fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha2_224 => Sha224::digest(message).to_vec(),
            Self::Sha2_256 => Sha256::digest(message).to_vec(),
            Self::Sha2_384 => Sha384::digest(message).to_vec(),
            Self::Sha2_512 => Sha512::digest(message).to_vec(),
            Self::Sha2_512_224 => Sha512_224::digest(message).to_vec(),
            Self::Sha2_512_256 => Sha512_256::digest(message).to_vec(),
            Self::Sha3_224 => Sha3_224::digest(message).to_vec(),
            Self::Sha3_256 => Sha3_256::digest(message).to_vec(),
            Self::Sha3_384 => Sha3_384::digest(message).to_vec(),
            Self::Sha3_512 => Sha3_512::digest(message).to_vec(),
            Self::Shake128 => {
                let mut hasher = Shake128::default();
                hasher.update(message);
                let mut reader = hasher.finalize_xof();
                let mut output = vec![0_u8; 32];
                reader.read(&mut output);
                output
            }
            Self::Shake256 => {
                let mut hasher = Shake256::default();
                hasher.update(message);
                let mut reader = hasher.finalize_xof();
                let mut output = vec![0_u8; 64];
                reader.read(&mut output);
                output
            }
        }
    }
}

/// Construct `M' = 0x01 || len(ctx) || ctx || DER(OID(PH)) || PH(M)`.
pub fn hash_message_prime(
    message: &[u8],
    context: &[u8],
    algorithm: PreHashAlgorithm,
) -> Result<Vec<u8>, HashMlDsaError> {
    let context_length = u8::try_from(context.len()).map_err(|_| HashMlDsaError::ContextTooLong)?;
    let digest = algorithm.digest(message);
    let oid = algorithm.oid_der();

    let mut output = Vec::with_capacity(2 + context.len() + oid.len() + digest.len());
    output.push(1);
    output.push(context_length);
    output.extend_from_slice(context);
    output.extend_from_slice(&oid);
    output.extend_from_slice(&digest);
    Ok(output)
}

/// Generate a HashML-DSA signature.
pub fn hash_sign(
    parameter_set: MlDsaParameterSet,
    private_key: &[u8],
    message: &[u8],
    context: &[u8],
    algorithm: PreHashAlgorithm,
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
) -> Result<Vec<u8>, HashMlDsaError> {
    let message_prime = hash_message_prime(message, context, algorithm)?;
    sign_internal_message(parameter_set, private_key, &message_prime, randomness)
        .map_err(|_: SignatureError| HashMlDsaError::Signing)
}

/// Verify a HashML-DSA signature.
pub fn hash_verify(
    parameter_set: MlDsaParameterSet,
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    algorithm: PreHashAlgorithm,
    signature: &[u8],
) -> Result<bool, HashMlDsaError> {
    let message_prime = hash_message_prime(message, context, algorithm)?;
    verify_internal_message(parameter_set, public_key, &message_prime, signature)
        .map_err(|_: VerificationError| HashMlDsaError::Verification)
}
