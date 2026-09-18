//! HashSLH-DSA prehash construction from FIPS 205.

use sha2::{Digest as Sha2Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256,
};

/// Prehash algorithms supported by HashSLH-DSA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlhDsaPreHash {
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

impl SlhDsaPreHash {
    /// Parse an ACVP hash identifier.
    #[cfg(feature = "internal-api")]
    pub fn from_acvp_name(name: &str) -> Option<Self> {
        match name {
            "SHA2-224" => Some(Self::Sha2_224),
            "SHA2-256" => Some(Self::Sha2_256),
            "SHA2-384" => Some(Self::Sha2_384),
            "SHA2-512" => Some(Self::Sha2_512),
            "SHA2-512/224" => Some(Self::Sha2_512_224),
            "SHA2-512/256" => Some(Self::Sha2_512_256),
            "SHA3-224" => Some(Self::Sha3_224),
            "SHA3-256" => Some(Self::Sha3_256),
            "SHA3-384" => Some(Self::Sha3_384),
            "SHA3-512" => Some(Self::Sha3_512),
            "SHAKE-128" => Some(Self::Shake128),
            "SHAKE-256" => Some(Self::Shake256),
            _ => None,
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

/// Construct the HashSLH-DSA external message
/// `0x01 || len(ctx) || ctx || DER(OID(PH)) || PH(M)`.
pub fn hash_message_prime(
    message: &[u8],
    context: &[u8],
    prehash: SlhDsaPreHash,
) -> Result<Vec<u8>, crate::SlhDsaError> {
    let context_length =
        u8::try_from(context.len()).map_err(|_| crate::SlhDsaError::ContextTooLong)?;

    let digest = prehash.digest(message);
    let oid = prehash.oid_der();

    let mut output = Vec::with_capacity(2 + context.len() + oid.len() + digest.len());
    output.push(0x01);
    output.push(context_length);
    output.extend_from_slice(context);
    output.extend_from_slice(&oid);
    output.extend_from_slice(&digest);

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_domain_separator_context_and_oid_are_correct() {
        let framed = hash_message_prime(b"message", b"ctx", SlhDsaPreHash::Sha2_256).unwrap();

        assert_eq!(&framed[..5], &[0x01, 3, b'c', b't', b'x']);
        assert_eq!(
            &framed[5..16],
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
        );
        assert_eq!(framed.len(), 2 + 3 + 11 + 32);
    }

    #[test]
    fn all_prehash_output_lengths_are_correct() {
        let cases = [
            (SlhDsaPreHash::Sha2_224, 28),
            (SlhDsaPreHash::Sha2_256, 32),
            (SlhDsaPreHash::Sha2_384, 48),
            (SlhDsaPreHash::Sha2_512, 64),
            (SlhDsaPreHash::Sha2_512_224, 28),
            (SlhDsaPreHash::Sha2_512_256, 32),
            (SlhDsaPreHash::Sha3_224, 28),
            (SlhDsaPreHash::Sha3_256, 32),
            (SlhDsaPreHash::Sha3_384, 48),
            (SlhDsaPreHash::Sha3_512, 64),
            (SlhDsaPreHash::Shake128, 32),
            (SlhDsaPreHash::Shake256, 64),
        ];

        for (prehash, digest_bytes) in cases {
            let framed = hash_message_prime(b"message", b"", prehash).unwrap();
            assert_eq!(framed.len(), 2 + 11 + digest_bytes);
        }
    }

    #[test]
    fn context_limit_is_strict() {
        assert_eq!(
            hash_message_prime(b"message", &[0_u8; 256], SlhDsaPreHash::Sha2_256),
            Err(crate::SlhDsaError::ContextTooLong)
        );
    }

    #[test]
    fn context_length_255_is_accepted() {
        assert!(hash_message_prime(b"message", &[0_u8; 255], SlhDsaPreHash::Sha2_256).is_ok());
    }
}
