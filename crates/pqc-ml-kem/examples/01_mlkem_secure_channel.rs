//! Illustrative ML-KEM secure-channel composition.
//!
//! This reference application demonstrates:
//!
//! - ML-KEM-768 key generation, encapsulation, and decapsulation;
//! - HKDF-SHA-256 key and nonce derivation;
//! - ChaCha20-Poly1305 authenticated encryption;
//! - associated-data binding;
//! - ciphertext tamper detection.
//!
//! This is an educational composition, not a standardized channel protocol.
//! Applications should normally use a reviewed protocol such as HPKE or TLS.

use core::fmt;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use pqc_core::PqcError;
use pqc_ml_kem::MlKem768;
use rand_core::OsRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;

const DOMAIN: &[u8] = b"pqc-rs/reference-app/ml-kem-secure-channel/v1";
const ASSOCIATED_DATA: &[u8] = b"channel=pqc-rs;version=1;role=sender-to-recipient";
const MESSAGE: &[u8] = b"post-quantum secure channel";

#[derive(Debug)]
enum ApplicationError {
    MlKem(PqcError),
    KeyDerivation,
    Encryption,
    Decryption,
    SharedSecretMismatch,
    TamperingAccepted,
}

impl From<PqcError> for ApplicationError {
    fn from(error: PqcError) -> Self {
        Self::MlKem(error)
    }
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MlKem(error) => write!(formatter, "ML-KEM operation failed: {error:?}"),
            Self::KeyDerivation => formatter.write_str("HKDF key derivation failed"),
            Self::Encryption => formatter.write_str("authenticated encryption failed"),
            Self::Decryption => formatter.write_str("authenticated decryption failed"),
            Self::SharedSecretMismatch => {
                formatter.write_str("encapsulation and decapsulation secrets differ")
            }
            Self::TamperingAccepted => {
                formatter.write_str("modified ciphertext was incorrectly accepted")
            }
        }
    }
}

impl std::error::Error for ApplicationError {}

fn derive_channel_material(
    shared_secret: &[u8],
    encapsulation: &[u8],
) -> Result<([u8; 32], [u8; 12]), ApplicationError> {
    let hkdf = Hkdf::<Sha256>::new(Some(DOMAIN), shared_secret);

    let mut context = Vec::with_capacity(DOMAIN.len() + encapsulation.len());
    context.extend_from_slice(DOMAIN);
    context.extend_from_slice(encapsulation);

    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];

    let mut key_info = context.clone();
    key_info.extend_from_slice(b"/key");

    let mut nonce_info = context;
    nonce_info.extend_from_slice(b"/nonce");

    hkdf.expand(&key_info, &mut key)
        .map_err(|_| ApplicationError::KeyDerivation)?;
    hkdf.expand(&nonce_info, &mut nonce)
        .map_err(|_| ApplicationError::KeyDerivation)?;

    Ok((key, nonce))
}

fn main() -> Result<(), ApplicationError> {
    // The recipient provisions an ML-KEM-768 key pair.
    let (recipient_public_key, recipient_secret_key) = MlKem768::keygen(&mut OsRng)?;

    // The sender encapsulates to the recipient's public key.
    let (encapsulation, sender_secret) = MlKem768::encaps(&recipient_public_key, &mut OsRng)?;

    // The recipient decapsulates the transmitted encapsulation.
    let recipient_secret = MlKem768::decaps(&recipient_secret_key, &encapsulation)?;

    if sender_secret.ct_eq(&recipient_secret).unwrap_u8() != 1 {
        return Err(ApplicationError::SharedSecretMismatch);
    }

    // Both peers independently derive identical channel keying material.
    // The encapsulation is included in the derivation context to bind the
    // symmetric channel state to this particular ML-KEM exchange.
    let (sender_key, sender_nonce) =
        derive_channel_material(sender_secret.as_bytes(), encapsulation.as_bytes())?;

    let (recipient_key, recipient_nonce) =
        derive_channel_material(recipient_secret.as_bytes(), encapsulation.as_bytes())?;

    if sender_key.ct_eq(&recipient_key).unwrap_u8() != 1
        || sender_nonce.ct_eq(&recipient_nonce).unwrap_u8() != 1
    {
        return Err(ApplicationError::SharedSecretMismatch);
    }

    let sender_cipher =
        ChaCha20Poly1305::new_from_slice(&sender_key).map_err(|_| ApplicationError::Encryption)?;

    let ciphertext = sender_cipher
        .encrypt(
            Nonce::from_slice(&sender_nonce),
            Payload {
                msg: MESSAGE,
                aad: ASSOCIATED_DATA,
            },
        )
        .map_err(|_| ApplicationError::Encryption)?;

    let recipient_cipher = ChaCha20Poly1305::new_from_slice(&recipient_key)
        .map_err(|_| ApplicationError::Decryption)?;

    let plaintext = recipient_cipher
        .decrypt(
            Nonce::from_slice(&recipient_nonce),
            Payload {
                msg: &ciphertext,
                aad: ASSOCIATED_DATA,
            },
        )
        .map_err(|_| ApplicationError::Decryption)?;

    assert_eq!(plaintext, MESSAGE);

    // Authenticated encryption must reject modified ciphertext.
    let mut modified = ciphertext.clone();
    let first = modified
        .first_mut()
        .ok_or(ApplicationError::TamperingAccepted)?;
    *first ^= 0x01;

    if recipient_cipher
        .decrypt(
            Nonce::from_slice(&recipient_nonce),
            Payload {
                msg: &modified,
                aad: ASSOCIATED_DATA,
            },
        )
        .is_ok()
    {
        return Err(ApplicationError::TamperingAccepted);
    }

    println!("ML-KEM-768 secure-channel reference application");
    println!(
        "encapsulation: {} bytes; encrypted payload: {} bytes",
        encapsulation.as_bytes().len(),
        ciphertext.len()
    );
    println!("authenticated decryption: pass");
    println!("ciphertext tamper detection: pass");

    Ok(())
}
