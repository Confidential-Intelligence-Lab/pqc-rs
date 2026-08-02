//! ML-DSA document-signing reference application.
//!
//! This example demonstrates:
//!
//! - ML-DSA-65 key generation;
//! - hedged Pure ML-DSA signing;
//! - context-bound document verification;
//! - rejection of a modified document;
//! - rejection of a modified signature.
//!
//! The example models an application that distributes a document together
//! with its detached signature. It does not define a serialization or
//! transport protocol.

use pqc_ml_dsa::{MlDsa, MlDsaError, MlDsaParameterSet, MlDsaPublicKey, MlDsaSignature};
use rand_core::OsRng;

const SIGNATURE_CONTEXT: &[u8] = b"pqc-rs/document-signing/v1";
const DOCUMENT_NAME: &str = "research-release.txt";
const DOCUMENT_CONTENTS: &[u8] = br#"PQC-rs reference release

This document demonstrates context-bound ML-DSA authentication.
"#;

struct SignedDocument {
    name: String,
    contents: Vec<u8>,
    signature: MlDsaSignature,
}

impl SignedDocument {
    fn verify(
        &self,
        implementation: &MlDsa,
        public_key: &MlDsaPublicKey,
    ) -> Result<bool, MlDsaError> {
        implementation.verify(
            public_key,
            &self.contents,
            SIGNATURE_CONTEXT,
            &self.signature,
        )
    }
}

fn main() -> Result<(), MlDsaError> {
    let implementation = MlDsa::new(MlDsaParameterSet::MlDsa65);

    // The document publisher provisions a fresh signing key pair.
    let key_pair = implementation.keygen(&mut OsRng)?;

    // Hedged signing combines the private key and message with fresh
    // randomness, providing protection if either source alone is imperfect.
    let signature = implementation.sign_hedged(
        key_pair.private_key(),
        DOCUMENT_CONTENTS,
        SIGNATURE_CONTEXT,
        &mut OsRng,
    )?;

    let signed_document = SignedDocument {
        name: DOCUMENT_NAME.to_owned(),
        contents: DOCUMENT_CONTENTS.to_vec(),
        signature,
    };

    // A recipient authenticates the exact document bytes and context.
    if !signed_document.verify(&implementation, key_pair.public_key())? {
        return Err(MlDsaError::InternalError);
    }

    // A modified document must not verify under the original signature.
    let mut modified_document = signed_document.contents.clone();
    let first = modified_document
        .first_mut()
        .ok_or(MlDsaError::InternalError)?;
    *first ^= 0x01;

    if implementation.verify(
        key_pair.public_key(),
        &modified_document,
        SIGNATURE_CONTEXT,
        &signed_document.signature,
    )? {
        return Err(MlDsaError::InternalError);
    }

    // A modified signature should either fail strict decoding or verify as
    // invalid. Both outcomes represent correct rejection.
    let mut modified_signature_bytes = signed_document.signature.as_bytes().to_vec();
    let last = modified_signature_bytes
        .last_mut()
        .ok_or(MlDsaError::InternalError)?;
    *last ^= 0x01;

    let modified_signature_rejected =
        match MlDsaSignature::from_bytes(MlDsaParameterSet::MlDsa65, &modified_signature_bytes) {
            Ok(modified_signature) => !implementation.verify(
                key_pair.public_key(),
                &signed_document.contents,
                SIGNATURE_CONTEXT,
                &modified_signature,
            )?,
            Err(MlDsaError::InvalidSignature) => true,
            Err(error) => return Err(error),
        };

    if !modified_signature_rejected {
        return Err(MlDsaError::InternalError);
    }

    println!("ML-DSA-65 document-signing reference application");
    println!("document: {}", signed_document.name);
    println!(
        "public key: {} bytes; signature: {} bytes",
        key_pair.public_key().as_bytes().len(),
        signed_document.signature.as_bytes().len(),
    );
    println!("original document verification: pass");
    println!("modified document rejection: pass");
    println!("modified signature rejection: pass");

    Ok(())
}
