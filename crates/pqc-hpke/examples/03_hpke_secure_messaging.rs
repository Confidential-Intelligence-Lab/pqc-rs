//! HPKE secure-messaging reference application.
//!
//! This example demonstrates:
//!
//! - ML-KEM-768 recipient key generation;
//! - validated HPKE ciphersuite selection;
//! - randomized Base-mode sender setup;
//! - receiver context reconstruction from the transmitted encapsulation;
//! - authenticated encryption of multiple ordered messages;
//! - associated-data binding;
//! - rejection of a modified ciphertext without advancing receiver state.

use std::error::Error;

use pqc_hpke::{
    setup_base_receiver_with_suite, setup_base_sender_with_suite, AeadId, HpkeSuite, KdfId,
    MlKemHpke,
};
use rand_core::OsRng;

const INFO: &[u8] = b"pqc-rs/reference-app/hpke-secure-messaging/v1";
const ASSOCIATED_DATA: &[u8] = b"channel=pqc-rs;version=1;direction=sender-to-recipient";

fn main() -> Result<(), Box<dyn Error>> {
    let kem = MlKemHpke::MlKem768;
    let suite = HpkeSuite::new(kem, KdfId::HKDF_SHA256, AeadId::CHACHA20_POLY1305)?;

    // The recipient provisions a fresh post-quantum HPKE key pair.
    let recipient = kem.generate_key_pair(&mut OsRng)?;

    // The sender creates an HPKE Base-mode context and an encapsulated key
    // that must be transmitted to the recipient with the ciphertexts.
    let sender = setup_base_sender_with_suite(kem, suite, &recipient.public_key, INFO, &mut OsRng)?;

    let encapsulated_key = sender.encapsulated_key;
    let mut sender_context = sender.context;

    // The recipient reconstructs the matching stateful context using its
    // private key, the transmitted encapsulation, and the same application
    // information string.
    let mut receiver_context = setup_base_receiver_with_suite(
        kem,
        suite,
        recipient.private_key_seed.as_bytes(),
        &encapsulated_key,
        INFO,
    )?;

    let messages: [&[u8]; 2] = [
        b"first authenticated HPKE message",
        b"second authenticated HPKE message",
    ];

    for message in messages {
        let ciphertext = sender_context.seal(ASSOCIATED_DATA, message)?;
        let plaintext = receiver_context.open(ASSOCIATED_DATA, &ciphertext)?;
        assert_eq!(plaintext, message);
    }

    // A failed authenticated decryption must not consume the receiver's
    // sequence number. This allows the original ciphertext to be retried.
    let final_message = b"tamper-evident HPKE message";
    let ciphertext = sender_context.seal(ASSOCIATED_DATA, final_message)?;
    let mut modified = ciphertext.clone();
    let first = modified
        .first_mut()
        .ok_or("HPKE produced an empty ciphertext")?;
    *first ^= 0x01;

    let sequence_before_failure = receiver_context.sequence_number();
    assert!(receiver_context.open(ASSOCIATED_DATA, &modified).is_err());
    assert_eq!(receiver_context.sequence_number(), sequence_before_failure,);

    let recovered = receiver_context.open(ASSOCIATED_DATA, &ciphertext)?;
    assert_eq!(recovered, final_message);

    assert_eq!(
        sender_context.sequence_number(),
        receiver_context.sequence_number(),
    );

    println!("HPKE secure-messaging reference application");
    println!("KEM: ML-KEM-768");
    println!("KDF: HKDF-SHA-256");
    println!("AEAD: ChaCha20-Poly1305");
    println!("encapsulation: {} bytes", encapsulated_key.len());
    println!("authenticated messages recovered: 3");
    println!("modified ciphertext rejection: pass");
    println!("receiver state preserved after failed open: pass");

    Ok(())
}
