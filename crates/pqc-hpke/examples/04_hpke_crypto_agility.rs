//! HPKE cryptographic-agility reference application.
//!
//! This example demonstrates:
//!
//! - configuration-driven KEM, KDF, and AEAD selection;
//! - one unchanged messaging workflow across multiple policies;
//! - randomized recipient key generation and Base-mode setup;
//! - authenticated encryption and decryption;
//! - policy separation from application logic.
//!
//! Both protocol participants execute in one process. In-memory values stand
//! in for serialized messages transported between separate applications.

use std::error::Error;

use pqc_hpke::{
    setup_base_receiver_with_suite, setup_base_sender_with_suite, AeadId, HpkeSuite, KdfId,
    MlKemHpke,
};
use rand_core::OsRng;

const INFO: &[u8] = b"pqc-rs/reference-app/hpke-crypto-agility/v1";
const ASSOCIATED_DATA: &[u8] = b"application=pqc-rs;purpose=agility-demo";
const MESSAGE: &[u8] = b"the application workflow is independent of cryptographic policy";

#[derive(Clone, Copy)]
struct CryptoPolicy {
    name: &'static str,
    kem: MlKemHpke,
    kdf: KdfId,
    aead: AeadId,
}

const POLICIES: [CryptoPolicy; 3] = [
    CryptoPolicy {
        name: "compact",
        kem: MlKemHpke::MlKem512,
        kdf: KdfId::HKDF_SHA256,
        aead: AeadId::AES_128_GCM,
    },
    CryptoPolicy {
        name: "balanced",
        kem: MlKemHpke::MlKem768,
        kdf: KdfId::HKDF_SHA256,
        aead: AeadId::CHACHA20_POLY1305,
    },
    CryptoPolicy {
        name: "high-security",
        kem: MlKemHpke::MlKem1024,
        kdf: KdfId::HKDF_SHA512,
        aead: AeadId::AES_256_GCM,
    },
];

struct AgilityResult {
    policy_name: &'static str,
    encapsulation_bytes: usize,
    ciphertext_bytes: usize,
}

fn execute_policy(policy: CryptoPolicy) -> Result<AgilityResult, Box<dyn Error>> {
    let suite = HpkeSuite::new(policy.kem, policy.kdf, policy.aead)?;

    // The recipient provisions a key pair according to the selected policy.
    let recipient = policy.kem.generate_key_pair(&mut OsRng)?;

    // The sender-side workflow is identical for every policy.
    let sender =
        setup_base_sender_with_suite(policy.kem, suite, &recipient.public_key, INFO, &mut OsRng)?;

    let encapsulated_key = sender.encapsulated_key;
    let mut sender_context = sender.context;

    // The receiver-side workflow is also independent of the selected policy.
    let mut receiver_context = setup_base_receiver_with_suite(
        policy.kem,
        suite,
        recipient.private_key_seed.as_bytes(),
        &encapsulated_key,
        INFO,
    )?;

    let ciphertext = sender_context.seal(ASSOCIATED_DATA, MESSAGE)?;
    let plaintext = receiver_context.open(ASSOCIATED_DATA, &ciphertext)?;

    assert_eq!(plaintext, MESSAGE);
    assert_eq!(
        sender_context.sequence_number(),
        receiver_context.sequence_number(),
    );

    Ok(AgilityResult {
        policy_name: policy.name,
        encapsulation_bytes: encapsulated_key.len(),
        ciphertext_bytes: ciphertext.len(),
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("HPKE cryptographic-agility reference application");

    for policy in POLICIES {
        let result = execute_policy(policy)?;

        println!(
            "policy: {}; encapsulation: {} bytes; ciphertext: {} bytes; round trip: pass",
            result.policy_name, result.encapsulation_bytes, result.ciphertext_bytes,
        );
    }

    println!("application workflow reused across all policies: pass");

    Ok(())
}
