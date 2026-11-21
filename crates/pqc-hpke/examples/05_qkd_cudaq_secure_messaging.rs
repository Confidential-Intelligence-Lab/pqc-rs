//! Experimental CUDA-Q BB84 fixture to ML-KEM-768 HPKE-PSK messaging.
//! The input contains an openly provisioned fixture, NOT a secure QKD key.
use std::{collections::BTreeMap, env, error::Error, fs};

use pqc_hpke::qkd::{QkdKeyStore, QkdProvenance, QkdProviderError};
use pqc_hpke::setup::setup_psk_receiver_with_suite;
use pqc_hpke::{setup_psk_sender_with_suite, AeadId, HpkeSuite, KdfId, MlKemHpke};
use rand_core::OsRng;
use zeroize::Zeroizing;

const INFO: &[u8] = b"pqc-rs/qkd-cudaq/hpke-psk-demo/v1;alice;bob";
const AAD: &[u8] = b"pqc-rs/qkd-cudaq/experimental-message/v1";

fn main() -> Result<(), Box<dyn Error>> {
    let fixture_path = env::args()
        .nth(1)
        .ok_or("usage: 05_qkd_cudaq_secure_messaging FIXTURE_PATH")?;
    let file = Zeroizing::new(fs::read_to_string(fixture_path)?);
    let mut lines = file.lines();
    if lines.next() != Some("QKD_SIM_FIXTURE_V1") {
        return Err("unrecognized QKD fixture format".into());
    }
    let mut fields = BTreeMap::new();
    for line in lines {
        let (key, value) = line.split_once('=').ok_or("malformed fixture field")?;
        if fields.insert(key, value).is_some() {
            return Err("duplicate fixture field".into());
        }
    }
    if fields.len() != 6
        || fields.get("provenance") != Some(&"cudaq-bb84-insecure-fixture")
        || fields.get("errors") != Some(&"0")
    {
        return Err("invalid or non-ideal experimental fixture".into());
    }
    let id = *fields.get("key_id").ok_or("missing key ID")?;
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("invalid fixture key ID".into());
    }
    let transmissions: usize = fields
        .get("transmissions")
        .ok_or("missing transmissions")?
        .parse()?;
    let sifted: usize = fields
        .get("sifted")
        .ok_or("missing sifted count")?
        .parse()?;
    if transmissions < 512 || sifted < 256 || sifted > transmissions {
        return Err("invalid fixture experiment counts".into());
    }
    let raw = Zeroizing::new(hex::decode(
        fields.get("secret_hex").ok_or("missing secret")?,
    )?);
    let secret: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "expected 256-bit key")?;
    // Explicitly insecure two-store provisioning: the fixture contains the shared secret.
    let mut alice = QkdKeyStore::new();
    let mut bob = QkdKeyStore::new();
    alice.provision_fixture(id, "alice", "bob", secret)?;
    bob.provision_fixture(id, "bob", "alice", secret)?;
    let alice_key = alice.take_for(id, "alice", "bob")?;
    let bob_key = bob.take_for(id, "bob", "alice")?;
    assert_eq!(alice_key.provenance(), QkdProvenance::SimulationFixture);
    assert_eq!(bob_key.provenance(), QkdProvenance::SimulationFixture);

    let kem = MlKemHpke::MlKem768;
    let suite = HpkeSuite::new(kem, KdfId::HKDF_SHA256, AeadId::CHACHA20_POLY1305)?;
    let recipient = kem.generate_key_pair(&mut OsRng)?;
    let sender = setup_psk_sender_with_suite(
        kem,
        suite,
        &recipient.public_key,
        INFO,
        alice_key.secret(),
        alice_key.id().as_bytes(),
        &mut OsRng,
    )?;
    let mut receiver = setup_psk_receiver_with_suite(
        kem,
        suite,
        recipient.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        INFO,
        bob_key.secret(),
        bob_key.id().as_bytes(),
    )?;
    let mut sender_context = sender.context;
    let message = b"CUDA-Q BB84 fixture + ML-KEM-768 HPKE PSK message";
    let ciphertext = sender_context.seal(AAD, message)?;
    if receiver.open(AAD, &ciphertext)? != message {
        return Err("plaintext mismatch".into());
    }
    if alice.take_for(id, "alice", "bob").unwrap_err() != QkdProviderError::KeyUnavailable
        || bob.take_for(id, "bob", "alice").unwrap_err() != QkdProviderError::KeyUnavailable
    {
        return Err("single-use key invariant failed".into());
    }
    println!("QKD_M1C_CUDAQ_BB84_INTEGRATION_STATUS=PASS");
    println!("QKD_M1C_PROVENANCE=SIMULATION_FIXTURE_NOT_SECURE_QKD");
    Ok(())
}
