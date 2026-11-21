//! Cross-language public-evidence gate and explicitly insecure HPKE PSK fixture.
use pqc_hpke::qkd::{QkdKeyStore, QkdProviderError};
use pqc_hpke::qkd_m2b::{production_handoff, HandoffDenial, PublicDistillationEvidence};
use pqc_hpke::setup::setup_psk_receiver_with_suite;
use pqc_hpke::{setup_psk_sender_with_suite, AeadId, HpkeSuite, KdfId, MlKemHpke};
use rand_core::OsRng;
use std::process::Command;

fn public_evidence_from_python() -> PublicDistillationEvidence<'static> {
    // This probe uses preconstructed measurement records, not CUDA-Q hardware
    // or a simulator runtime. Always exercise the cross-language denial gate in
    // ordinary CI; CUDAQ_PYTHON remains an explicit interpreter override.
    let executable = std::env::var("CUDAQ_PYTHON").unwrap_or_else(|_| "python3".to_owned());
    let script = format!(
        "{}/../../experiments/qkd/m2b_handoff_probe.py",
        env!("CARGO_MANIFEST_DIR")
    );
    let result = Command::new(executable)
        .arg(script)
        .output()
        .expect("M2.A Python probe launch");
    assert!(
        result.status.success(),
        "M2.A probe failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let text = String::from_utf8(result.stdout).expect("non-UTF8 public evidence");
    let parts: Vec<_> = text.trim_end().split('\t').collect();
    assert_eq!(parts.len(), 8, "invalid public evidence wire shape");
    assert_eq!(parts[0], "M2A_EVIDENCE_V1");
    assert_eq!(parts[1], "CUDA_Q_SIMULATION_NOT_SECURE_QKD");
    assert_eq!(parts[7], "REJECT_NO_VERIFIED_ENTROPY");
    fn flag(v: &str) -> bool {
        match v {
            "true" => true,
            "false" => false,
            _ => panic!("invalid public bool"),
        }
    }
    // Provenance is matched above, not taken from untrusted input.
    PublicDistillationEvidence {
        provenance: "CUDA_Q_SIMULATION_NOT_SECURE_QKD",
        security_model_validated: flag(parts[2]),
        security_qualified: flag(parts[3]),
        quantum_min_entropy_proven: flag(parts[4]),
        qkd_psk_available: flag(parts[5]),
        hpke_export_authorized: flag(parts[6]),
    }
}

#[test]
fn actual_m2a_report_is_denied_at_rust_boundary() {
    let facts = public_evidence_from_python();
    assert_eq!(
        production_handoff(facts),
        Err(HandoffDenial::SimulationProvenance)
    );
    assert!(!facts.hpke_export_authorized);
    println!("QKD_M2B_PUBLIC_M2A_RUST_GATE=REJECT_UNQUALIFIED");
}

#[test]
fn forged_positive_public_flags_cannot_grant_authority() {
    let all_positive = PublicDistillationEvidence {
        provenance: "CUDA_Q_SIMULATION_NOT_SECURE_QKD",
        security_model_validated: true,
        security_qualified: true,
        quantum_min_entropy_proven: true,
        qkd_psk_available: true,
        hpke_export_authorized: true,
    };
    assert_eq!(
        production_handoff(all_positive),
        Err(HandoffDenial::SimulationProvenance)
    );
    assert_eq!(
        production_handoff(PublicDistillationEvidence {
            provenance: "other",
            ..all_positive
        }),
        Err(HandoffDenial::QualifiedProviderNotImplemented)
    );
    assert_eq!(
        production_handoff(PublicDistillationEvidence {
            provenance: "other",
            quantum_min_entropy_proven: false,
            ..all_positive
        }),
        Err(HandoffDenial::MissingEvidence)
    );
}

#[test]
fn independent_explicit_fixture_roundtrips_mlkem768_hpke_psk() {
    // These 32 bytes are a public, constant, intentionally insecure fixture.
    // They are NOT extracted from M2.A or from a simulated quantum circuit.
    let mut alice = QkdKeyStore::new();
    let mut bob = QkdKeyStore::new();
    alice
        .provision_fixture("m2b-insecure-fixture-01", "alice", "bob", [0xA5; 32])
        .unwrap();
    bob.provision_fixture("m2b-insecure-fixture-01", "bob", "alice", [0xA5; 32])
        .unwrap();
    assert_eq!(
        alice
            .take_for("m2b-insecure-fixture-01", "eve", "bob")
            .unwrap_err(),
        QkdProviderError::Unauthorized
    );
    let key_a = alice
        .take_for("m2b-insecure-fixture-01", "alice", "bob")
        .unwrap();
    let key_b = bob
        .take_for("m2b-insecure-fixture-01", "bob", "alice")
        .unwrap();
    let kem = MlKemHpke::MlKem768;
    let suite = HpkeSuite::new(kem, KdfId::HKDF_SHA256, AeadId::CHACHA20_POLY1305).unwrap();
    let recipient = kem.generate_key_pair(&mut OsRng).unwrap();
    let info = b"pqc-rs/m2b/EXPLICITLY-INSECURE-FIXTURE/v1;alice;bob";
    let aad = b"m2b-fixture-only";
    let sender = setup_psk_sender_with_suite(
        kem,
        suite,
        &recipient.public_key,
        info,
        key_a.secret(),
        key_a.id().as_bytes(),
        &mut OsRng,
    )
    .unwrap();
    let mut sender_ctx = sender.context;
    let ciphertext = sender_ctx
        .seal(aad, b"M2.B functional fixture only")
        .unwrap();
    let mut receiver = setup_psk_receiver_with_suite(
        kem,
        suite,
        recipient.private_key_seed.as_bytes(),
        &sender.encapsulated_key,
        info,
        key_b.secret(),
        key_b.id().as_bytes(),
    )
    .unwrap();
    assert_eq!(
        receiver.open(aad, &ciphertext).unwrap(),
        b"M2.B functional fixture only"
    );
    assert_eq!(
        alice
            .take_for("m2b-insecure-fixture-01", "alice", "bob")
            .unwrap_err(),
        QkdProviderError::KeyUnavailable
    );
    assert_eq!(
        bob.take_for("m2b-insecure-fixture-01", "bob", "alice")
            .unwrap_err(),
        QkdProviderError::KeyUnavailable
    );
    println!("QKD_M2B_INSECURE_HPKE_FIXTURE=PASS");
}
