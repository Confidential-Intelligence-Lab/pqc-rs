//! Controlled active-session comparison and synchronization tests.
//!
//! Changes to policy and evidence are synthetic, locally recorded inputs.
//! The tests cover opt-in guarded APIs only; they do not demonstrate external
//! evidence authentication, distributed revocation, or provider migration.

use std::sync::{mpsc, Arc, Barrier};
use std::thread;

use pqc_hpke::MlKemHpke;
use pqc_protocol::{
    negotiate_policy_permitted_common, AlgorithmId, AuthorizationDecision, CapabilityOffer,
    CapabilityPolicy, ConfigurationIdentity, CryptographicTransition, EstablishedProtocolContext,
    EvidenceApplicability, EvidenceScope, ExecutionContextChange, ExecutionGateError,
    ImplementationRevision, OperationalReadiness, ParameterSetId, PolicyAssessment, PolicyId,
    ProtocolId, ProtocolRole, ProtocolVersion, ProviderId, SessionId, TransitionAssessments,
    TransitionExecutionGate, TypedProtocolSession, HPKE_ML_KEM_768,
};
use pqc_secure_channel::{
    activate_receiver, activate_receiver_continuous, activate_sender, activate_sender_continuous,
    ContinuedUseError, ContinuedUseReceiver, ContinuedUseSender, SharedTransitionGate,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};

const AAD: &[u8] = b"temporal-evaluation-aad";
const CONTEXT: &[u8] = b"temporal-evaluation-v1";
const ROUNDS: usize = 32;

struct DeterministicRng(u8);

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for DeterministicRng {}

fn endpoint(role: ProtocolRole) -> EstablishedProtocolContext {
    let ids = [HPKE_ML_KEM_768];
    let offer = CapabilityOffer::new(&ids).unwrap();
    let policy = CapabilityPolicy::new(PolicyId::new(0x2010), &ids).unwrap();
    let negotiated = negotiate_policy_permitted_common(offer, offer, policy).unwrap();
    TypedProtocolSession::new(
        SessionId::from_bytes([0x31; 16]),
        ProtocolId::new(0x1300),
        ProtocolVersion::new(1, 0),
        role,
    )
    .begin_establishment()
    .establish_with_negotiation(negotiated)
}

fn transition(operation: EvidenceScope) -> CryptographicTransition {
    let config = |provider| {
        ConfigurationIdentity::new(
            AlgorithmId::new(u32::from(HPKE_ML_KEM_768.value())),
            ParameterSetId::new(768),
            ProviderId::new(provider),
            ImplementationRevision::new(1),
        )
    };
    CryptographicTransition::new(config(1), config(2), operation)
}

fn permitted(request: CryptographicTransition) -> TransitionAssessments {
    TransitionAssessments {
        assessed_transition: request,
        transition_policy: PolicyAssessment::Permitted,
        source_policy: PolicyAssessment::Permitted,
        destination_policy: PolicyAssessment::Permitted,
        destination_evidence: EvidenceApplicability::Applicable,
        readiness: OperationalReadiness::Ready,
    }
}

fn missing(request: CryptographicTransition) -> TransitionAssessments {
    let mut result = permitted(request);
    result.destination_evidence = EvidenceApplicability::Missing;
    result
}

fn setup_guarded() -> (
    SharedTransitionGate,
    SharedTransitionGate,
    ContinuedUseSender,
    ContinuedUseReceiver,
) {
    let key_pair = MlKemHpke::MlKem768.derive_key_pair(&[0x11; 64]).unwrap();
    let sender_request = transition(EvidenceScope::Encapsulation);
    let receiver_request = transition(EvidenceScope::Decapsulation);
    let sender_gate = SharedTransitionGate::new(TransitionExecutionGate::new(
        sender_request,
        permitted(sender_request),
    ));
    let receiver_gate = SharedTransitionGate::new(TransitionExecutionGate::new(
        receiver_request,
        permitted(receiver_request),
    ));
    let mut rng = DeterministicRng(0x51);
    let (encapsulated, sender) = activate_sender_continuous(
        &sender_gate,
        sender_gate.snapshot().unwrap(),
        &endpoint(ProtocolRole::Client),
        &key_pair.public_key,
        CONTEXT,
        &mut rng,
    )
    .unwrap()
    .into_parts();
    let receiver = activate_receiver_continuous(
        &receiver_gate,
        receiver_gate.snapshot().unwrap(),
        &endpoint(ProtocolRole::Server),
        key_pair.private_key_seed.as_bytes(),
        &encapsulated,
        CONTEXT,
    )
    .unwrap();
    (sender_gate, receiver_gate, sender, receiver)
}

#[test]
fn active_session_baseline_versus_guarded_withdrawal_and_recovery() {
    let key_pair = MlKemHpke::MlKem768.derive_key_pair(&[0x21; 64]).unwrap();
    let client = endpoint(ProtocolRole::Client);
    let server = endpoint(ProtocolRole::Server);
    let sender_request = transition(EvidenceScope::Encapsulation);
    let receiver_request = transition(EvidenceScope::Decapsulation);
    let sender_gate = SharedTransitionGate::new(TransitionExecutionGate::new(
        sender_request,
        permitted(sender_request),
    ));
    let receiver_gate = SharedTransitionGate::new(TransitionExecutionGate::new(
        receiver_request,
        permitted(receiver_request),
    ));

    // Identical test RNG streams and HPKE parameters yield identical contexts.
    let mut baseline_rng = DeterministicRng(0x51);
    let mut guarded_rng = DeterministicRng(0x51);
    let (baseline_encapsulated, mut baseline_sender) =
        activate_sender(&client, &key_pair.public_key, CONTEXT, &mut baseline_rng)
            .unwrap()
            .into_parts();
    let (guarded_encapsulated, mut guarded_sender) = activate_sender_continuous(
        &sender_gate,
        sender_gate.snapshot().unwrap(),
        &client,
        &key_pair.public_key,
        CONTEXT,
        &mut guarded_rng,
    )
    .unwrap()
    .into_parts();
    assert_eq!(baseline_encapsulated, guarded_encapsulated);
    let mut baseline_receiver = activate_receiver(
        &server,
        key_pair.private_key_seed.as_bytes(),
        &baseline_encapsulated,
        CONTEXT,
    )
    .unwrap();
    let mut guarded_receiver = activate_receiver_continuous(
        &receiver_gate,
        receiver_gate.snapshot().unwrap(),
        &server,
        key_pair.private_key_seed.as_bytes(),
        &guarded_encapsulated,
        CONTEXT,
    )
    .unwrap();

    let first_baseline = baseline_sender.seal(AAD, b"first").unwrap();
    let first_guarded = guarded_sender.seal(AAD, b"first").unwrap();
    assert_eq!(first_baseline, first_guarded);
    assert_eq!(
        baseline_receiver.open(AAD, &first_baseline).unwrap(),
        b"first"
    );
    assert_eq!(
        guarded_receiver.open(AAD, &first_guarded).unwrap(),
        b"first"
    );

    sender_gate
        .advance(ExecutionContextChange::Evidence, missing(sender_request))
        .unwrap();
    receiver_gate
        .advance(ExecutionContextChange::Evidence, missing(receiver_request))
        .unwrap();

    // The baseline continues because the original API has no evidence gate.
    let baseline_second = baseline_sender.seal(AAD, b"second").unwrap();
    assert_eq!(
        baseline_receiver.open(AAD, &baseline_second).unwrap(),
        b"second"
    );
    assert_eq!(baseline_sender.sequence_number(), 2);
    assert_eq!(baseline_receiver.sequence_number(), 2);

    // Guarded channels reject BEFORE consuming the message sequence.
    assert!(matches!(
        guarded_sender.seal(AAD, b"second"),
        Err(ContinuedUseError::Gate(ExecutionGateError::StaleContext))
    ));
    assert!(matches!(
        guarded_receiver.open(AAD, &baseline_second),
        Err(ContinuedUseError::Gate(ExecutionGateError::StaleContext))
    ));
    assert_eq!(guarded_sender.sequence_number(), 1);
    assert_eq!(guarded_receiver.sequence_number(), 1);
    assert!(matches!(
        guarded_sender.refresh_authorization(),
        Err(ContinuedUseError::Gate(ExecutionGateError::NotPermitted(
            AuthorizationDecision::Defer
        )))
    ));
    assert!(matches!(
        guarded_receiver.refresh_authorization(),
        Err(ContinuedUseError::Gate(ExecutionGateError::NotPermitted(
            AuthorizationDecision::Defer
        )))
    ));

    sender_gate
        .advance(ExecutionContextChange::Evidence, permitted(sender_request))
        .unwrap();
    receiver_gate
        .advance(
            ExecutionContextChange::Evidence,
            permitted(receiver_request),
        )
        .unwrap();
    assert!(matches!(
        guarded_sender.seal(AAD, b"second"),
        Err(ContinuedUseError::Gate(ExecutionGateError::StaleContext))
    ));
    guarded_sender.refresh_authorization().unwrap();
    guarded_receiver.refresh_authorization().unwrap();
    let guarded_second = guarded_sender.seal(AAD, b"second").unwrap();
    assert_eq!(baseline_second, guarded_second);
    assert_eq!(
        guarded_receiver.open(AAD, &guarded_second).unwrap(),
        b"second"
    );
    assert_eq!(guarded_sender.sequence_number(), 2);
    assert_eq!(guarded_receiver.sequence_number(), 2);

    println!(
        "TEMPORAL_COMPARE|active_session|baseline_after_withdrawal=allowed|guarded_after_withdrawal=blocked|blocked_sender_seq=1|blocked_receiver_seq=1|recovered_sender_seq=2|recovered_receiver_seq=2|ciphertext_parity=true"
    );
}

#[test]
fn concurrent_evidence_updater_enforces_ordered_revocation_across_threads() {
    let (sender_gate, _, mut sender, mut receiver) = setup_guarded();
    let change_request = transition(EvidenceScope::Encapsulation);
    let updater_gate = sender_gate.clone();
    let (withdrawn_tx, withdrawn_rx) = mpsc::channel::<usize>();
    let (withdrawn_ack_tx, withdrawn_ack_rx) = mpsc::channel::<()>();
    let (restored_tx, restored_rx) = mpsc::channel::<usize>();
    let (restored_ack_tx, restored_ack_rx) = mpsc::channel::<()>();

    let updater = thread::spawn(move || {
        for round in 0..ROUNDS {
            updater_gate
                .advance(ExecutionContextChange::Evidence, missing(change_request))
                .unwrap();
            withdrawn_tx.send(round).unwrap();
            withdrawn_ack_rx.recv().unwrap();
            updater_gate
                .advance(ExecutionContextChange::Evidence, permitted(change_request))
                .unwrap();
            restored_tx.send(round).unwrap();
            restored_ack_rx.recv().unwrap();
        }
    });

    for round in 0..ROUNDS {
        assert_eq!(withdrawn_rx.recv().unwrap(), round);
        assert!(matches!(
            sender.seal(AAD, b"blocked"),
            Err(ContinuedUseError::Gate(ExecutionGateError::StaleContext))
        ));
        assert_eq!(sender.sequence_number(), round as u64);
        withdrawn_ack_tx.send(()).unwrap();

        assert_eq!(restored_rx.recv().unwrap(), round);
        // Restoring an assessment never implicitly refreshes a stale handle.
        assert!(matches!(
            sender.seal(AAD, b"resumed"),
            Err(ContinuedUseError::Gate(ExecutionGateError::StaleContext))
        ));
        sender.refresh_authorization().unwrap();
        let ciphertext = sender.seal(AAD, b"resumed").unwrap();
        assert_eq!(receiver.open(AAD, &ciphertext).unwrap(), b"resumed");
        assert_eq!(sender.sequence_number(), (round + 1) as u64);
        assert_eq!(receiver.sequence_number(), (round + 1) as u64);
        restored_ack_tx.send(()).unwrap();
    }
    updater.join().unwrap();
    println!(
        "CONCURRENT_GATE|phased_evidence_updates|rounds={ROUNDS}|blocked={ROUNDS}|resumed={ROUNDS}|sequence_preserved=true"
    );
}

#[test]
fn simultaneous_updates_do_not_lose_snapshot_invalidation() {
    let (gate, _, mut sender, _) = setup_guarded();
    let request = transition(EvidenceScope::Encapsulation);
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for kind in [
        ExecutionContextChange::Evidence,
        ExecutionContextChange::Deployment,
    ] {
        let gate_clone = gate.clone();
        let barrier_clone = barrier.clone();
        workers.push(thread::spawn(move || {
            barrier_clone.wait();
            gate_clone.advance(kind, permitted(request)).unwrap();
        }));
    }
    barrier.wait();
    for worker in workers {
        worker.join().unwrap();
    }

    assert!(matches!(
        sender.seal(AAD, b"stale"),
        Err(ContinuedUseError::Gate(ExecutionGateError::StaleContext))
    ));
    assert_eq!(sender.sequence_number(), 0);
    sender.refresh_authorization().unwrap();
    sender.seal(AAD, b"after-refresh").unwrap();
    assert_eq!(sender.sequence_number(), 1);
    println!(
        "CONCURRENT_GATE|simultaneous_updates|updates=2|pre_refresh=stale|post_refresh=allowed|seq=1"
    );
}
