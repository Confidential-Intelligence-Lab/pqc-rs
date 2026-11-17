//! Runtime enforcement after HPKE activation using locally recorded changes.
//!
//! These tests provide modeled policy/evidence assessments, not independently
//! authenticated external evidence or a physical provider swap.

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
    activate_receiver_continuous, activate_sender_continuous, ContinuedUseError,
    ContinuedUseReceiver, ContinuedUseSender, SharedTransitionGate,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};

const AAD: &[u8] = b"continued-use-aad";
const CONTEXT: &[u8] = b"continued-use-v1";

struct DeterministicRng(u8);

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
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
    let local = CapabilityOffer::new(&ids).unwrap();
    let peer = CapabilityOffer::new(&ids).unwrap();
    let policy = CapabilityPolicy::new(PolicyId::new(0x1010), &ids).unwrap();
    let negotiated = negotiate_policy_permitted_common(local, peer, policy).unwrap();
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

fn setup_channels() -> (
    SharedTransitionGate,
    SharedTransitionGate,
    ContinuedUseSender,
    ContinuedUseReceiver,
) {
    let pair = MlKemHpke::MlKem768.derive_key_pair(&[0x11; 64]).unwrap();
    let sender_transition = transition(EvidenceScope::Encapsulation);
    let receiver_transition = transition(EvidenceScope::Decapsulation);
    let sender_gate = SharedTransitionGate::new(TransitionExecutionGate::new(
        sender_transition,
        permitted(sender_transition),
    ));
    let receiver_gate = SharedTransitionGate::new(TransitionExecutionGate::new(
        receiver_transition,
        permitted(receiver_transition),
    ));

    let mut rng = DeterministicRng(0x51);
    let activated = activate_sender_continuous(
        &sender_gate,
        sender_gate.snapshot().unwrap(),
        &endpoint(ProtocolRole::Client),
        &pair.public_key,
        CONTEXT,
        &mut rng,
    )
    .unwrap();
    let (encapsulated, sender) = activated.into_parts();
    let receiver = activate_receiver_continuous(
        &receiver_gate,
        receiver_gate.snapshot().unwrap(),
        &endpoint(ProtocolRole::Server),
        pair.private_key_seed.as_bytes(),
        &encapsulated,
        CONTEXT,
    )
    .unwrap();
    (sender_gate, receiver_gate, sender, receiver)
}

#[test]
fn continued_use_permits_normal_hpke_roundtrip() {
    let (_, _, mut sender, mut receiver) = setup_channels();
    assert_eq!(sender.sequence_number(), 0);
    assert_eq!(receiver.sequence_number(), 0);
    let message = sender.seal(AAD, b"first").unwrap();
    assert_eq!(receiver.open(AAD, &message).unwrap(), b"first");
    assert_eq!(sender.sequence_number(), 1);
    assert_eq!(receiver.sequence_number(), 1);
    println!("CONTINUED_USE|normal|sender=allowed|receiver=allowed|seq=1");
}

#[test]
fn sender_withdrawal_blocks_message_without_advancing_sequence() {
    let (sender_gate, _, mut sender, mut receiver) = setup_channels();
    let first = sender.seal(AAD, b"first").unwrap();
    assert_eq!(receiver.open(AAD, &first).unwrap(), b"first");
    assert_eq!(sender.sequence_number(), 1);

    let sender_gate_clone = sender_gate.clone();
    let request = transition(EvidenceScope::Encapsulation);
    let mut missing = permitted(request);
    missing.destination_evidence = EvidenceApplicability::Missing;
    sender_gate_clone
        .advance(ExecutionContextChange::Evidence, missing)
        .unwrap();

    assert!(matches!(
        sender.seal(AAD, b"second"),
        Err(ContinuedUseError::Gate(ExecutionGateError::StaleContext))
    ));
    assert_eq!(sender.sequence_number(), 1);
    assert!(matches!(
        sender.refresh_authorization(),
        Err(ContinuedUseError::Gate(ExecutionGateError::NotPermitted(
            AuthorizationDecision::Defer
        )))
    ));
    assert_eq!(sender.sequence_number(), 1);

    sender_gate
        .advance(ExecutionContextChange::Evidence, permitted(request))
        .unwrap();
    assert!(matches!(
        sender.seal(AAD, b"second"),
        Err(ContinuedUseError::Gate(ExecutionGateError::StaleContext))
    ));
    sender.refresh_authorization().unwrap();
    let second = sender.seal(AAD, b"second").unwrap();
    assert_eq!(receiver.open(AAD, &second).unwrap(), b"second");
    assert_eq!(sender.sequence_number(), 2);
    assert_eq!(receiver.sequence_number(), 2);
    println!("CONTINUED_USE|sender_evidence_withdrawal|blocked_seq=1|resumed_seq=2");
}

#[test]
fn receiver_withdrawal_preserves_ciphertext_and_sequence() {
    let (_, receiver_gate, mut sender, mut receiver) = setup_channels();
    let message = sender.seal(AAD, b"first").unwrap();
    let request = transition(EvidenceScope::Decapsulation);
    let mut missing = permitted(request);
    missing.destination_evidence = EvidenceApplicability::Missing;
    receiver_gate
        .advance(ExecutionContextChange::Evidence, missing)
        .unwrap();

    assert!(matches!(
        receiver.open(AAD, &message),
        Err(ContinuedUseError::Gate(ExecutionGateError::StaleContext))
    ));
    assert_eq!(receiver.sequence_number(), 0);
    assert!(matches!(
        receiver.refresh_authorization(),
        Err(ContinuedUseError::Gate(ExecutionGateError::NotPermitted(
            AuthorizationDecision::Defer
        )))
    ));
    assert_eq!(receiver.sequence_number(), 0);

    receiver_gate
        .advance(ExecutionContextChange::Evidence, permitted(request))
        .unwrap();
    receiver.refresh_authorization().unwrap();
    assert_eq!(receiver.open(AAD, &message).unwrap(), b"first");
    assert_eq!(receiver.sequence_number(), 1);
    println!("CONTINUED_USE|receiver_evidence_withdrawal|blocked_seq=0|resumed_seq=1");
}

#[test]
fn policy_prohibition_requires_fresh_affirmative_reassessment() {
    let (sender_gate, _, mut sender, _) = setup_channels();
    let request = transition(EvidenceScope::Encapsulation);
    let mut prohibited = permitted(request);
    prohibited.transition_policy = PolicyAssessment::Prohibited;
    sender_gate
        .advance(ExecutionContextChange::Policy, prohibited)
        .unwrap();
    assert!(matches!(
        sender.refresh_authorization(),
        Err(ContinuedUseError::Gate(ExecutionGateError::NotPermitted(
            AuthorizationDecision::Deny
        )))
    ));
    assert_eq!(sender.sequence_number(), 0);

    sender_gate
        .advance(ExecutionContextChange::Policy, permitted(request))
        .unwrap();
    assert!(matches!(
        sender.seal(AAD, b"restored"),
        Err(ContinuedUseError::Gate(ExecutionGateError::StaleContext))
    ));
    sender.refresh_authorization().unwrap();
    sender.seal(AAD, b"restored").unwrap();
    assert_eq!(sender.sequence_number(), 1);
    println!("CONTINUED_USE|policy_prohibition|denied_then_resumed|seq=1");
}

#[test]
fn unknown_and_pending_assessments_do_not_authorize_messages() {
    let (sender_gate, _, mut sender, _) = setup_channels();
    let request = transition(EvidenceScope::Encapsulation);
    let mut unknown = permitted(request);
    unknown.destination_evidence = EvidenceApplicability::Indeterminate;
    sender_gate
        .advance(ExecutionContextChange::Evidence, unknown)
        .unwrap();
    assert!(matches!(
        sender.refresh_authorization(),
        Err(ContinuedUseError::Gate(ExecutionGateError::NotPermitted(
            AuthorizationDecision::Unknown
        )))
    ));
    assert_eq!(sender.sequence_number(), 0);

    let mut pending = permitted(request);
    pending.readiness = OperationalReadiness::Pending;
    sender_gate
        .advance(ExecutionContextChange::Deployment, pending)
        .unwrap();
    assert!(matches!(
        sender.refresh_authorization(),
        Err(ContinuedUseError::Gate(ExecutionGateError::NotPermitted(
            AuthorizationDecision::Defer
        )))
    ));
    assert_eq!(sender.sequence_number(), 0);
    println!("CONTINUED_USE|unknown_and_pending|no_hpke_message|seq=0");
}

#[test]
fn stale_activation_does_not_create_a_guarded_channel() {
    let pair = MlKemHpke::MlKem768.derive_key_pair(&[0x31; 64]).unwrap();
    let request = transition(EvidenceScope::Encapsulation);
    let gate = SharedTransitionGate::new(TransitionExecutionGate::new(request, permitted(request)));
    let old = gate.snapshot().unwrap();
    let mut missing = permitted(request);
    missing.destination_evidence = EvidenceApplicability::Missing;
    gate.advance(ExecutionContextChange::Evidence, missing)
        .unwrap();
    let mut rng = DeterministicRng(0x61);
    let attempt = activate_sender_continuous(
        &gate,
        old,
        &endpoint(ProtocolRole::Client),
        &pair.public_key,
        CONTEXT,
        &mut rng,
    );
    assert!(matches!(
        attempt,
        Err(ContinuedUseError::Activation(
            pqc_secure_channel::GuardedActivationError::Gate(ExecutionGateError::StaleContext)
        ))
    ));
    println!("CONTINUED_USE|stale_activation|rejected");
}

#[test]
fn independent_gate_handles_share_a_single_authorization_state() {
    let (sender_gate, _, mut sender, _) = setup_channels();
    let second_handle = sender_gate.clone();
    let request = transition(EvidenceScope::Encapsulation);
    let mut denied = permitted(request);
    denied.transition_policy = PolicyAssessment::Prohibited;
    second_handle
        .advance(ExecutionContextChange::Policy, denied)
        .unwrap();
    assert!(matches!(
        sender.seal(AAD, b"blocked"),
        Err(ContinuedUseError::Gate(ExecutionGateError::StaleContext))
    ));
    assert_eq!(sender.sequence_number(), 0);
}
