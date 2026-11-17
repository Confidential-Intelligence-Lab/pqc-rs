//! Controlled comparison of HPKE activation with and without transition gating.
//!
//! These tests use caller-supplied policy/evidence assessments, not an
//! authenticated evidence verifier. Both paths execute the same PQC-rs ML-KEM
//! implementation: provider identity is an abstract configuration label, not
//! a physically swapped provider. The baseline is correct HPKE but is not
//! designed to revalidate security-relevant state at activation.

use pqc_hpke::MlKemHpke;
use pqc_protocol::{
    negotiate_policy_permitted_common, AlgorithmId, AssessedExecutionContext,
    AuthorizationDecision, CapabilityId, CapabilityOffer, CapabilityPolicy, ConfigurationIdentity,
    CryptographicTransition, EstablishedProtocolContext, EvidenceApplicability, EvidenceScope,
    ExecutionContextChange, ExecutionGateError, ImplementationRevision, OperationalReadiness,
    ParameterSetId, PolicyAssessment, PolicyId, ProtocolId, ProtocolRole, ProtocolVersion,
    ProviderId, SessionId, TransitionAssessments, TransitionExecutionGate, TypedProtocolSession,
    HPKE_ML_KEM_768, HPKE_ML_KEM_768_X25519,
};
use pqc_secure_channel::{
    activate_receiver, activate_receiver_guarded, activate_sender, activate_sender_guarded,
    GuardedActivationError,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};

const APPLICATION_CONTEXT: &[u8] = b"transition-comparison-v1";
const RNG_SEED: u8 = 0x51;

struct CountingRng {
    next: u8,
    bytes_generated: usize,
}

impl CountingRng {
    const fn new(seed: u8) -> Self {
        Self {
            next: seed,
            bytes_generated: 0,
        }
    }
}

impl RngCore for CountingRng {
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

    fn fill_bytes(&mut self, output: &mut [u8]) {
        self.bytes_generated += output.len();
        for byte in output {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(output);
        Ok(())
    }
}

impl CryptoRng for CountingRng {}

fn endpoint(capability: CapabilityId, role: ProtocolRole) -> EstablishedProtocolContext {
    let capabilities = [capability];
    let local = CapabilityOffer::new(&capabilities).unwrap();
    let peer = CapabilityOffer::new(&capabilities).unwrap();
    let policy = CapabilityPolicy::new(PolicyId::new(0x1010), &capabilities).unwrap();
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

fn transition(capability: CapabilityId, scope: EvidenceScope) -> CryptographicTransition {
    let algorithm = AlgorithmId::new(u32::from(capability.value()));
    let source = ConfigurationIdentity::new(
        algorithm,
        ParameterSetId::new(768),
        ProviderId::new(1),
        ImplementationRevision::new(1),
    );
    let destination = ConfigurationIdentity::new(
        algorithm,
        ParameterSetId::new(768),
        ProviderId::new(2),
        ImplementationRevision::new(1),
    );
    CryptographicTransition::new(source, destination, scope)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedGuardResult {
    Allowed,
    Stale,
    Deny,
    Defer,
    Unknown,
}

impl ExpectedGuardResult {
    const fn label(self) -> &'static str {
        match self {
            Self::Allowed => "activated",
            Self::Stale => "stale",
            Self::Deny => "denied",
            Self::Defer => "deferred",
            Self::Unknown => "unknown",
        }
    }

    const fn matches(self, error: &GuardedActivationError) -> bool {
        matches!(
            (self, error),
            (
                Self::Stale,
                GuardedActivationError::Gate(ExecutionGateError::StaleContext)
            ) | (
                Self::Deny,
                GuardedActivationError::Gate(ExecutionGateError::NotPermitted(
                    AuthorizationDecision::Deny
                ))
            ) | (
                Self::Defer,
                GuardedActivationError::Gate(ExecutionGateError::NotPermitted(
                    AuthorizationDecision::Defer
                ))
            ) | (
                Self::Unknown,
                GuardedActivationError::Gate(ExecutionGateError::NotPermitted(
                    AuthorizationDecision::Unknown
                ))
            )
        )
    }
}

fn compare_sender(
    scenario: &str,
    gate: &TransitionExecutionGate,
    snapshot: AssessedExecutionContext,
    client: &EstablishedProtocolContext,
    recipient_public_key: &[u8],
    expected: ExpectedGuardResult,
) {
    let mut baseline_rng = CountingRng::new(RNG_SEED);
    let baseline = activate_sender(
        client,
        recipient_public_key,
        APPLICATION_CONTEXT,
        &mut baseline_rng,
    )
    .expect("baseline cryptographic activation must succeed");
    assert!(baseline_rng.bytes_generated > 0);

    let mut guarded_rng = CountingRng::new(RNG_SEED);
    let guarded = activate_sender_guarded(
        gate,
        snapshot,
        client,
        recipient_public_key,
        APPLICATION_CONTEXT,
        &mut guarded_rng,
    );

    match expected {
        ExpectedGuardResult::Allowed => {
            let activated = match guarded {
                Ok(activated) => activated,
                Err(error) => panic!("{scenario}: expected permitted activation, got {error}"),
            };
            assert!(guarded_rng.bytes_generated > 0);
            assert_eq!(baseline.encapsulated_key(), activated.encapsulated_key());
        }
        _ => {
            let error = match guarded {
                Err(error) => error,
                Ok(_) => panic!("{scenario}: inadmissible activation was unexpectedly allowed"),
            };
            assert!(
                expected.matches(&error),
                "{scenario}: unexpected error {error}"
            );
            assert_eq!(
                guarded_rng.bytes_generated, 0,
                "{scenario}: rejected activation consumed randomness"
            );
        }
    }

    println!(
        "AGILITY_COMPARE|{}|baseline=activated|guarded={}|baseline_rng_bytes={}|guarded_rng_bytes={}",
        scenario,
        expected.label(),
        baseline_rng.bytes_generated,
        guarded_rng.bytes_generated
    );
}

#[test]
fn comparison_matrix_across_state_changes() {
    let key_pair = MlKemHpke::MlKem768.derive_key_pair(&[0x11; 64]).unwrap();
    let client = endpoint(HPKE_ML_KEM_768, ProtocolRole::Client);
    let request = transition(HPKE_ML_KEM_768, EvidenceScope::Encapsulation);
    let mut gate = TransitionExecutionGate::new(request, permitted(request));

    compare_sender(
        "initial_permitted",
        &gate,
        gate.snapshot(),
        &client,
        &key_pair.public_key,
        ExpectedGuardResult::Allowed,
    );

    let before_withdrawal = gate.snapshot();
    let mut missing = permitted(request);
    missing.destination_evidence = EvidenceApplicability::Missing;
    gate.advance(ExecutionContextChange::Evidence, missing)
        .unwrap();
    compare_sender(
        "evidence_withdrawn_stale_snapshot",
        &gate,
        before_withdrawal,
        &client,
        &key_pair.public_key,
        ExpectedGuardResult::Stale,
    );
    compare_sender(
        "evidence_withdrawn_fresh_snapshot",
        &gate,
        gate.snapshot(),
        &client,
        &key_pair.public_key,
        ExpectedGuardResult::Defer,
    );

    let mut indeterminate = permitted(request);
    indeterminate.destination_evidence = EvidenceApplicability::Indeterminate;
    gate.advance(ExecutionContextChange::Evidence, indeterminate)
        .unwrap();
    compare_sender(
        "evidence_indeterminate",
        &gate,
        gate.snapshot(),
        &client,
        &key_pair.public_key,
        ExpectedGuardResult::Unknown,
    );

    let mut mismatched = permitted(request);
    mismatched.destination_evidence = EvidenceApplicability::Mismatch;
    gate.advance(ExecutionContextChange::Evidence, mismatched)
        .unwrap();
    compare_sender(
        "evidence_mismatch",
        &gate,
        gate.snapshot(),
        &client,
        &key_pair.public_key,
        ExpectedGuardResult::Deny,
    );

    let before_restoration = gate.snapshot();
    gate.advance(ExecutionContextChange::Evidence, permitted(request))
        .unwrap();
    compare_sender(
        "restored_evidence_stale_snapshot",
        &gate,
        before_restoration,
        &client,
        &key_pair.public_key,
        ExpectedGuardResult::Stale,
    );
    compare_sender(
        "restored_evidence_fresh_snapshot",
        &gate,
        gate.snapshot(),
        &client,
        &key_pair.public_key,
        ExpectedGuardResult::Allowed,
    );

    let before_policy = gate.snapshot();
    let mut prohibited = permitted(request);
    prohibited.destination_policy = PolicyAssessment::Prohibited;
    gate.advance(ExecutionContextChange::Policy, prohibited)
        .unwrap();
    compare_sender(
        "policy_change_stale_snapshot",
        &gate,
        before_policy,
        &client,
        &key_pair.public_key,
        ExpectedGuardResult::Stale,
    );
    compare_sender(
        "policy_prohibition_fresh_snapshot",
        &gate,
        gate.snapshot(),
        &client,
        &key_pair.public_key,
        ExpectedGuardResult::Deny,
    );

    gate.advance(ExecutionContextChange::Policy, permitted(request))
        .unwrap();
    compare_sender(
        "policy_restored",
        &gate,
        gate.snapshot(),
        &client,
        &key_pair.public_key,
        ExpectedGuardResult::Allowed,
    );

    let mut pending = permitted(request);
    pending.readiness = OperationalReadiness::Pending;
    gate.advance(ExecutionContextChange::Deployment, pending)
        .unwrap();
    compare_sender(
        "deployment_pending",
        &gate,
        gate.snapshot(),
        &client,
        &key_pair.public_key,
        ExpectedGuardResult::Defer,
    );

    gate.advance(ExecutionContextChange::Deployment, permitted(request))
        .unwrap();
    let before_source_change = gate.snapshot();
    gate.advance(ExecutionContextChange::SourceState, permitted(request))
        .unwrap();
    compare_sender(
        "source_state_revision_changed",
        &gate,
        before_source_change,
        &client,
        &key_pair.public_key,
        ExpectedGuardResult::Stale,
    );
}

#[test]
fn receiver_baseline_succeeds_after_evidence_withdrawal_but_guarded_denies() {
    let key_pair = MlKemHpke::MlKem768.derive_key_pair(&[0x11; 64]).unwrap();
    let client = endpoint(HPKE_ML_KEM_768, ProtocolRole::Client);
    let server = endpoint(HPKE_ML_KEM_768, ProtocolRole::Server);

    let mut rng = CountingRng::new(RNG_SEED);
    let sender =
        activate_sender(&client, &key_pair.public_key, APPLICATION_CONTEXT, &mut rng).unwrap();
    let (encapsulated_key, mut sender) = sender.into_parts();
    let ciphertext = sender.seal(b"ad", b"payload").unwrap();

    let request = transition(HPKE_ML_KEM_768, EvidenceScope::Decapsulation);
    let mut receiver_gate = TransitionExecutionGate::new(request, permitted(request));
    let mut missing = permitted(request);
    missing.destination_evidence = EvidenceApplicability::Missing;
    receiver_gate
        .advance(ExecutionContextChange::Evidence, missing)
        .unwrap();

    let mut baseline_receiver = activate_receiver(
        &server,
        key_pair.private_key_seed.as_bytes(),
        &encapsulated_key,
        APPLICATION_CONTEXT,
    )
    .unwrap();
    assert_eq!(
        baseline_receiver
            .open(b"ad", &ciphertext)
            .unwrap()
            .as_slice(),
        b"payload"
    );

    let guarded_receiver = activate_receiver_guarded(
        &receiver_gate,
        receiver_gate.snapshot(),
        &server,
        key_pair.private_key_seed.as_bytes(),
        &encapsulated_key,
        APPLICATION_CONTEXT,
    );
    assert!(matches!(
        guarded_receiver,
        Err(GuardedActivationError::Gate(
            ExecutionGateError::NotPermitted(AuthorizationDecision::Defer)
        ))
    ));
    println!("AGILITY_COMPARE|receiver_evidence_withdrawn|baseline=activated|guarded=deferred");
}

#[test]
fn hybrid_profile_required_but_pure_kem_negotiated_is_rejected_by_guard() {
    let key_pair = MlKemHpke::MlKem768.derive_key_pair(&[0x11; 64]).unwrap();
    let client = endpoint(HPKE_ML_KEM_768, ProtocolRole::Client);
    let request = transition(HPKE_ML_KEM_768_X25519, EvidenceScope::Encapsulation);
    let gate = TransitionExecutionGate::new(request, permitted(request));
    let mut baseline_rng = CountingRng::new(RNG_SEED);
    assert!(activate_sender(
        &client,
        &key_pair.public_key,
        APPLICATION_CONTEXT,
        &mut baseline_rng,
    )
    .is_ok());

    let mut guarded_rng = CountingRng::new(RNG_SEED);
    let guarded = activate_sender_guarded(
        &gate,
        gate.snapshot(),
        &client,
        &key_pair.public_key,
        APPLICATION_CONTEXT,
        &mut guarded_rng,
    );
    assert!(matches!(
        guarded,
        Err(GuardedActivationError::CapabilityMismatch)
    ));
    assert_eq!(guarded_rng.bytes_generated, 0);
    println!(
        "AGILITY_COMPARE|hybrid_profile_required_pure_negotiated|baseline=activated|guarded=capability_mismatch"
    );
}

#[test]
fn established_channels_continue_after_evidence_change_without_per_message_gate() {
    let key_pair = MlKemHpke::MlKem768.derive_key_pair(&[0x11; 64]).unwrap();
    let client = endpoint(HPKE_ML_KEM_768, ProtocolRole::Client);
    let server = endpoint(HPKE_ML_KEM_768, ProtocolRole::Server);
    let sender_request = transition(HPKE_ML_KEM_768, EvidenceScope::Encapsulation);
    let receiver_request = transition(HPKE_ML_KEM_768, EvidenceScope::Decapsulation);
    let mut sender_gate = TransitionExecutionGate::new(sender_request, permitted(sender_request));
    let mut receiver_gate =
        TransitionExecutionGate::new(receiver_request, permitted(receiver_request));
    let mut rng = CountingRng::new(RNG_SEED);

    let activated_sender = activate_sender_guarded(
        &sender_gate,
        sender_gate.snapshot(),
        &client,
        &key_pair.public_key,
        APPLICATION_CONTEXT,
        &mut rng,
    )
    .unwrap();
    let (encapsulated_key, mut sender) = activated_sender.into_parts();
    let mut receiver = activate_receiver_guarded(
        &receiver_gate,
        receiver_gate.snapshot(),
        &server,
        key_pair.private_key_seed.as_bytes(),
        &encapsulated_key,
        APPLICATION_CONTEXT,
    )
    .unwrap();

    let mut missing_sender = permitted(sender_request);
    missing_sender.destination_evidence = EvidenceApplicability::Missing;
    sender_gate
        .advance(ExecutionContextChange::Evidence, missing_sender)
        .unwrap();
    let mut missing_receiver = permitted(receiver_request);
    missing_receiver.destination_evidence = EvidenceApplicability::Missing;
    receiver_gate
        .advance(ExecutionContextChange::Evidence, missing_receiver)
        .unwrap();

    let encrypted = sender.seal(b"ad", b"post-withdrawal message").unwrap();
    assert_eq!(
        receiver.open(b"ad", &encrypted).unwrap().as_slice(),
        b"post-withdrawal message"
    );
    println!(
        "AGILITY_SCOPE|established_channel_after_evidence_change|continuing_use=allowed|enforcement=activation_only"
    );
}
