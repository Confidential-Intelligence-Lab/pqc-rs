use pqc_hpke::MlKemHpke;
use pqc_protocol::{
    negotiate_policy_permitted_common, AlgorithmId, AuthorizationDecision, CapabilityId,
    CapabilityOffer, CapabilityPolicy, ConfigurationIdentity, CryptographicTransition,
    EstablishedProtocolContext, EvidenceApplicability, EvidenceScope, ExecutionContextChange,
    ExecutionGateError, ImplementationRevision, OperationalReadiness, ParameterSetId,
    PolicyAssessment, PolicyId, ProtocolId, ProtocolRole, ProtocolVersion, ProviderId, SessionId,
    TransitionAssessments, TransitionExecutionGate, TypedProtocolSession, HPKE_ML_KEM_1024,
    HPKE_ML_KEM_768,
};
use pqc_secure_channel::{
    activate_receiver_guarded, activate_sender_guarded, GuardedActivationError,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};

struct DeterministicRng {
    next: u8,
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for item in dest {
            *item = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for DeterministicRng {}

fn established(capability: CapabilityId, role: ProtocolRole) -> EstablishedProtocolContext {
    let offered = [capability];
    let local = CapabilityOffer::new(&offered).unwrap();
    let remote = CapabilityOffer::new(&offered).unwrap();
    let policy = CapabilityPolicy::new(PolicyId::new(1), &offered).unwrap();
    let negotiated = negotiate_policy_permitted_common(local, remote, policy).unwrap();
    TypedProtocolSession::new(
        SessionId::from_bytes([0x41; 16]),
        ProtocolId::new(0x1300),
        ProtocolVersion::new(1, 0),
        role,
    )
    .begin_establishment()
    .establish_with_negotiation(negotiated)
}

fn transition(operation: EvidenceScope) -> CryptographicTransition {
    let source = ConfigurationIdentity::new(
        AlgorithmId::new(u32::from(HPKE_ML_KEM_768.value())),
        ParameterSetId::new(768),
        ProviderId::new(1),
        ImplementationRevision::new(1),
    );
    let destination = ConfigurationIdentity::new(
        AlgorithmId::new(u32::from(HPKE_ML_KEM_768.value())),
        ParameterSetId::new(768),
        ProviderId::new(2),
        ImplementationRevision::new(1),
    );
    CryptographicTransition::new(source, destination, operation)
}

fn allowed(change: CryptographicTransition) -> TransitionAssessments {
    TransitionAssessments {
        assessed_transition: change,
        transition_policy: PolicyAssessment::Permitted,
        source_policy: PolicyAssessment::Permitted,
        destination_policy: PolicyAssessment::Permitted,
        destination_evidence: EvidenceApplicability::Applicable,
        readiness: OperationalReadiness::Ready,
    }
}

fn gate(operation: EvidenceScope) -> TransitionExecutionGate {
    let t = transition(operation);
    TransitionExecutionGate::new(t, allowed(t))
}

#[test]
fn guarded_hpke_activation_round_trip() {
    let key_pair = MlKemHpke::MlKem768.derive_key_pair(&[0x11; 64]).unwrap();
    let sender_gate = gate(EvidenceScope::Encapsulation);
    let receiver_gate = gate(EvidenceScope::Decapsulation);
    let client = established(HPKE_ML_KEM_768, ProtocolRole::Client);
    let server = established(HPKE_ML_KEM_768, ProtocolRole::Server);
    let mut rng = DeterministicRng { next: 0x51 };
    let activation = activate_sender_guarded(
        &sender_gate,
        sender_gate.snapshot(),
        &client,
        &key_pair.public_key,
        b"guarded-hpke",
        &mut rng,
    )
    .unwrap();
    let (encapsulated_key, mut sender) = activation.into_parts();
    let mut receiver = activate_receiver_guarded(
        &receiver_gate,
        receiver_gate.snapshot(),
        &server,
        key_pair.private_key_seed.as_bytes(),
        &encapsulated_key,
        b"guarded-hpke",
    )
    .unwrap();
    let ciphertext = sender.seal(b"aad", b"message").unwrap();
    assert_eq!(
        receiver.open(b"aad", &ciphertext).unwrap().as_slice(),
        b"message"
    );
}

#[test]
fn evidence_withdrawal_blocks_actual_encapsulation() {
    let key_pair = MlKemHpke::MlKem768.derive_key_pair(&[0x11; 64]).unwrap();
    let mut gate = gate(EvidenceScope::Encapsulation);
    let stale = gate.snapshot();
    let mut withdrawn = allowed(transition(EvidenceScope::Encapsulation));
    withdrawn.destination_evidence = EvidenceApplicability::Missing;
    gate.advance(ExecutionContextChange::Evidence, withdrawn)
        .unwrap();
    let client = established(HPKE_ML_KEM_768, ProtocolRole::Client);
    let mut rng = DeterministicRng { next: 0x51 };

    let stale_result = activate_sender_guarded(
        &gate,
        stale,
        &client,
        &key_pair.public_key,
        b"guarded-hpke",
        &mut rng,
    );
    assert!(matches!(
        stale_result,
        Err(GuardedActivationError::Gate(
            ExecutionGateError::StaleContext
        ))
    ));
    assert_eq!(rng.next, 0x51, "encapsulation must not consume randomness");

    let fresh_result = activate_sender_guarded(
        &gate,
        gate.snapshot(),
        &client,
        &key_pair.public_key,
        b"guarded-hpke",
        &mut rng,
    );
    assert!(matches!(
        fresh_result,
        Err(GuardedActivationError::Gate(
            ExecutionGateError::NotPermitted(AuthorizationDecision::Defer)
        ))
    ));
    assert_eq!(
        rng.next, 0x51,
        "rejected activation must not consume randomness"
    );

    gate.advance(
        ExecutionContextChange::Evidence,
        allowed(transition(EvidenceScope::Encapsulation)),
    )
    .unwrap();
    assert!(activate_sender_guarded(
        &gate,
        gate.snapshot(),
        &client,
        &key_pair.public_key,
        b"guarded-hpke",
        &mut rng,
    )
    .is_ok());
}

#[test]
fn negotiated_capability_mismatch_fails_before_encapsulation() {
    let gate = gate(EvidenceScope::Encapsulation);
    let wrong_client = established(HPKE_ML_KEM_1024, ProtocolRole::Client);
    let mut rng = DeterministicRng { next: 0x51 };
    let result = activate_sender_guarded(
        &gate,
        gate.snapshot(),
        &wrong_client,
        &[],
        b"guarded-hpke",
        &mut rng,
    );
    assert!(matches!(
        result,
        Err(GuardedActivationError::CapabilityMismatch)
    ));
    assert_eq!(rng.next, 0x51);
}

#[test]
fn incorrect_operation_scope_fails_before_encapsulation() {
    let gate = gate(EvidenceScope::Signing);
    let client = established(HPKE_ML_KEM_768, ProtocolRole::Client);
    let mut rng = DeterministicRng { next: 0x51 };
    let result = activate_sender_guarded(
        &gate,
        gate.snapshot(),
        &client,
        &[],
        b"guarded-hpke",
        &mut rng,
    );
    assert!(matches!(
        result,
        Err(GuardedActivationError::OperationMismatch)
    ));
    assert_eq!(rng.next, 0x51);
}

#[test]
fn withdrawn_evidence_prevents_receiver_decapsulation() {
    let mut gate = gate(EvidenceScope::Decapsulation);
    let mut withdrawn = allowed(transition(EvidenceScope::Decapsulation));
    withdrawn.destination_evidence = EvidenceApplicability::Missing;
    gate.advance(ExecutionContextChange::Evidence, withdrawn)
        .unwrap();

    let server = established(HPKE_ML_KEM_768, ProtocolRole::Server);
    // Empty inputs would fail at the HPKE layer if the gate ran the operation.
    let result =
        activate_receiver_guarded(&gate, gate.snapshot(), &server, &[], &[], b"guarded-hpke");
    assert!(matches!(
        result,
        Err(GuardedActivationError::Gate(
            ExecutionGateError::NotPermitted(AuthorizationDecision::Defer)
        ))
    ));
}
