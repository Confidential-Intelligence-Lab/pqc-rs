use pqc_authentication::{
    prove_authentication_deterministic, AuthenticationError, AuthenticationVerifier,
};
use pqc_ml_dsa::{MlDsa, MlDsaKeyGenSeed, MlDsaParameterSet};
use pqc_protocol::{
    negotiate_policy_permitted_common, CapabilityOffer, CapabilityPolicy,
    EstablishedProtocolContext, PolicyId, ProtocolId, ProtocolRole, ProtocolVersion, SessionId,
    TypedProtocolSession, AUTH_ML_DSA_65,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};

const APPLICATION_CONTEXT: &[u8] = b"pqc-forge/reference-authentication";

#[derive(Debug)]
struct TestRng {
    next: u8,
}

impl TestRng {
    const fn new(next: u8) -> Self {
        Self { next }
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

fn established_context() -> EstablishedProtocolContext {
    let ids = [AUTH_ML_DSA_65];

    let local = CapabilityOffer::new(&ids).unwrap();
    let peer = CapabilityOffer::new(&ids).unwrap();
    let policy = CapabilityPolicy::new(PolicyId::new(0x0201), &ids).unwrap();

    let negotiated = negotiate_policy_permitted_common(local, peer, policy).unwrap();

    TypedProtocolSession::new(
        SessionId::from_bytes([0x41; 16]),
        ProtocolId::new(0x0200),
        ProtocolVersion::new(1, 0),
        ProtocolRole::Client,
    )
    .begin_establishment()
    .establish_with_negotiation(negotiated)
}

fn key_pair(seed_byte: u8) -> pqc_ml_dsa::MlDsaKeyPair {
    let implementation = MlDsa::new(MlDsaParameterSet::MlDsa65);
    let seed = MlDsaKeyGenSeed::from_bytes(MlDsaParameterSet::MlDsa65, [seed_byte; 32]);
    implementation.keygen_from_seed(&seed).unwrap()
}

#[test]
fn verifier_issues_fresh_challenges() {
    let established = established_context();
    let keys = key_pair(0x61);
    let verifier =
        AuthenticationVerifier::new(&established, keys.public_key(), APPLICATION_CONTEXT);
    let mut rng = TestRng::new(0x10);

    let first = verifier.issue_challenge(&mut rng);
    let second = verifier.issue_challenge(&mut rng);

    assert_ne!(first.challenge(), second.challenge());
}

#[test]
fn complete_challenge_response_authenticates() {
    let established = established_context();
    let keys = key_pair(0x61);
    let verifier =
        AuthenticationVerifier::new(&established, keys.public_key(), APPLICATION_CONTEXT);
    let mut rng = TestRng::new(0x10);

    let pending = verifier.issue_challenge(&mut rng);

    let proof = prove_authentication_deterministic(
        &established,
        pending.challenge(),
        APPLICATION_CONTEXT,
        keys.private_key(),
    )
    .unwrap();

    pending.verify(&proof).unwrap();
}

#[test]
fn proof_for_different_challenge_is_rejected() {
    let established = established_context();
    let keys = key_pair(0x61);
    let verifier =
        AuthenticationVerifier::new(&established, keys.public_key(), APPLICATION_CONTEXT);
    let mut rng = TestRng::new(0x10);

    let first = verifier.issue_challenge(&mut rng);
    let second = verifier.issue_challenge(&mut rng);

    let proof = prove_authentication_deterministic(
        &established,
        first.challenge(),
        APPLICATION_CONTEXT,
        keys.private_key(),
    )
    .unwrap();

    assert_eq!(
        second.verify(&proof),
        Err(AuthenticationError::InvalidProof)
    );
}

#[test]
fn proof_from_wrong_key_is_rejected() {
    let established = established_context();
    let expected = key_pair(0x61);
    let attacker = key_pair(0x62);
    let verifier =
        AuthenticationVerifier::new(&established, expected.public_key(), APPLICATION_CONTEXT);
    let mut rng = TestRng::new(0x10);

    let pending = verifier.issue_challenge(&mut rng);

    let proof = prove_authentication_deterministic(
        &established,
        pending.challenge(),
        APPLICATION_CONTEXT,
        attacker.private_key(),
    )
    .unwrap();

    assert_eq!(
        pending.verify(&proof),
        Err(AuthenticationError::InvalidProof)
    );
}

#[test]
fn proof_from_wrong_application_context_is_rejected() {
    let established = established_context();
    let keys = key_pair(0x61);
    let verifier =
        AuthenticationVerifier::new(&established, keys.public_key(), APPLICATION_CONTEXT);
    let mut rng = TestRng::new(0x10);

    let pending = verifier.issue_challenge(&mut rng);

    let proof = prove_authentication_deterministic(
        &established,
        pending.challenge(),
        b"pqc-forge/wrong-context",
        keys.private_key(),
    )
    .unwrap();

    assert_eq!(
        pending.verify(&proof),
        Err(AuthenticationError::InvalidProof)
    );
}
