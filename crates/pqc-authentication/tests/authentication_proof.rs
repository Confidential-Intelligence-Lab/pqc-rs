use pqc_authentication::{
    authentication_transcript, prove_authentication_deterministic, verify_authentication,
    AuthenticationChallenge, AuthenticationError, MAX_APPLICATION_CONTEXT_BYTES,
};
use pqc_ml_dsa::{MlDsa, MlDsaKeyGenSeed, MlDsaParameterSet};
use pqc_protocol::{
    negotiate_policy_permitted_common, CapabilityOffer, CapabilityPolicy,
    EstablishedProtocolContext, PolicyId, ProtocolId, ProtocolRole, ProtocolVersion, SessionId,
    TypedProtocolSession, AUTH_ML_DSA_65,
};

const APPLICATION_CONTEXT: &[u8] = b"pqc-forge/test-authentication";

fn established_context(session_byte: u8, policy_id: u16) -> EstablishedProtocolContext {
    let ids = [AUTH_ML_DSA_65];

    let local = CapabilityOffer::new(&ids).unwrap();
    let peer = CapabilityOffer::new(&ids).unwrap();
    let policy = CapabilityPolicy::new(PolicyId::new(policy_id), &ids).unwrap();

    let negotiated = negotiate_policy_permitted_common(local, peer, policy).unwrap();

    TypedProtocolSession::new(
        SessionId::from_bytes([session_byte; 16]),
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
fn canonical_transcript_is_deterministic() {
    let established = established_context(0x41, 0x0201);
    let challenge = AuthenticationChallenge::from_bytes([0x51; 32]);

    let first = authentication_transcript(&established, &challenge, APPLICATION_CONTEXT);
    let second = authentication_transcript(&established, &challenge, APPLICATION_CONTEXT);

    assert_eq!(first, second);
}

#[test]
fn valid_authentication_proof_verifies() {
    let established = established_context(0x41, 0x0201);
    let challenge = AuthenticationChallenge::from_bytes([0x51; 32]);
    let keys = key_pair(0x61);

    let proof = prove_authentication_deterministic(
        &established,
        &challenge,
        APPLICATION_CONTEXT,
        keys.private_key(),
    )
    .unwrap();

    assert!(verify_authentication(
        &established,
        &challenge,
        APPLICATION_CONTEXT,
        keys.public_key(),
        &proof,
    )
    .unwrap());
}

#[test]
fn modified_challenge_is_rejected() {
    let established = established_context(0x41, 0x0201);
    let challenge = AuthenticationChallenge::from_bytes([0x51; 32]);
    let modified = AuthenticationChallenge::from_bytes([0x52; 32]);
    let keys = key_pair(0x61);

    let proof = prove_authentication_deterministic(
        &established,
        &challenge,
        APPLICATION_CONTEXT,
        keys.private_key(),
    )
    .unwrap();

    assert!(!verify_authentication(
        &established,
        &modified,
        APPLICATION_CONTEXT,
        keys.public_key(),
        &proof,
    )
    .unwrap());
}

#[test]
fn modified_application_context_is_rejected() {
    let established = established_context(0x41, 0x0201);
    let challenge = AuthenticationChallenge::from_bytes([0x51; 32]);
    let keys = key_pair(0x61);

    let proof = prove_authentication_deterministic(
        &established,
        &challenge,
        APPLICATION_CONTEXT,
        keys.private_key(),
    )
    .unwrap();

    assert!(!verify_authentication(
        &established,
        &challenge,
        b"pqc-forge/other-application",
        keys.public_key(),
        &proof,
    )
    .unwrap());
}

#[test]
fn different_session_is_rejected() {
    let signer_context = established_context(0x41, 0x0201);
    let verifier_context = established_context(0x42, 0x0201);
    let challenge = AuthenticationChallenge::from_bytes([0x51; 32]);
    let keys = key_pair(0x61);

    let proof = prove_authentication_deterministic(
        &signer_context,
        &challenge,
        APPLICATION_CONTEXT,
        keys.private_key(),
    )
    .unwrap();

    assert!(!verify_authentication(
        &verifier_context,
        &challenge,
        APPLICATION_CONTEXT,
        keys.public_key(),
        &proof,
    )
    .unwrap());
}

#[test]
fn different_policy_evidence_is_rejected() {
    let signer_context = established_context(0x41, 0x0201);
    let verifier_context = established_context(0x41, 0x0202);
    let challenge = AuthenticationChallenge::from_bytes([0x51; 32]);
    let keys = key_pair(0x61);

    let proof = prove_authentication_deterministic(
        &signer_context,
        &challenge,
        APPLICATION_CONTEXT,
        keys.private_key(),
    )
    .unwrap();

    assert!(!verify_authentication(
        &verifier_context,
        &challenge,
        APPLICATION_CONTEXT,
        keys.public_key(),
        &proof,
    )
    .unwrap());
}

#[test]
fn wrong_public_key_is_rejected() {
    let established = established_context(0x41, 0x0201);
    let challenge = AuthenticationChallenge::from_bytes([0x51; 32]);
    let signer = key_pair(0x61);
    let other = key_pair(0x62);

    let proof = prove_authentication_deterministic(
        &established,
        &challenge,
        APPLICATION_CONTEXT,
        signer.private_key(),
    )
    .unwrap();

    assert!(!verify_authentication(
        &established,
        &challenge,
        APPLICATION_CONTEXT,
        other.public_key(),
        &proof,
    )
    .unwrap());
}

#[test]
fn canonical_transcript_encoding_is_frozen() {
    let established = established_context(0x41, 0x0201);
    let challenge = AuthenticationChallenge::from_bytes([0x51; 32]);

    let transcript = authentication_transcript(&established, &challenge, b"ctx").unwrap();

    let expected = [
        // "PQC-FORGE-AUTH-TRANSCRIPT"
        0x50, 0x51, 0x43, 0x2d, 0x46, 0x4f, 0x52, 0x47, 0x45, 0x2d, 0x41, 0x55, 0x54, 0x48, 0x2d,
        0x54, 0x52, 0x41, 0x4e, 0x53, 0x43, 0x52, 0x49, 0x50, 0x54,
        // Transcript version.
        0x01, // Session ID.
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, // Protocol ID = 0x0200.
        0x02, 0x00, // Protocol version = 1.0.
        0x00, 0x01, 0x00, 0x00, // Policy ID = 0x0201.
        0x02, 0x01, // Capability ID = AUTH_ML_DSA_65 = 0x0201.
        0x02, 0x01, // Verifier challenge.
        0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51,
        0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51,
        0x51, 0x51, // Application-context length = 3.
        0x00, 0x03, // "ctx"
        0x63, 0x74, 0x78,
    ];

    assert_eq!(transcript.as_slice(), expected.as_slice());
}

#[test]
fn maximum_application_context_is_accepted() {
    let established = established_context(0x41, 0x0201);
    let challenge = AuthenticationChallenge::from_bytes([0x51; 32]);
    let application_context = vec![0x61; MAX_APPLICATION_CONTEXT_BYTES];

    let transcript =
        authentication_transcript(&established, &challenge, &application_context).unwrap();

    assert!(transcript.ends_with(&application_context));
}

#[test]
fn oversized_application_context_is_rejected() {
    let established = established_context(0x41, 0x0201);
    let challenge = AuthenticationChallenge::from_bytes([0x51; 32]);
    let application_context = vec![0x61; MAX_APPLICATION_CONTEXT_BYTES + 1];

    assert_eq!(
        authentication_transcript(&established, &challenge, &application_context),
        Err(AuthenticationError::ApplicationContextTooLong {
            length: MAX_APPLICATION_CONTEXT_BYTES + 1,
            maximum: MAX_APPLICATION_CONTEXT_BYTES,
        })
    );
}
