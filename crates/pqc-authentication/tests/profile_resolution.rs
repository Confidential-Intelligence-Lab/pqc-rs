use pqc_authentication::{
    resolve_authentication_profile, AuthenticationError, AuthenticationProfile,
};
use pqc_ml_dsa::MlDsaParameterSet;
use pqc_protocol::{
    negotiate_policy_permitted_common, CapabilityId, CapabilityOffer, CapabilityPolicy,
    EstablishedProtocolContext, PolicyId, ProtocolId, ProtocolRole, ProtocolVersion, SessionId,
    TypedProtocolSession, AUTH_ML_DSA_65, HPKE_ML_KEM_768,
};

fn established_context(capability: CapabilityId) -> EstablishedProtocolContext {
    let local_ids = [capability];
    let peer_ids = [capability];
    let allowed_ids = [capability];

    let local = CapabilityOffer::new(&local_ids).expect("local offer must be valid");
    let peer = CapabilityOffer::new(&peer_ids).expect("peer offer must be valid");
    let policy =
        CapabilityPolicy::new(PolicyId::new(0x0201), &allowed_ids).expect("policy must be valid");

    let negotiated =
        negotiate_policy_permitted_common(local, peer, policy).expect("capability must negotiate");

    TypedProtocolSession::new(
        SessionId::from_bytes([0x41; 16]),
        ProtocolId::new(0x0200),
        ProtocolVersion::new(1, 0),
        ProtocolRole::Client,
    )
    .begin_establishment()
    .establish_with_negotiation(negotiated)
}

#[test]
fn negotiated_ml_dsa_65_resolves_exactly() {
    let context = established_context(AUTH_ML_DSA_65);

    assert_eq!(
        resolve_authentication_profile(&context),
        Ok(AuthenticationProfile::MlDsa65)
    );
}

#[test]
fn ml_dsa_65_profile_maps_to_expected_parameter_set() {
    assert_eq!(
        AuthenticationProfile::MlDsa65.parameter_set(),
        MlDsaParameterSet::MlDsa65
    );
}

#[test]
fn unrelated_secure_channel_capability_is_rejected() {
    let context = established_context(HPKE_ML_KEM_768);

    assert_eq!(
        resolve_authentication_profile(&context),
        Err(AuthenticationError::UnsupportedCapability {
            capability: HPKE_ML_KEM_768,
        })
    );
}

#[test]
fn authentication_resolution_preserves_negotiated_evidence_boundary() {
    let context = established_context(AUTH_ML_DSA_65);

    assert_eq!(context.capability(), AUTH_ML_DSA_65);
    assert_eq!(
        resolve_authentication_profile(&context),
        Ok(AuthenticationProfile::MlDsa65)
    );
}
