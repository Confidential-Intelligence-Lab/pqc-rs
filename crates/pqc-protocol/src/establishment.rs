//! Negotiation-aware protocol establishment context.

use crate::{CapabilityId, EstablishedState, NegotiatedCapability, PolicyId, TypedProtocolSession};

/// Established protocol context bound to validated negotiation evidence.
///
/// This context owns both an established typed protocol session and the
/// [`NegotiatedCapability`] under which establishment was completed.
///
/// It does not add negotiation state to [`crate::ProtocolSession`] itself and
/// performs no transport I/O, provider resolution, cryptographic execution, or
/// wire processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EstablishedProtocolContext {
    session: TypedProtocolSession<EstablishedState>,
    negotiated: NegotiatedCapability,
}

impl EstablishedProtocolContext {
    pub(crate) const fn from_parts(
        session: TypedProtocolSession<EstablishedState>,
        negotiated: NegotiatedCapability,
    ) -> Self {
        Self {
            session,
            negotiated,
        }
    }

    /// Borrow the established typed session.
    pub const fn session(&self) -> &TypedProtocolSession<EstablishedState> {
        &self.session
    }

    /// Return the negotiated capability evidence.
    pub const fn negotiated(&self) -> NegotiatedCapability {
        self.negotiated
    }

    /// Return the policy under which the capability was negotiated.
    pub const fn policy_id(&self) -> PolicyId {
        self.negotiated.policy_id()
    }

    /// Return the negotiated capability.
    pub const fn capability(&self) -> CapabilityId {
        self.negotiated.capability()
    }

    /// Consume the context and return its owned components.
    pub fn into_parts(self) -> (TypedProtocolSession<EstablishedState>, NegotiatedCapability) {
        (self.session, self.negotiated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        negotiate_policy_permitted_common, CapabilityOffer, CapabilityPolicy, EstablishingState,
        ProtocolId, ProtocolRole, ProtocolVersion, SessionId, SessionState,
    };

    fn establishing() -> TypedProtocolSession<EstablishingState> {
        crate::TypedProtocolSession::new(
            SessionId::from_bytes([0x5a; 16]),
            ProtocolId::new(0x0100),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Client,
        )
        .begin_establishment()
    }

    fn negotiated() -> NegotiatedCapability {
        let local_ids = [
            CapabilityId::new(10),
            CapabilityId::new(20),
            CapabilityId::new(30),
        ];
        let peer_ids = [CapabilityId::new(30), CapabilityId::new(20)];
        let allowed = [CapabilityId::new(20), CapabilityId::new(30)];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(PolicyId::new(7), &allowed).unwrap();

        negotiate_policy_permitted_common(local, peer, policy).unwrap()
    }

    #[test]
    fn context_preserves_established_session() {
        let context = establishing().establish_with_negotiation(negotiated());

        assert_eq!(context.session().runtime_state(), SessionState::Established);
        assert_eq!(
            context.session().session_id(),
            SessionId::from_bytes([0x5a; 16])
        );
        assert_eq!(context.session().protocol_id(), ProtocolId::new(0x0100));
        assert_eq!(
            context.session().protocol_version(),
            ProtocolVersion::new(1, 0)
        );
        assert_eq!(context.session().role(), ProtocolRole::Client);
    }

    #[test]
    fn context_preserves_negotiation_evidence() {
        let negotiated = negotiated();
        let context = establishing().establish_with_negotiation(negotiated);

        assert_eq!(context.negotiated(), negotiated);
        assert_eq!(context.policy_id(), PolicyId::new(7));
        assert_eq!(context.capability(), CapabilityId::new(20));
    }

    #[test]
    fn into_parts_preserves_both_owned_components() {
        let negotiated = negotiated();
        let context = establishing().establish_with_negotiation(negotiated);

        let (session, recovered_negotiated) = context.into_parts();

        assert_eq!(session.runtime_state(), SessionState::Established);
        assert_eq!(session.session_id(), SessionId::from_bytes([0x5a; 16]));
        assert_eq!(recovered_negotiated, negotiated);
    }

    #[test]
    fn negotiation_aware_establishment_preserves_metadata() {
        let establishing = establishing();

        let session_id = establishing.session_id();
        let protocol_id = establishing.protocol_id();
        let protocol_version = establishing.protocol_version();
        let role = establishing.role();

        let context = establishing.establish_with_negotiation(negotiated());

        assert_eq!(context.session().session_id(), session_id);
        assert_eq!(context.session().protocol_id(), protocol_id);
        assert_eq!(context.session().protocol_version(), protocol_version);
        assert_eq!(context.session().role(), role);
    }

    #[test]
    fn plain_establishment_remains_available() {
        let established = establishing().establish();

        assert_eq!(established.runtime_state(), SessionState::Established);
    }
}

#[cfg(test)]
mod downgrade_resistance_tests {
    use crate::{
        negotiate_policy_permitted_common, CapabilityId, CapabilityOffer, CapabilityPolicy,
        PolicyId, ProtocolId, ProtocolRole, ProtocolVersion, SessionId, SessionState,
        TypedProtocolSession,
    };

    fn establish(
        local_ids: &[CapabilityId],
        peer_ids: &[CapabilityId],
        allowed: &[CapabilityId],
        policy_id: PolicyId,
    ) -> Option<crate::EstablishedProtocolContext> {
        let local = CapabilityOffer::new(local_ids).unwrap();
        let peer = CapabilityOffer::new(peer_ids).unwrap();
        let policy = CapabilityPolicy::new(policy_id, allowed).unwrap();

        let negotiated = negotiate_policy_permitted_common(local, peer, policy)?;

        let establishing = TypedProtocolSession::new(
            SessionId::from_bytes([0xa5; 16]),
            ProtocolId::new(0x1200),
            ProtocolVersion::new(1, 2),
            ProtocolRole::Client,
        )
        .begin_establishment();

        Some(establishing.establish_with_negotiation(negotiated))
    }

    #[test]
    fn adversarial_peer_order_cannot_downgrade_local_preference() {
        let local = [
            CapabilityId::new(100),
            CapabilityId::new(200),
            CapabilityId::new(300),
        ];
        let peer = [
            CapabilityId::new(300),
            CapabilityId::new(200),
            CapabilityId::new(100),
        ];
        let allowed = local;

        let context = establish(&local, &peer, &allowed, PolicyId::new(10)).unwrap();

        assert_eq!(context.capability(), CapabilityId::new(100));
    }

    #[test]
    fn adversarial_peer_order_cannot_bypass_policy_filtering() {
        let local = [
            CapabilityId::new(100),
            CapabilityId::new(200),
            CapabilityId::new(300),
        ];
        let peer = [
            CapabilityId::new(300),
            CapabilityId::new(200),
            CapabilityId::new(100),
        ];
        let allowed = [CapabilityId::new(300), CapabilityId::new(200)];

        let context = establish(&local, &peer, &allowed, PolicyId::new(11)).unwrap();

        assert_eq!(context.capability(), CapabilityId::new(200));
    }

    #[test]
    fn peer_injected_capability_cannot_be_selected() {
        let local = [CapabilityId::new(100), CapabilityId::new(200)];
        let peer = [
            CapabilityId::new(999),
            CapabilityId::new(100),
            CapabilityId::new(200),
        ];
        let allowed = [
            CapabilityId::new(999),
            CapabilityId::new(100),
            CapabilityId::new(200),
        ];

        let context = establish(&local, &peer, &allowed, PolicyId::new(12)).unwrap();

        assert_eq!(context.capability(), CapabilityId::new(100));
        assert_ne!(context.capability(), CapabilityId::new(999));
    }

    #[test]
    fn policy_forces_permitted_choice_over_stronger_common_choice() {
        let local = [
            CapabilityId::new(100),
            CapabilityId::new(200),
            CapabilityId::new(300),
        ];
        let peer = local;
        let allowed = [CapabilityId::new(300)];

        let context = establish(&local, &peer, &allowed, PolicyId::new(13)).unwrap();

        assert_eq!(context.capability(), CapabilityId::new(300));
    }

    #[test]
    fn policy_permission_cannot_create_peer_support() {
        let local = [CapabilityId::new(100), CapabilityId::new(200)];
        let peer = [CapabilityId::new(200)];
        let allowed = [CapabilityId::new(100), CapabilityId::new(200)];

        let context = establish(&local, &peer, &allowed, PolicyId::new(14)).unwrap();

        assert_eq!(context.capability(), CapabilityId::new(200));
    }

    #[test]
    fn no_three_way_intersection_prevents_established_context() {
        let local = [CapabilityId::new(100), CapabilityId::new(200)];
        let peer = [CapabilityId::new(100), CapabilityId::new(200)];
        let allowed = [CapabilityId::new(300)];

        assert!(establish(&local, &peer, &allowed, PolicyId::new(15)).is_none());
    }

    #[test]
    fn end_to_end_establishment_retains_exact_negotiation_evidence() {
        let local = [
            CapabilityId::new(100),
            CapabilityId::new(200),
            CapabilityId::new(300),
        ];
        let peer = [CapabilityId::new(300), CapabilityId::new(200)];
        let allowed = [CapabilityId::new(300), CapabilityId::new(200)];
        let policy_id = PolicyId::new(0x55);

        let context = establish(&local, &peer, &allowed, policy_id).unwrap();

        assert_eq!(context.session().runtime_state(), SessionState::Established);
        assert_eq!(
            context.session().session_id(),
            SessionId::from_bytes([0xa5; 16])
        );
        assert_eq!(context.session().protocol_id(), ProtocolId::new(0x1200));
        assert_eq!(
            context.session().protocol_version(),
            ProtocolVersion::new(1, 2)
        );
        assert_eq!(context.session().role(), ProtocolRole::Client);

        assert_eq!(context.policy_id(), policy_id);
        assert_eq!(context.capability(), CapabilityId::new(200));

        let negotiated = context.negotiated();

        assert_eq!(negotiated.policy_id(), policy_id);
        assert_eq!(negotiated.capability(), CapabilityId::new(200));
    }
}
