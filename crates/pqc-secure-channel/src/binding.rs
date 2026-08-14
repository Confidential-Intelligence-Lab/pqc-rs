//! Canonical cryptographic binding for negotiated secure channels.

use pqc_protocol::{CapabilityId, EstablishedProtocolContext, ProtocolId, ProtocolVersion};

/// Domain separator for PQC-rs secure-channel HPKE context binding.
pub const SECURE_CHANNEL_BINDING_DOMAIN: &[u8; 14] = b"PQC-RS-SC-BIND";

/// Version of the canonical secure-channel binding encoding.
pub const SECURE_CHANNEL_BINDING_VERSION: u8 = 1;

/// Number of bytes before the application-context payload.
pub const SECURE_CHANNEL_BINDING_HEADER_LEN: usize = 31;

/// Canonical peer-agreed context bound into the HPKE key schedule.
///
/// The binding contains only values that must agree at both protocol
/// endpoints: protocol identifier, protocol version, negotiated capability,
/// and an application-supplied context.
///
/// Endpoint-local session identifiers, participant roles, and policy
/// identifiers are intentionally excluded because independently established
/// peers may legitimately hold different values for those fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureChannelBinding {
    bytes: Vec<u8>,
}

impl SecureChannelBinding {
    /// Construct the canonical binding for an established protocol context.
    ///
    /// The application context is length-delimited and may be empty.
    ///
    /// # Panics
    ///
    /// Panics only on platforms where `usize` cannot be represented as `u64`.
    /// Such platforms are not supported by this encoding.
    pub fn new(established: &EstablishedProtocolContext, application_context: &[u8]) -> Self {
        Self::from_shared_values(
            established.session().protocol_id(),
            established.session().protocol_version(),
            established.capability(),
            application_context,
        )
    }

    /// Return the canonical bytes supplied to the HPKE key schedule.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn from_shared_values(
        protocol_id: ProtocolId,
        protocol_version: ProtocolVersion,
        capability: CapabilityId,
        application_context: &[u8],
    ) -> Self {
        let application_context_len = u64::try_from(application_context.len())
            .expect("application context length exceeds u64");

        let mut bytes =
            Vec::with_capacity(SECURE_CHANNEL_BINDING_HEADER_LEN + application_context.len());

        bytes.extend_from_slice(SECURE_CHANNEL_BINDING_DOMAIN);
        bytes.push(SECURE_CHANNEL_BINDING_VERSION);
        bytes.extend_from_slice(&protocol_id.value().to_be_bytes());
        bytes.extend_from_slice(&protocol_version.major().to_be_bytes());
        bytes.extend_from_slice(&protocol_version.minor().to_be_bytes());
        bytes.extend_from_slice(&capability.value().to_be_bytes());
        bytes.extend_from_slice(&application_context_len.to_be_bytes());
        bytes.extend_from_slice(application_context);

        Self { bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqc_protocol::{
        negotiate_policy_permitted_common, CapabilityOffer, CapabilityPolicy, PolicyId,
        ProtocolRole, SessionId, TypedProtocolSession,
    };

    fn established(
        session_byte: u8,
        role: ProtocolRole,
        policy_id: PolicyId,
        protocol_id: ProtocolId,
        version: ProtocolVersion,
        capability: CapabilityId,
    ) -> EstablishedProtocolContext {
        let local_ids = [capability];
        let peer_ids = [capability];
        let allowed = [capability];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(policy_id, &allowed).unwrap();

        let negotiated = negotiate_policy_permitted_common(local, peer, policy).unwrap();

        TypedProtocolSession::new(
            SessionId::from_bytes([session_byte; 16]),
            protocol_id,
            version,
            role,
        )
        .begin_establishment()
        .establish_with_negotiation(negotiated)
    }

    #[test]
    fn canonical_encoding_is_exact() {
        let context = established(
            0x41,
            ProtocolRole::Client,
            PolicyId::new(31),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 2),
            CapabilityId::new(0x0103),
        );

        let binding = SecureChannelBinding::new(&context, b"app");

        let mut expected = Vec::new();
        expected.extend_from_slice(b"PQC-RS-SC-BIND");
        expected.push(1);
        expected.extend_from_slice(&0x1300_u16.to_be_bytes());
        expected.extend_from_slice(&1_u16.to_be_bytes());
        expected.extend_from_slice(&2_u16.to_be_bytes());
        expected.extend_from_slice(&0x0103_u16.to_be_bytes());
        expected.extend_from_slice(&3_u64.to_be_bytes());
        expected.extend_from_slice(b"app");

        assert_eq!(binding.as_bytes(), expected);
        assert_eq!(
            binding.as_bytes().len(),
            SECURE_CHANNEL_BINDING_HEADER_LEN + 3
        );
    }

    #[test]
    fn endpoint_local_metadata_does_not_change_binding() {
        let client = established(
            0x41,
            ProtocolRole::Client,
            PolicyId::new(31),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            CapabilityId::new(8),
        );

        let server = established(
            0x42,
            ProtocolRole::Server,
            PolicyId::new(32),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            CapabilityId::new(8),
        );

        assert_ne!(client.session().session_id(), server.session().session_id());
        assert_ne!(client.session().role(), server.session().role());
        assert_ne!(client.policy_id(), server.policy_id());

        assert_eq!(
            SecureChannelBinding::new(&client, b"application"),
            SecureChannelBinding::new(&server, b"application")
        );
    }

    #[test]
    fn protocol_id_changes_binding() {
        let first = established(
            0x41,
            ProtocolRole::Client,
            PolicyId::new(1),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            CapabilityId::new(8),
        );

        let second = established(
            0x41,
            ProtocolRole::Client,
            PolicyId::new(1),
            ProtocolId::new(0x1301),
            ProtocolVersion::new(1, 0),
            CapabilityId::new(8),
        );

        assert_ne!(
            SecureChannelBinding::new(&first, b"app"),
            SecureChannelBinding::new(&second, b"app")
        );
    }

    #[test]
    fn protocol_version_changes_binding() {
        let first = established(
            0x41,
            ProtocolRole::Client,
            PolicyId::new(1),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            CapabilityId::new(8),
        );

        let second = established(
            0x41,
            ProtocolRole::Client,
            PolicyId::new(1),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 1),
            CapabilityId::new(8),
        );

        assert_ne!(
            SecureChannelBinding::new(&first, b"app"),
            SecureChannelBinding::new(&second, b"app")
        );
    }

    #[test]
    fn capability_changes_binding() {
        let first = established(
            0x41,
            ProtocolRole::Client,
            PolicyId::new(1),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            CapabilityId::new(8),
        );

        let second = established(
            0x41,
            ProtocolRole::Client,
            PolicyId::new(1),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            CapabilityId::new(9),
        );

        assert_ne!(
            SecureChannelBinding::new(&first, b"app"),
            SecureChannelBinding::new(&second, b"app")
        );
    }

    #[test]
    fn application_context_changes_binding() {
        let context = established(
            0x41,
            ProtocolRole::Client,
            PolicyId::new(1),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            CapabilityId::new(8),
        );

        assert_ne!(
            SecureChannelBinding::new(&context, b"application-a"),
            SecureChannelBinding::new(&context, b"application-b")
        );
    }

    #[test]
    fn application_context_is_length_delimited() {
        let context = established(
            0x41,
            ProtocolRole::Client,
            PolicyId::new(1),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            CapabilityId::new(8),
        );

        let empty = SecureChannelBinding::new(&context, b"");
        let nonempty = SecureChannelBinding::new(&context, b"\0");

        assert_ne!(empty, nonempty);
        assert_eq!(empty.as_bytes().len(), SECURE_CHANNEL_BINDING_HEADER_LEN);
        assert_eq!(
            nonempty.as_bytes().len(),
            SECURE_CHANNEL_BINDING_HEADER_LEN + 1
        );
    }
}
