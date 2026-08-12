//! Protocol-specific capability-handshake orchestration state.

use crate::{
    negotiate_decoded_policy_permitted_common, CapabilityOffer, CapabilityPolicy,
    CapabilityRejectionPayload, CapabilityRejectionReason, CapabilitySelectionPayload,
    DecodedCapabilityOffer, HandlerAction, HandlerOutcome, MessageClass, MessageId,
    NegotiatedCapability, OutboundResponse, ProtocolDirection, ProtocolEncode, ProtocolError,
    ProtocolFrame, ProtocolHandler, ProtocolResponder, CAPABILITY_OFFER_MESSAGE_ID,
    CAPABILITY_REJECTION_MESSAGE_ID, CAPABILITY_SELECTION_MESSAGE_ID,
};

/// Error produced by server-side capability-handshake orchestration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerHandshakeError {
    /// The requested operation is not valid in the current handshake state.
    InvalidState,
    /// The inbound frame carries an unexpected message identifier.
    UnexpectedMessage {
        /// Message identifier received from the peer.
        message_id: MessageId,
    },
    /// The inbound frame is not classified as a handshake message.
    UnexpectedMessageClass {
        /// Message class received from the peer.
        message_class: MessageClass,
    },
    /// The inbound frame has an invalid logical direction for a server offer.
    UnexpectedDirection {
        /// Direction received from the peer.
        direction: ProtocolDirection,
    },
    /// Canonical handshake payload processing failed.
    Protocol(ProtocolError),
}

impl core::fmt::Display for ServerHandshakeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidState => formatter.write_str("invalid server handshake state"),
            Self::UnexpectedMessage { .. } => {
                formatter.write_str("unexpected server handshake message")
            }
            Self::UnexpectedMessageClass { .. } => {
                formatter.write_str("unexpected server handshake message class")
            }
            Self::UnexpectedDirection { .. } => {
                formatter.write_str("unexpected server handshake direction")
            }
            Self::Protocol(error) => {
                write!(formatter, "server handshake protocol failure: {error}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ServerHandshakeError {}

/// Server-side capability-handshake state.
///
/// Receiving an offer may produce pending selection or rejection state, but
/// does not establish the protocol session. Successful response construction
/// advances pending state to the corresponding emitted state.
///
/// Establishment remains a separate evidence-consuming operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerHandshakeState {
    /// The server is waiting for the client's capability offer.
    AwaitingOffer,
    /// A negotiated capability is waiting to be emitted to the client.
    SelectionPending(NegotiatedCapability),
    /// The negotiated capability has been encoded as a server response.
    SelectionEmitted(NegotiatedCapability),
    /// A negotiation rejection is waiting to be emitted to the client.
    RejectionPending(CapabilityRejectionReason),
    /// The negotiation rejection has been encoded as a server response.
    RejectionEmitted(CapabilityRejectionReason),
}

/// Server-side capability-handshake orchestrator.
///
/// The server retains its validated local capability offer and resolved local
/// policy. Inbound peer offers are decoded and negotiated immediately; the
/// borrowed decoded offer is not retained after frame processing.
///
/// This state machine performs no transport I/O, session establishment,
/// provider resolution, or cryptographic execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerCapabilityHandshake<'a> {
    local_offer: CapabilityOffer<'a>,
    policy: CapabilityPolicy<'a>,
    state: ServerHandshakeState,
}

impl<'a> ServerCapabilityHandshake<'a> {
    /// Construct a server handshake awaiting the client's offer.
    pub const fn new(local_offer: CapabilityOffer<'a>, policy: CapabilityPolicy<'a>) -> Self {
        Self {
            local_offer,
            policy,
            state: ServerHandshakeState::AwaitingOffer,
        }
    }

    /// Return the current server handshake state.
    pub const fn state(&self) -> ServerHandshakeState {
        self.state
    }

    /// Return the server's validated local capability offer.
    pub const fn local_offer(&self) -> CapabilityOffer<'a> {
        self.local_offer
    }

    /// Return the server's resolved local capability policy.
    pub const fn policy(&self) -> CapabilityPolicy<'a> {
        self.policy
    }

    /// Return negotiated evidence waiting to be emitted, if present.
    pub const fn pending_negotiated(&self) -> Option<NegotiatedCapability> {
        match self.state {
            ServerHandshakeState::SelectionPending(negotiated) => Some(negotiated),
            _ => None,
        }
    }

    /// Return negotiated evidence already emitted, if present.
    pub const fn emitted_negotiated(&self) -> Option<NegotiatedCapability> {
        match self.state {
            ServerHandshakeState::SelectionEmitted(negotiated) => Some(negotiated),
            _ => None,
        }
    }

    /// Return the pending or emitted rejection reason, if present.
    pub const fn rejection_reason(&self) -> Option<CapabilityRejectionReason> {
        match self.state {
            ServerHandshakeState::RejectionPending(reason)
            | ServerHandshakeState::RejectionEmitted(reason) => Some(reason),
            _ => None,
        }
    }
}

impl ProtocolHandler for ServerCapabilityHandshake<'_> {
    type Error = ServerHandshakeError;

    fn handle_frame(&mut self, frame: &ProtocolFrame<'_>) -> Result<HandlerOutcome, Self::Error> {
        if self.state != ServerHandshakeState::AwaitingOffer {
            return Err(ServerHandshakeError::InvalidState);
        }

        let header = frame.header();

        if header.message_id() != CAPABILITY_OFFER_MESSAGE_ID {
            return Err(ServerHandshakeError::UnexpectedMessage {
                message_id: header.message_id(),
            });
        }

        if header.message_class() != MessageClass::Handshake {
            return Err(ServerHandshakeError::UnexpectedMessageClass {
                message_class: header.message_class(),
            });
        }

        if header.direction() != ProtocolDirection::ClientToServer {
            return Err(ServerHandshakeError::UnexpectedDirection {
                direction: header.direction(),
            });
        }

        let peer = DecodedCapabilityOffer::decode_exact(frame.payload())
            .map_err(ServerHandshakeError::Protocol)?;

        if let Some(negotiated) =
            negotiate_decoded_policy_permitted_common(self.local_offer, peer, self.policy)
        {
            self.state = ServerHandshakeState::SelectionPending(negotiated);
        } else {
            let reason = rejection_reason(self.local_offer, peer);
            self.state = ServerHandshakeState::RejectionPending(reason);
        }

        Ok(HandlerOutcome::new(HandlerAction::Respond))
    }
}

impl ProtocolResponder for ServerCapabilityHandshake<'_> {
    type Error = ServerHandshakeError;

    fn write_response<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<OutboundResponse<'a>, Self::Error> {
        match self.state {
            ServerHandshakeState::SelectionPending(negotiated) => {
                let payload = CapabilitySelectionPayload::new(negotiated.capability());
                let written = payload
                    .encode_into(output)
                    .map_err(ServerHandshakeError::Protocol)?;

                self.state = ServerHandshakeState::SelectionEmitted(negotiated);

                Ok(OutboundResponse::new(
                    CAPABILITY_SELECTION_MESSAGE_ID,
                    MessageClass::Handshake,
                    &output[..written],
                ))
            }
            ServerHandshakeState::RejectionPending(reason) => {
                let payload = CapabilityRejectionPayload::new(reason);
                let written = payload
                    .encode_into(output)
                    .map_err(ServerHandshakeError::Protocol)?;

                self.state = ServerHandshakeState::RejectionEmitted(reason);

                Ok(OutboundResponse::new(
                    CAPABILITY_REJECTION_MESSAGE_ID,
                    MessageClass::Handshake,
                    &output[..written],
                ))
            }
            _ => Err(ServerHandshakeError::InvalidState),
        }
    }
}

fn rejection_reason(
    local: CapabilityOffer<'_>,
    peer: DecodedCapabilityOffer<'_>,
) -> CapabilityRejectionReason {
    let capabilities = local.capabilities();
    let mut index = 0;

    while index < capabilities.len() {
        if peer.contains(capabilities[index]) {
            return CapabilityRejectionReason::PolicyRejected;
        }

        index += 1;
    }

    CapabilityRejectionReason::NoCommonCapability
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CapabilityId, CapabilityOfferPayload, MemoryTransport, PolicyId, ProtocolDriver,
        ProtocolId, ProtocolRole, ProtocolSession, ProtocolVersion, SessionId, SessionState,
    };

    fn local_ids() -> [CapabilityId; 3] {
        [
            CapabilityId::new(10),
            CapabilityId::new(20),
            CapabilityId::new(30),
        ]
    }

    fn allowed_ids() -> [CapabilityId; 2] {
        [CapabilityId::new(20), CapabilityId::new(30)]
    }

    fn server<'a>(
        local: &'a [CapabilityId],
        allowed: &'a [CapabilityId],
    ) -> ServerCapabilityHandshake<'a> {
        ServerCapabilityHandshake::new(
            CapabilityOffer::new(local).unwrap(),
            CapabilityPolicy::new(PolicyId::new(7), allowed).unwrap(),
        )
    }

    fn encode_offer(capabilities: &[CapabilityId], output: &mut [u8]) -> usize {
        let offer = CapabilityOffer::new(capabilities).unwrap();
        CapabilityOfferPayload::new(offer)
            .unwrap()
            .encode_into(output)
            .unwrap()
    }

    fn frame<'a>(
        message_id: MessageId,
        message_class: MessageClass,
        direction: ProtocolDirection,
        payload: &'a [u8],
    ) -> ProtocolFrame<'a> {
        ProtocolFrame::current(
            ProtocolVersion::new(1, 0),
            ProtocolId::new(0x1300),
            message_id,
            message_class,
            direction,
            payload,
        )
        .unwrap()
    }

    #[test]
    fn valid_offer_moves_server_to_selection_pending() {
        let local = local_ids();
        let allowed = allowed_ids();
        let peer = [CapabilityId::new(30), CapabilityId::new(20)];
        let mut payload = [0_u8; 6];
        let length = encode_offer(&peer, &mut payload);
        let inbound = frame(
            CAPABILITY_OFFER_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ClientToServer,
            &payload[..length],
        );
        let mut handshake = server(&local, &allowed);

        let outcome = handshake.handle_frame(&inbound).unwrap();

        assert_eq!(outcome, HandlerOutcome::new(HandlerAction::Respond));
        assert_eq!(outcome.requested_transition(), None);

        let negotiated = handshake.pending_negotiated().unwrap();
        assert_eq!(negotiated.policy_id(), PolicyId::new(7));
        assert_eq!(negotiated.capability(), CapabilityId::new(20));
    }

    #[test]
    fn peer_order_does_not_override_server_local_preference() {
        let local = [
            CapabilityId::new(10),
            CapabilityId::new(20),
            CapabilityId::new(30),
        ];
        let allowed = local;
        let peer = [
            CapabilityId::new(30),
            CapabilityId::new(20),
            CapabilityId::new(10),
        ];
        let mut payload = [0_u8; 8];
        let length = encode_offer(&peer, &mut payload);
        let inbound = frame(
            CAPABILITY_OFFER_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ClientToServer,
            &payload[..length],
        );
        let mut handshake = server(&local, &allowed);

        handshake.handle_frame(&inbound).unwrap();

        assert_eq!(
            handshake.pending_negotiated().unwrap().capability(),
            CapabilityId::new(10)
        );
    }

    #[test]
    fn no_common_capability_moves_server_to_no_common_rejection() {
        let local = local_ids();
        let allowed = allowed_ids();
        let peer = [CapabilityId::new(100), CapabilityId::new(200)];
        let mut payload = [0_u8; 6];
        let length = encode_offer(&peer, &mut payload);
        let inbound = frame(
            CAPABILITY_OFFER_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ClientToServer,
            &payload[..length],
        );
        let mut handshake = server(&local, &allowed);

        handshake.handle_frame(&inbound).unwrap();

        assert_eq!(
            handshake.state(),
            ServerHandshakeState::RejectionPending(CapabilityRejectionReason::NoCommonCapability)
        );
    }

    #[test]
    fn policy_exclusion_moves_server_to_policy_rejection() {
        let local = local_ids();
        let allowed = [CapabilityId::new(30)];
        let peer = [CapabilityId::new(10), CapabilityId::new(20)];
        let mut payload = [0_u8; 6];
        let length = encode_offer(&peer, &mut payload);
        let inbound = frame(
            CAPABILITY_OFFER_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ClientToServer,
            &payload[..length],
        );
        let mut handshake = server(&local, &allowed);

        handshake.handle_frame(&inbound).unwrap();

        assert_eq!(
            handshake.state(),
            ServerHandshakeState::RejectionPending(CapabilityRejectionReason::PolicyRejected)
        );
    }

    #[test]
    fn malformed_offer_is_rejected_without_changing_state() {
        let local = local_ids();
        let allowed = allowed_ids();
        let malformed = [0x00, 0x02, 0x00, 0x01];
        let inbound = frame(
            CAPABILITY_OFFER_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ClientToServer,
            &malformed,
        );
        let mut handshake = server(&local, &allowed);

        assert_eq!(
            handshake.handle_frame(&inbound),
            Err(ServerHandshakeError::Protocol(ProtocolError::UnexpectedEnd))
        );
        assert_eq!(handshake.state(), ServerHandshakeState::AwaitingOffer);
    }

    #[test]
    fn unexpected_message_is_rejected_without_changing_state() {
        let local = local_ids();
        let allowed = allowed_ids();
        let inbound = frame(
            CAPABILITY_SELECTION_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ClientToServer,
            &[],
        );
        let mut handshake = server(&local, &allowed);

        assert_eq!(
            handshake.handle_frame(&inbound),
            Err(ServerHandshakeError::UnexpectedMessage {
                message_id: CAPABILITY_SELECTION_MESSAGE_ID,
            })
        );
        assert_eq!(handshake.state(), ServerHandshakeState::AwaitingOffer);
    }

    #[test]
    fn unexpected_class_and_direction_are_rejected() {
        let local = local_ids();
        let allowed = allowed_ids();
        let empty_offer = [0x00, 0x00];

        let mut handshake = server(&local, &allowed);
        let wrong_class = frame(
            CAPABILITY_OFFER_MESSAGE_ID,
            MessageClass::Application,
            ProtocolDirection::ClientToServer,
            &empty_offer,
        );

        assert!(matches!(
            handshake.handle_frame(&wrong_class),
            Err(ServerHandshakeError::UnexpectedMessageClass { .. })
        ));
        assert_eq!(handshake.state(), ServerHandshakeState::AwaitingOffer);

        let wrong_direction = frame(
            CAPABILITY_OFFER_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ServerToClient,
            &empty_offer,
        );

        assert!(matches!(
            handshake.handle_frame(&wrong_direction),
            Err(ServerHandshakeError::UnexpectedDirection { .. })
        ));
        assert_eq!(handshake.state(), ServerHandshakeState::AwaitingOffer);
    }

    #[test]
    fn selection_responder_emits_canonical_selection_and_advances_state() {
        let local = local_ids();
        let allowed = allowed_ids();
        let peer = [CapabilityId::new(20)];
        let mut offer_payload = [0_u8; 4];
        let length = encode_offer(&peer, &mut offer_payload);
        let inbound = frame(
            CAPABILITY_OFFER_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ClientToServer,
            &offer_payload[..length],
        );
        let mut handshake = server(&local, &allowed);

        handshake.handle_frame(&inbound).unwrap();

        let negotiated = handshake.pending_negotiated().unwrap();
        let mut output = [0_u8; 2];
        let response = handshake.write_response(&mut output).unwrap();

        assert_eq!(response.message_id(), CAPABILITY_SELECTION_MESSAGE_ID);
        assert_eq!(response.message_class(), MessageClass::Handshake);
        assert_eq!(response.payload(), &[0x00, 0x14]);
        assert_eq!(
            handshake.state(),
            ServerHandshakeState::SelectionEmitted(negotiated)
        );
        assert_eq!(handshake.emitted_negotiated(), Some(negotiated));
    }

    #[test]
    fn rejection_responder_emits_canonical_rejection_and_advances_state() {
        let local = local_ids();
        let allowed = allowed_ids();
        let peer = [CapabilityId::new(99)];
        let mut offer_payload = [0_u8; 4];
        let length = encode_offer(&peer, &mut offer_payload);
        let inbound = frame(
            CAPABILITY_OFFER_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ClientToServer,
            &offer_payload[..length],
        );
        let mut handshake = server(&local, &allowed);

        handshake.handle_frame(&inbound).unwrap();

        let mut output = [0_u8; 2];
        let response = handshake.write_response(&mut output).unwrap();

        assert_eq!(response.message_id(), CAPABILITY_REJECTION_MESSAGE_ID);
        assert_eq!(response.message_class(), MessageClass::Handshake);
        assert_eq!(response.payload(), &[0x00, 0x01]);
        assert_eq!(
            handshake.state(),
            ServerHandshakeState::RejectionEmitted(CapabilityRejectionReason::NoCommonCapability)
        );
    }

    #[test]
    fn short_response_buffer_preserves_pending_state() {
        let local = local_ids();
        let allowed = allowed_ids();
        let peer = [CapabilityId::new(20)];
        let mut offer_payload = [0_u8; 4];
        let length = encode_offer(&peer, &mut offer_payload);
        let inbound = frame(
            CAPABILITY_OFFER_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ClientToServer,
            &offer_payload[..length],
        );
        let mut handshake = server(&local, &allowed);

        handshake.handle_frame(&inbound).unwrap();

        let before = handshake.state();
        let mut output = [0_u8; 1];

        assert_eq!(
            handshake.write_response(&mut output),
            Err(ServerHandshakeError::Protocol(
                ProtocolError::BufferTooSmall {
                    required: 2,
                    available: 1,
                }
            ))
        );
        assert_eq!(handshake.state(), before);
    }

    #[test]
    fn response_is_invalid_before_offer_and_after_successful_emission() {
        let local = local_ids();
        let allowed = allowed_ids();
        let mut handshake = server(&local, &allowed);
        let mut output = [0_u8; 2];

        assert_eq!(
            handshake.write_response(&mut output),
            Err(ServerHandshakeError::InvalidState)
        );

        let peer = [CapabilityId::new(20)];
        let mut offer_payload = [0_u8; 4];
        let length = encode_offer(&peer, &mut offer_payload);
        let inbound = frame(
            CAPABILITY_OFFER_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ClientToServer,
            &offer_payload[..length],
        );

        handshake.handle_frame(&inbound).unwrap();
        handshake.write_response(&mut output).unwrap();

        assert_eq!(
            handshake.write_response(&mut output),
            Err(ServerHandshakeError::InvalidState)
        );
    }

    #[test]
    fn driver_handling_valid_offer_does_not_establish_runtime_session() {
        let local = local_ids();
        let allowed = allowed_ids();
        let peer = [CapabilityId::new(20)];
        let mut offer_payload = [0_u8; 4];
        let length = encode_offer(&peer, &mut offer_payload);
        let inbound = frame(
            CAPABILITY_OFFER_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ClientToServer,
            &offer_payload[..length],
        );

        let mut session = ProtocolSession::new(
            SessionId::from_bytes([0x5a; 16]),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Server,
        );
        session.transition_to(SessionState::Establishing).unwrap();

        let transport = MemoryTransport::<16>::new(16).unwrap();
        let mut driver = ProtocolDriver::new(transport, session);
        let mut handshake = server(&local, &allowed);

        let outcome = driver.handle_frame(&mut handshake, &inbound).unwrap();

        assert_eq!(outcome, HandlerOutcome::new(HandlerAction::Respond));
        assert_eq!(outcome.requested_transition(), None);
        assert_eq!(driver.session().state(), SessionState::Establishing);
        assert!(handshake.pending_negotiated().is_some());
    }
}
