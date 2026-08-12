//! Protocol-specific capability-handshake orchestration state.

use crate::{
    negotiate_decoded_policy_permitted_common, validate_selected_capability, CapabilityOffer,
    CapabilityOfferPayload, CapabilityPolicy, CapabilityRejectionPayload,
    CapabilityRejectionReason, CapabilitySelectionPayload, DecodedCapabilityOffer, HandlerAction,
    HandlerOutcome, MessageClass, MessageId, NegotiatedCapability, OutboundResponse,
    ProtocolDecode, ProtocolDirection, ProtocolEncode, ProtocolError, ProtocolFrame,
    ProtocolHandler, ProtocolResponder, CAPABILITY_OFFER_MESSAGE_ID,
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

/// Error produced by client-side capability-handshake orchestration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientHandshakeError {
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
    /// The inbound frame has an invalid logical direction for a server reply.
    UnexpectedDirection {
        /// Direction received from the peer.
        direction: ProtocolDirection,
    },
    /// The peer selected a capability that cannot be validated locally.
    InvalidSelection {
        /// Capability selected by the peer.
        capability: crate::CapabilityId,
    },
    /// Canonical handshake payload processing failed.
    Protocol(ProtocolError),
}

impl core::fmt::Display for ClientHandshakeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidState => formatter.write_str("invalid client handshake state"),
            Self::UnexpectedMessage { .. } => {
                formatter.write_str("unexpected client handshake message")
            }
            Self::UnexpectedMessageClass { .. } => {
                formatter.write_str("unexpected client handshake message class")
            }
            Self::UnexpectedDirection { .. } => {
                formatter.write_str("unexpected client handshake direction")
            }
            Self::InvalidSelection { .. } => {
                formatter.write_str("peer capability selection failed local validation")
            }
            Self::Protocol(error) => {
                write!(formatter, "client handshake protocol failure: {error}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ClientHandshakeError {}

/// Client-side capability-handshake state.
///
/// The client first emits its original capability offer, then waits for a
/// server selection or rejection. A peer-selected capability becomes trusted
/// negotiation evidence only after validation against the client's original
/// offer and resolved local policy.
///
/// Receiving a valid selection does not establish the protocol session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientHandshakeState {
    /// The client's capability offer has not yet been emitted.
    OfferPending,
    /// The offer has been encoded and the client awaits the server response.
    AwaitingSelection,
    /// The server selection has passed local offer and policy validation.
    SelectionValidated(NegotiatedCapability),
    /// The server rejected capability negotiation.
    Rejected(CapabilityRejectionReason),
}

/// Client-side capability-handshake orchestrator.
///
/// The client retains the exact validated offer it emitted and the local
/// resolved policy against which a server selection must later be checked.
///
/// This state machine performs no transport I/O, session establishment,
/// provider resolution, or cryptographic execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientCapabilityHandshake<'a> {
    local_offer: CapabilityOffer<'a>,
    policy: CapabilityPolicy<'a>,
    state: ClientHandshakeState,
}

impl<'a> ClientCapabilityHandshake<'a> {
    /// Construct a client handshake with an offer waiting to be emitted.
    pub const fn new(local_offer: CapabilityOffer<'a>, policy: CapabilityPolicy<'a>) -> Self {
        Self {
            local_offer,
            policy,
            state: ClientHandshakeState::OfferPending,
        }
    }

    /// Return the current client handshake state.
    pub const fn state(&self) -> ClientHandshakeState {
        self.state
    }

    /// Return the exact capability offer retained by the client.
    pub const fn local_offer(&self) -> CapabilityOffer<'a> {
        self.local_offer
    }

    /// Return the client's resolved local capability policy.
    pub const fn policy(&self) -> CapabilityPolicy<'a> {
        self.policy
    }

    /// Return validated negotiation evidence, if selection has succeeded.
    pub const fn validated_negotiated(&self) -> Option<NegotiatedCapability> {
        match self.state {
            ClientHandshakeState::SelectionValidated(negotiated) => Some(negotiated),
            _ => None,
        }
    }

    /// Return the peer rejection reason, if negotiation was rejected.
    pub const fn rejection_reason(&self) -> Option<CapabilityRejectionReason> {
        match self.state {
            ClientHandshakeState::Rejected(reason) => Some(reason),
            _ => None,
        }
    }
}

impl ProtocolResponder for ClientCapabilityHandshake<'_> {
    type Error = ClientHandshakeError;

    fn write_response<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<OutboundResponse<'a>, Self::Error> {
        if self.state != ClientHandshakeState::OfferPending {
            return Err(ClientHandshakeError::InvalidState);
        }

        let payload = CapabilityOfferPayload::new(self.local_offer)
            .map_err(ClientHandshakeError::Protocol)?;
        let written = payload
            .encode_into(output)
            .map_err(ClientHandshakeError::Protocol)?;

        self.state = ClientHandshakeState::AwaitingSelection;

        Ok(OutboundResponse::new(
            CAPABILITY_OFFER_MESSAGE_ID,
            MessageClass::Handshake,
            &output[..written],
        ))
    }
}

impl ProtocolHandler for ClientCapabilityHandshake<'_> {
    type Error = ClientHandshakeError;

    fn handle_frame(&mut self, frame: &ProtocolFrame<'_>) -> Result<HandlerOutcome, Self::Error> {
        if self.state != ClientHandshakeState::AwaitingSelection {
            return Err(ClientHandshakeError::InvalidState);
        }

        let header = frame.header();

        if header.message_class() != MessageClass::Handshake {
            return Err(ClientHandshakeError::UnexpectedMessageClass {
                message_class: header.message_class(),
            });
        }

        if header.direction() != ProtocolDirection::ServerToClient {
            return Err(ClientHandshakeError::UnexpectedDirection {
                direction: header.direction(),
            });
        }

        match header.message_id() {
            CAPABILITY_SELECTION_MESSAGE_ID => {
                let selection = CapabilitySelectionPayload::decode_exact(frame.payload())
                    .map_err(ClientHandshakeError::Protocol)?;
                let selected = selection.capability();

                let negotiated =
                    validate_selected_capability(self.local_offer, selected, self.policy).ok_or(
                        ClientHandshakeError::InvalidSelection {
                            capability: selected,
                        },
                    )?;

                self.state = ClientHandshakeState::SelectionValidated(negotiated);

                Ok(HandlerOutcome::new(HandlerAction::Continue))
            }
            CAPABILITY_REJECTION_MESSAGE_ID => {
                let rejection = CapabilityRejectionPayload::decode_exact(frame.payload())
                    .map_err(ClientHandshakeError::Protocol)?;
                let reason = rejection.reason();

                self.state = ClientHandshakeState::Rejected(reason);

                Ok(HandlerOutcome::new(HandlerAction::Close))
            }
            message_id => Err(ClientHandshakeError::UnexpectedMessage { message_id }),
        }
    }
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

#[cfg(test)]
mod client_tests {
    use super::*;
    use crate::{
        CapabilityId, EstablishingState, MemoryTransport, PolicyId, ProtocolDriver, ProtocolId,
        ProtocolRole, ProtocolSession, ProtocolVersion, SessionId, SessionState,
        TypedProtocolSession,
    };

    fn client_ids() -> [CapabilityId; 3] {
        [
            CapabilityId::new(10),
            CapabilityId::new(20),
            CapabilityId::new(30),
        ]
    }

    fn allowed_ids() -> [CapabilityId; 2] {
        [CapabilityId::new(20), CapabilityId::new(30)]
    }

    fn client<'a>(
        local: &'a [CapabilityId],
        allowed: &'a [CapabilityId],
    ) -> ClientCapabilityHandshake<'a> {
        ClientCapabilityHandshake::new(
            CapabilityOffer::new(local).unwrap(),
            CapabilityPolicy::new(PolicyId::new(41), allowed).unwrap(),
        )
    }

    fn server_frame<'a>(
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

    fn move_to_awaiting_selection(handshake: &mut ClientCapabilityHandshake<'_>) {
        let mut output = [0_u8; 16];
        handshake.write_response(&mut output).unwrap();
        assert_eq!(handshake.state(), ClientHandshakeState::AwaitingSelection);
    }

    #[test]
    fn client_emits_canonical_capability_offer() {
        let local = client_ids();
        let allowed = allowed_ids();
        let mut handshake = client(&local, &allowed);
        let mut output = [0_u8; 8];

        let response = handshake.write_response(&mut output).unwrap();

        assert_eq!(response.message_id(), CAPABILITY_OFFER_MESSAGE_ID);
        assert_eq!(response.message_class(), MessageClass::Handshake);
        assert_eq!(
            response.payload(),
            &[0x00, 0x03, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x1e]
        );
        assert_eq!(handshake.state(), ClientHandshakeState::AwaitingSelection);
    }

    #[test]
    fn short_offer_buffer_preserves_offer_pending_state() {
        let local = client_ids();
        let allowed = allowed_ids();
        let mut handshake = client(&local, &allowed);
        let mut output = [0_u8; 7];

        assert_eq!(
            handshake.write_response(&mut output),
            Err(ClientHandshakeError::Protocol(
                ProtocolError::BufferTooSmall {
                    required: 8,
                    available: 7,
                }
            ))
        );
        assert_eq!(handshake.state(), ClientHandshakeState::OfferPending);
    }

    #[test]
    fn client_offer_cannot_be_emitted_twice() {
        let local = client_ids();
        let allowed = allowed_ids();
        let mut handshake = client(&local, &allowed);
        let mut output = [0_u8; 8];

        handshake.write_response(&mut output).unwrap();

        assert_eq!(
            handshake.write_response(&mut output),
            Err(ClientHandshakeError::InvalidState)
        );
    }

    #[test]
    fn valid_server_selection_produces_local_negotiation_evidence() {
        let local = client_ids();
        let allowed = allowed_ids();
        let mut handshake = client(&local, &allowed);
        move_to_awaiting_selection(&mut handshake);

        let payload = [0x00, 0x14];
        let frame = server_frame(
            CAPABILITY_SELECTION_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ServerToClient,
            &payload,
        );

        let outcome = handshake.handle_frame(&frame).unwrap();

        assert_eq!(outcome, HandlerOutcome::new(HandlerAction::Continue));
        assert_eq!(outcome.requested_transition(), None);

        let negotiated = handshake.validated_negotiated().unwrap();
        assert_eq!(negotiated.policy_id(), PolicyId::new(41));
        assert_eq!(negotiated.capability(), CapabilityId::new(20));
    }

    #[test]
    fn server_selection_not_in_original_offer_is_rejected() {
        let local = client_ids();
        let allowed = [
            CapabilityId::new(20),
            CapabilityId::new(30),
            CapabilityId::new(99),
        ];
        let mut handshake = client(&local, &allowed);
        move_to_awaiting_selection(&mut handshake);

        let payload = [0x00, 0x63];
        let frame = server_frame(
            CAPABILITY_SELECTION_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ServerToClient,
            &payload,
        );

        assert_eq!(
            handshake.handle_frame(&frame),
            Err(ClientHandshakeError::InvalidSelection {
                capability: CapabilityId::new(99),
            })
        );
        assert_eq!(handshake.state(), ClientHandshakeState::AwaitingSelection);
    }

    #[test]
    fn locally_forbidden_server_selection_is_rejected() {
        let local = client_ids();
        let allowed = [CapabilityId::new(20)];
        let mut handshake = client(&local, &allowed);
        move_to_awaiting_selection(&mut handshake);

        let payload = [0x00, 0x1e];
        let frame = server_frame(
            CAPABILITY_SELECTION_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ServerToClient,
            &payload,
        );

        assert_eq!(
            handshake.handle_frame(&frame),
            Err(ClientHandshakeError::InvalidSelection {
                capability: CapabilityId::new(30),
            })
        );
        assert_eq!(handshake.state(), ClientHandshakeState::AwaitingSelection);
    }

    #[test]
    fn malformed_selection_preserves_awaiting_state() {
        let local = client_ids();
        let allowed = allowed_ids();
        let mut handshake = client(&local, &allowed);
        move_to_awaiting_selection(&mut handshake);

        let payload = [0x00];
        let frame = server_frame(
            CAPABILITY_SELECTION_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ServerToClient,
            &payload,
        );

        assert_eq!(
            handshake.handle_frame(&frame),
            Err(ClientHandshakeError::Protocol(ProtocolError::UnexpectedEnd))
        );
        assert_eq!(handshake.state(), ClientHandshakeState::AwaitingSelection);
    }

    #[test]
    fn canonical_rejection_moves_client_to_rejected_state() {
        let local = client_ids();
        let allowed = allowed_ids();
        let mut handshake = client(&local, &allowed);
        move_to_awaiting_selection(&mut handshake);

        let payload = [0x00, 0x02];
        let frame = server_frame(
            CAPABILITY_REJECTION_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ServerToClient,
            &payload,
        );

        let outcome = handshake.handle_frame(&frame).unwrap();

        assert_eq!(outcome, HandlerOutcome::new(HandlerAction::Close));
        assert_eq!(outcome.requested_transition(), None);
        assert_eq!(
            handshake.state(),
            ClientHandshakeState::Rejected(CapabilityRejectionReason::PolicyRejected)
        );
        assert_eq!(
            handshake.rejection_reason(),
            Some(CapabilityRejectionReason::PolicyRejected)
        );
    }

    #[test]
    fn malformed_rejection_preserves_awaiting_state() {
        let local = client_ids();
        let allowed = allowed_ids();
        let mut handshake = client(&local, &allowed);
        move_to_awaiting_selection(&mut handshake);

        let payload = [0xff, 0xff];
        let frame = server_frame(
            CAPABILITY_REJECTION_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ServerToClient,
            &payload,
        );

        assert_eq!(
            handshake.handle_frame(&frame),
            Err(ClientHandshakeError::Protocol(
                ProtocolError::InvalidEncoding
            ))
        );
        assert_eq!(handshake.state(), ClientHandshakeState::AwaitingSelection);
    }

    #[test]
    fn unexpected_metadata_is_rejected_without_state_change() {
        let local = client_ids();
        let allowed = allowed_ids();
        let mut handshake = client(&local, &allowed);
        move_to_awaiting_selection(&mut handshake);

        let selection = [0x00, 0x14];

        let wrong_class = server_frame(
            CAPABILITY_SELECTION_MESSAGE_ID,
            MessageClass::Application,
            ProtocolDirection::ServerToClient,
            &selection,
        );

        assert!(matches!(
            handshake.handle_frame(&wrong_class),
            Err(ClientHandshakeError::UnexpectedMessageClass { .. })
        ));
        assert_eq!(handshake.state(), ClientHandshakeState::AwaitingSelection);

        let wrong_direction = server_frame(
            CAPABILITY_SELECTION_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ClientToServer,
            &selection,
        );

        assert!(matches!(
            handshake.handle_frame(&wrong_direction),
            Err(ClientHandshakeError::UnexpectedDirection { .. })
        ));
        assert_eq!(handshake.state(), ClientHandshakeState::AwaitingSelection);

        let wrong_message = server_frame(
            CAPABILITY_OFFER_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ServerToClient,
            &selection,
        );

        assert_eq!(
            handshake.handle_frame(&wrong_message),
            Err(ClientHandshakeError::UnexpectedMessage {
                message_id: CAPABILITY_OFFER_MESSAGE_ID,
            })
        );
        assert_eq!(handshake.state(), ClientHandshakeState::AwaitingSelection);
    }

    #[test]
    fn driver_handling_valid_selection_does_not_establish_runtime_session() {
        let local = client_ids();
        let allowed = allowed_ids();
        let mut handshake = client(&local, &allowed);
        move_to_awaiting_selection(&mut handshake);

        let selection = [0x00, 0x14];
        let frame = server_frame(
            CAPABILITY_SELECTION_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ServerToClient,
            &selection,
        );

        let mut session = ProtocolSession::new(
            SessionId::from_bytes([0x6b; 16]),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Client,
        );
        session.transition_to(SessionState::Establishing).unwrap();

        let transport = MemoryTransport::<16>::new(16).unwrap();
        let mut driver = ProtocolDriver::new(transport, session);

        let outcome = driver.handle_frame(&mut handshake, &frame).unwrap();

        assert_eq!(outcome, HandlerOutcome::new(HandlerAction::Continue));
        assert_eq!(outcome.requested_transition(), None);
        assert_eq!(driver.session().state(), SessionState::Establishing);
        assert!(handshake.validated_negotiated().is_some());
    }

    fn typed_establishing() -> TypedProtocolSession<EstablishingState> {
        TypedProtocolSession::new(
            SessionId::from_bytes([0x7c; 16]),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Client,
        )
        .begin_establishment()
    }

    #[test]
    fn validated_selection_can_be_committed_through_existing_establishment_boundary() {
        let local = client_ids();
        let allowed = allowed_ids();
        let mut handshake = client(&local, &allowed);
        move_to_awaiting_selection(&mut handshake);

        let selection = [0x00, 0x14];
        let frame = server_frame(
            CAPABILITY_SELECTION_MESSAGE_ID,
            MessageClass::Handshake,
            ProtocolDirection::ServerToClient,
            &selection,
        );

        handshake.handle_frame(&frame).unwrap();

        let negotiated = handshake.validated_negotiated().unwrap();
        let context = typed_establishing().establish_with_negotiation(negotiated);

        assert_eq!(context.session().runtime_state(), SessionState::Established);
        assert_eq!(context.policy_id(), PolicyId::new(41));
        assert_eq!(context.capability(), CapabilityId::new(20));
    }
}

#[cfg(test)]
mod end_to_end_handshake_tests {
    use super::*;
    use crate::{
        CapabilityId, FrameReceiver, FrameTransmitter, PolicyId, ProtocolFrame, ProtocolId,
        ProtocolRole, ProtocolSession, ProtocolVersion, SessionId, SessionState, TransportError,
    };

    const FRAME_STORAGE_LEN: usize = 128;
    const PAYLOAD_STORAGE_LEN: usize = 64;
    const TRANSPORT_CAPACITY: usize = 128;

    fn transmit_response_into_transport<const N: usize>(
        response: OutboundResponse<'_>,
        direction: ProtocolDirection,
        transport: &mut crate::MemoryTransport<N>,
    ) {
        let frame = ProtocolFrame::current(
            ProtocolVersion::new(1, 0),
            ProtocolId::new(0x1300),
            response.message_id(),
            response.message_class(),
            direction,
            response.payload(),
        )
        .unwrap();

        let mut scratch = [0_u8; FRAME_STORAGE_LEN];
        let mut transmitter = FrameTransmitter::new(&frame, &mut scratch).unwrap();

        while !transmitter.is_complete() {
            match transmitter.advance(transport) {
                Ok(_) => {}
                Err(crate::FrameTransferError::Transport(TransportError::Pending)) => {
                    panic!("transport capacity unexpectedly exhausted");
                }
                Err(error) => panic!("unexpected transmit failure: {error:?}"),
            }
        }
    }

    fn receive_frame_from_transport<const N: usize>(
        transport: &mut crate::MemoryTransport<N>,
        storage: &mut [u8],
    ) -> usize {
        let mut receiver = FrameReceiver::new(storage).unwrap();

        while !receiver.is_complete() {
            match receiver.advance(transport) {
                Ok(_) => {}
                Err(crate::FrameTransferError::Transport(TransportError::Pending)) => {
                    panic!("transport became pending before frame completion");
                }
                Err(error) => panic!("unexpected receive failure: {error:?}"),
            }
        }

        let frame_len = receiver.expected_len().unwrap();
        assert_eq!(receiver.received_len(), frame_len);
        assert!(receiver.frame().unwrap().is_some());

        frame_len
    }

    #[test]
    fn fragmented_end_to_end_handshake_produces_matching_capability_evidence() {
        let client_ids = [
            CapabilityId::new(10),
            CapabilityId::new(20),
            CapabilityId::new(30),
        ];
        let client_allowed = [CapabilityId::new(20), CapabilityId::new(30)];

        let server_ids = [
            CapabilityId::new(30),
            CapabilityId::new(20),
            CapabilityId::new(40),
        ];
        let server_allowed = [
            CapabilityId::new(20),
            CapabilityId::new(30),
            CapabilityId::new(40),
        ];

        let client_policy_id = PolicyId::new(0x101);
        let server_policy_id = PolicyId::new(0x202);

        let mut client = ClientCapabilityHandshake::new(
            CapabilityOffer::new(&client_ids).unwrap(),
            CapabilityPolicy::new(client_policy_id, &client_allowed).unwrap(),
        );

        let mut server = ServerCapabilityHandshake::new(
            CapabilityOffer::new(&server_ids).unwrap(),
            CapabilityPolicy::new(server_policy_id, &server_allowed).unwrap(),
        );

        /*
         * A one-byte transfer limit deliberately fragments both the fixed
         * frame header and handshake payload. The handshake therefore crosses
         * the complete resumable frame transport path.
         */
        let mut client_to_server = crate::MemoryTransport::<TRANSPORT_CAPACITY>::new(1).unwrap();
        let mut server_to_client = crate::MemoryTransport::<TRANSPORT_CAPACITY>::new(1).unwrap();

        /*
         * Client -> server capability offer.
         */
        let mut client_payload = [0_u8; PAYLOAD_STORAGE_LEN];
        let offer_response = client.write_response(&mut client_payload).unwrap();

        assert_eq!(client.state(), ClientHandshakeState::AwaitingSelection);

        transmit_response_into_transport(
            offer_response,
            ProtocolDirection::ClientToServer,
            &mut client_to_server,
        );

        let mut server_frame_storage = [0_u8; FRAME_STORAGE_LEN];
        let offer_frame_len =
            receive_frame_from_transport(&mut client_to_server, &mut server_frame_storage);
        let offer_frame =
            ProtocolFrame::decode_exact(&server_frame_storage[..offer_frame_len]).unwrap();

        let server_outcome = server.handle_frame(&offer_frame).unwrap();

        assert_eq!(server_outcome, HandlerOutcome::new(HandlerAction::Respond));
        assert_eq!(server_outcome.requested_transition(), None);

        let server_evidence = server.pending_negotiated().unwrap();

        /*
         * Server local ordering is authoritative among common,
         * policy-permitted capabilities: 30 precedes 20.
         */
        assert_eq!(server_evidence.capability(), CapabilityId::new(30));
        assert_eq!(server_evidence.policy_id(), server_policy_id);

        /*
         * Server -> client canonical selection.
         */
        let mut server_payload = [0_u8; PAYLOAD_STORAGE_LEN];
        let selection_response = server.write_response(&mut server_payload).unwrap();

        assert_eq!(
            server.state(),
            ServerHandshakeState::SelectionEmitted(server_evidence)
        );

        transmit_response_into_transport(
            selection_response,
            ProtocolDirection::ServerToClient,
            &mut server_to_client,
        );

        let mut client_frame_storage = [0_u8; FRAME_STORAGE_LEN];
        let selection_frame_len =
            receive_frame_from_transport(&mut server_to_client, &mut client_frame_storage);
        let selection_frame =
            ProtocolFrame::decode_exact(&client_frame_storage[..selection_frame_len]).unwrap();

        let client_outcome = client.handle_frame(&selection_frame).unwrap();

        assert_eq!(client_outcome, HandlerOutcome::new(HandlerAction::Continue));
        assert_eq!(client_outcome.requested_transition(), None);

        let client_evidence = client.validated_negotiated().unwrap();

        /*
         * Both endpoints agree on the capability while independently binding
         * it to their own resolved local policy.
         */
        assert_eq!(client_evidence.capability(), server_evidence.capability());
        assert_eq!(client_evidence.capability(), CapabilityId::new(30));

        assert_eq!(client_evidence.policy_id(), client_policy_id);
        assert_eq!(server_evidence.policy_id(), server_policy_id);
    }

    #[test]
    fn fragmented_handshake_does_not_implicitly_establish_sessions() {
        let client_ids = [CapabilityId::new(1), CapabilityId::new(2)];
        let server_ids = [CapabilityId::new(2), CapabilityId::new(1)];
        let allowed = [CapabilityId::new(1), CapabilityId::new(2)];

        let mut client = ClientCapabilityHandshake::new(
            CapabilityOffer::new(&client_ids).unwrap(),
            CapabilityPolicy::new(PolicyId::new(11), &allowed).unwrap(),
        );

        let mut server = ServerCapabilityHandshake::new(
            CapabilityOffer::new(&server_ids).unwrap(),
            CapabilityPolicy::new(PolicyId::new(22), &allowed).unwrap(),
        );

        let mut client_session = ProtocolSession::new(
            SessionId::from_bytes([0x31; 16]),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Client,
        );
        client_session
            .transition_to(SessionState::Establishing)
            .unwrap();

        let mut server_session = ProtocolSession::new(
            SessionId::from_bytes([0x32; 16]),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Server,
        );
        server_session
            .transition_to(SessionState::Establishing)
            .unwrap();

        let mut client_to_server = crate::MemoryTransport::<TRANSPORT_CAPACITY>::new(2).unwrap();
        let mut server_to_client = crate::MemoryTransport::<TRANSPORT_CAPACITY>::new(2).unwrap();

        let mut payload = [0_u8; PAYLOAD_STORAGE_LEN];
        let offer = client.write_response(&mut payload).unwrap();

        transmit_response_into_transport(
            offer,
            ProtocolDirection::ClientToServer,
            &mut client_to_server,
        );

        let mut server_storage = [0_u8; FRAME_STORAGE_LEN];
        let offer_frame_len =
            receive_frame_from_transport(&mut client_to_server, &mut server_storage);
        let offer_frame = ProtocolFrame::decode_exact(&server_storage[..offer_frame_len]).unwrap();

        let outcome = server.handle_frame(&offer_frame).unwrap();

        assert_eq!(outcome.requested_transition(), None);
        assert_eq!(client_session.state(), SessionState::Establishing);
        assert_eq!(server_session.state(), SessionState::Establishing);

        let server_evidence = server.pending_negotiated().unwrap();

        let selection = server.write_response(&mut payload).unwrap();

        transmit_response_into_transport(
            selection,
            ProtocolDirection::ServerToClient,
            &mut server_to_client,
        );

        let mut client_storage = [0_u8; FRAME_STORAGE_LEN];
        let selection_frame_len =
            receive_frame_from_transport(&mut server_to_client, &mut client_storage);
        let selection_frame =
            ProtocolFrame::decode_exact(&client_storage[..selection_frame_len]).unwrap();

        let outcome = client.handle_frame(&selection_frame).unwrap();

        assert_eq!(outcome.requested_transition(), None);
        assert_eq!(client_session.state(), SessionState::Establishing);
        assert_eq!(server_session.state(), SessionState::Establishing);

        let client_evidence = client.validated_negotiated().unwrap();

        assert_eq!(client_evidence.capability(), server_evidence.capability());
    }

    #[test]
    fn end_to_end_evidence_can_be_committed_only_after_handshake_completion() {
        let client_ids = [CapabilityId::new(7), CapabilityId::new(8)];
        let server_ids = [CapabilityId::new(8), CapabilityId::new(7)];
        let allowed = [CapabilityId::new(7), CapabilityId::new(8)];

        let client_policy_id = PolicyId::new(31);
        let server_policy_id = PolicyId::new(32);

        let mut client = ClientCapabilityHandshake::new(
            CapabilityOffer::new(&client_ids).unwrap(),
            CapabilityPolicy::new(client_policy_id, &allowed).unwrap(),
        );

        let mut server = ServerCapabilityHandshake::new(
            CapabilityOffer::new(&server_ids).unwrap(),
            CapabilityPolicy::new(server_policy_id, &allowed).unwrap(),
        );

        let mut c2s = crate::MemoryTransport::<TRANSPORT_CAPACITY>::new(1).unwrap();
        let mut s2c = crate::MemoryTransport::<TRANSPORT_CAPACITY>::new(1).unwrap();

        let mut payload = [0_u8; PAYLOAD_STORAGE_LEN];

        let offer = client.write_response(&mut payload).unwrap();
        transmit_response_into_transport(offer, ProtocolDirection::ClientToServer, &mut c2s);

        let mut server_storage = [0_u8; FRAME_STORAGE_LEN];
        let frame_len = receive_frame_from_transport(&mut c2s, &mut server_storage);
        let frame = ProtocolFrame::decode_exact(&server_storage[..frame_len]).unwrap();
        server.handle_frame(&frame).unwrap();

        let server_evidence = server.pending_negotiated().unwrap();

        let selection = server.write_response(&mut payload).unwrap();
        transmit_response_into_transport(selection, ProtocolDirection::ServerToClient, &mut s2c);

        let mut client_storage = [0_u8; FRAME_STORAGE_LEN];
        let frame_len = receive_frame_from_transport(&mut s2c, &mut client_storage);
        let frame = ProtocolFrame::decode_exact(&client_storage[..frame_len]).unwrap();
        client.handle_frame(&frame).unwrap();

        let client_evidence = client.validated_negotiated().unwrap();

        assert_eq!(client_evidence.capability(), server_evidence.capability());

        /*
         * Only now do both endpoints cross the explicit establishment
         * boundary using their independently produced local evidence.
         */
        let client_established = crate::TypedProtocolSession::new(
            SessionId::from_bytes([0x41; 16]),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Client,
        )
        .begin_establishment()
        .establish_with_negotiation(client_evidence);

        let server_established = crate::TypedProtocolSession::new(
            SessionId::from_bytes([0x42; 16]),
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Server,
        )
        .begin_establishment()
        .establish_with_negotiation(server_evidence);

        assert_eq!(
            client_established.session().runtime_state(),
            SessionState::Established
        );
        assert_eq!(
            server_established.session().runtime_state(),
            SessionState::Established
        );

        assert_eq!(
            client_established.capability(),
            server_established.capability()
        );
        assert_eq!(client_established.policy_id(), client_policy_id);
        assert_eq!(server_established.policy_id(), server_policy_id);
    }
}
