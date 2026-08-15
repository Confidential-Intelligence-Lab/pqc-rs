use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use pqc_hpke::{hybrid_kem::HybridKem, MlKemHpke};
use pqc_protocol::{
    CapabilityId, CapabilityOffer, CapabilityPolicy, ClientCapabilityHandshake, FrameReceiver,
    FrameTransferError, FrameTransmitter, HandlerAction, MessageClass, MessageId, PolicyId,
    ProtocolDirection, ProtocolFrame, ProtocolHandler, ProtocolId, ProtocolResponder, ProtocolRole,
    ProtocolVersion, ServerCapabilityHandshake, SessionId, TransportError, TransportReceive,
    TransportResult, TransportTransmit, TypedProtocolSession, HPKE_ML_KEM_1024, HPKE_ML_KEM_768,
    HPKE_ML_KEM_768_X25519,
};
use pqc_secure_channel::{activate_receiver, activate_sender};
use rand_core::{CryptoRng, Error as RandError, RngCore};

const PROTOCOL_ID: ProtocolId = ProtocolId::new(0x1300);
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

const CLIENT_POLICY_ID: PolicyId = PolicyId::new(0x1010);
const SERVER_POLICY_ID: PolicyId = PolicyId::new(0x2020);

const CLIENT_SESSION_BYTE: u8 = 0x41;
const SERVER_SESSION_BYTE: u8 = 0x42;

const APPLICATION_CONTEXT: &[u8] = b"pqc-forge-e6-adverse-schedule";
const REQUEST_AAD: &[u8] = b"pqc-forge-e6-request";
const RESPONSE_AAD: &[u8] = b"pqc-forge-e6-response";

const REQUEST: [u8; 1024] = [0xa5; 1024];
const RESPONSE: [u8; 1024] = [0x5a; 1024];

const FRAME_STORAGE_LEN: usize = 8192;
const HANDSHAKE_PAYLOAD_LEN: usize = 64;

const CLIENT_ACTIVATION_MESSAGE_ID: MessageId = MessageId::new(0x1001);
const SERVER_ACTIVATION_MESSAGE_ID: MessageId = MessageId::new(0x1002);
const PROTECTED_REQUEST_MESSAGE_ID: MessageId = MessageId::new(0x1003);
const PROTECTED_RESPONSE_MESSAGE_ID: MessageId = MessageId::new(0x1004);

#[derive(Clone, Copy, Debug)]
enum AdverseKind {
    None,
    PeriodicPending,
    PeriodicInterrupted,
    AlternatingPending,
    AlternatingInterrupted,
}

impl AdverseKind {
    const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PeriodicPending => "periodic-pending",
            Self::PeriodicInterrupted => "periodic-interrupted",
            Self::AlternatingPending => "progress-pending",
            Self::AlternatingInterrupted => "progress-interrupted",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Schedule {
    id: &'static str,
    transfer_limit: usize,
    kind: AdverseKind,
}

const SCHEDULES: [Schedule; 6] = [
    Schedule {
        id: "S0",
        transfer_limit: 7,
        kind: AdverseKind::None,
    },
    Schedule {
        id: "S1",
        transfer_limit: 1,
        kind: AdverseKind::None,
    },
    Schedule {
        id: "S2",
        transfer_limit: 7,
        kind: AdverseKind::PeriodicPending,
    },
    Schedule {
        id: "S3",
        transfer_limit: 7,
        kind: AdverseKind::PeriodicInterrupted,
    },
    Schedule {
        id: "S4",
        transfer_limit: 1,
        kind: AdverseKind::AlternatingPending,
    },
    Schedule {
        id: "S5",
        transfer_limit: 1,
        kind: AdverseKind::AlternatingInterrupted,
    },
];

#[derive(Clone, Copy, Debug, Default)]
struct DirectionStats {
    calls: usize,
    progress_calls: usize,
    committed_bytes: usize,
    pending: usize,
    interrupted: usize,
    max_progress: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct TransportStats {
    transmit: DirectionStats,
    receive: DirectionStats,
}

#[derive(Clone, Copy, Debug, Default)]
struct ScheduleState {
    calls: usize,
}

impl ScheduleState {
    fn adverse_event(&mut self, kind: AdverseKind) -> Option<TransportError> {
        self.calls += 1;

        match kind {
            AdverseKind::None => None,

            // Fixed deterministic periodicity: every fourth attempted
            // transport operation is a zero-progress retryable event.
            AdverseKind::PeriodicPending if self.calls % 4 == 0 => Some(TransportError::Pending),
            AdverseKind::PeriodicInterrupted if self.calls % 4 == 0 => {
                Some(TransportError::Interrupted)
            }

            // Odd attempts make progress; even attempts inject the
            // zero-progress retryable event.
            AdverseKind::AlternatingPending if self.calls % 2 == 0 => Some(TransportError::Pending),
            AdverseKind::AlternatingInterrupted if self.calls % 2 == 0 => {
                Some(TransportError::Interrupted)
            }

            _ => None,
        }
    }
}

struct ScheduledTcpTransport {
    stream: TcpStream,
    schedule: Schedule,
    transmit_schedule: ScheduleState,
    receive_schedule: ScheduleState,
    stats: TransportStats,
}

impl ScheduledTcpTransport {
    fn new(stream: TcpStream, schedule: Schedule) -> Self {
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        Self {
            stream,
            schedule,
            transmit_schedule: ScheduleState::default(),
            receive_schedule: ScheduleState::default(),
            stats: TransportStats::default(),
        }
    }

    const fn stats(&self) -> TransportStats {
        self.stats
    }

    fn record_transmit_retryable(&mut self, error: TransportError) {
        match error {
            TransportError::Pending => self.stats.transmit.pending += 1,
            TransportError::Interrupted => self.stats.transmit.interrupted += 1,
            _ => unreachable!("E6 only records retryable transport errors"),
        }
    }

    fn record_receive_retryable(&mut self, error: TransportError) {
        match error {
            TransportError::Pending => self.stats.receive.pending += 1,
            TransportError::Interrupted => self.stats.receive.interrupted += 1,
            _ => unreachable!("E6 only records retryable transport errors"),
        }
    }
}

fn map_io_error(error: &std::io::Error) -> TransportError {
    match error.kind() {
        ErrorKind::WouldBlock => TransportError::Pending,
        ErrorKind::Interrupted => TransportError::Interrupted,
        _ => TransportError::Other,
    }
}

impl TransportTransmit for ScheduledTcpTransport {
    fn transmit(&mut self, input: &[u8]) -> TransportResult<usize> {
        if input.is_empty() {
            return Ok(0);
        }

        self.stats.transmit.calls += 1;

        if let Some(error) = self.transmit_schedule.adverse_event(self.schedule.kind) {
            self.record_transmit_retryable(error);
            return Err(error);
        }

        let limit = input.len().min(self.schedule.transfer_limit);

        match self.stream.write(&input[..limit]) {
            Ok(0) => Err(TransportError::Closed),
            Ok(progress) => {
                self.stats.transmit.progress_calls += 1;
                self.stats.transmit.committed_bytes += progress;
                self.stats.transmit.max_progress = self.stats.transmit.max_progress.max(progress);
                Ok(progress)
            }
            Err(error) => {
                let error = map_io_error(&error);

                if matches!(error, TransportError::Pending | TransportError::Interrupted) {
                    self.record_transmit_retryable(error);
                }

                Err(error)
            }
        }
    }
}

impl TransportReceive for ScheduledTcpTransport {
    fn receive(&mut self, output: &mut [u8]) -> TransportResult<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        self.stats.receive.calls += 1;

        if let Some(error) = self.receive_schedule.adverse_event(self.schedule.kind) {
            self.record_receive_retryable(error);
            return Err(error);
        }

        let limit = output.len().min(self.schedule.transfer_limit);

        match self.stream.read(&mut output[..limit]) {
            Ok(0) => Err(TransportError::Closed),
            Ok(progress) => {
                self.stats.receive.progress_calls += 1;
                self.stats.receive.committed_bytes += progress;
                self.stats.receive.max_progress = self.stats.receive.max_progress.max(progress);
                Ok(progress)
            }
            Err(error) => {
                let error = map_io_error(&error);

                if matches!(error, TransportError::Pending | TransportError::Interrupted) {
                    self.record_receive_retryable(error);
                }

                Err(error)
            }
        }
    }
}

struct DeterministicRng {
    next: u8,
}

impl DeterministicRng {
    const fn new(seed: u8) -> Self {
        Self { next: seed }
    }
}

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
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for DeterministicRng {}

struct ProfileFixture {
    label: &'static str,
    capability: CapabilityId,
    client_public_key: Vec<u8>,
    client_private_key: Vec<u8>,
    server_public_key: Vec<u8>,
    server_private_key: Vec<u8>,
}

fn ml_kem_fixture(
    label: &'static str,
    capability: CapabilityId,
    kem: MlKemHpke,
    client_seed: u8,
    server_seed: u8,
) -> ProfileFixture {
    let client = kem.derive_key_pair(&[client_seed; 64]).unwrap();
    let server = kem.derive_key_pair(&[server_seed; 64]).unwrap();

    ProfileFixture {
        label,
        capability,
        client_public_key: client.public_key,
        client_private_key: client.private_key_seed.as_bytes().to_vec(),
        server_public_key: server.public_key,
        server_private_key: server.private_key_seed.as_bytes().to_vec(),
    }
}

fn hybrid_fixture(
    label: &'static str,
    capability: CapabilityId,
    kem: HybridKem,
    client_seed: u8,
    server_seed: u8,
) -> ProfileFixture {
    let client = kem.derive_key_pair(&[client_seed; 64]).unwrap();
    let server = kem.derive_key_pair(&[server_seed; 64]).unwrap();

    ProfileFixture {
        label,
        capability,
        client_public_key: client.public_key,
        client_private_key: client.private_seed.as_bytes().to_vec(),
        server_public_key: server.public_key,
        server_private_key: server.private_seed.as_bytes().to_vec(),
    }
}

fn fixtures() -> [ProfileFixture; 3] {
    [
        ml_kem_fixture("MLKEM768", HPKE_ML_KEM_768, MlKemHpke::MlKem768, 0x11, 0x12),
        ml_kem_fixture(
            "MLKEM1024",
            HPKE_ML_KEM_1024,
            MlKemHpke::MlKem1024,
            0x21,
            0x22,
        ),
        hybrid_fixture(
            "MLKEM768-X25519",
            HPKE_ML_KEM_768_X25519,
            HybridKem::MlKem768X25519,
            0x31,
            0x32,
        ),
    ]
}

fn ordered_capabilities(target: CapabilityId) -> [CapabilityId; 3] {
    let mut ordered = [target, CapabilityId::new(0), CapabilityId::new(0)];
    let mut index = 1;

    for capability in [HPKE_ML_KEM_768, HPKE_ML_KEM_1024, HPKE_ML_KEM_768_X25519] {
        if capability != target {
            ordered[index] = capability;
            index += 1;
        }
    }

    assert_eq!(index, 3);
    ordered
}

fn send_frame(transport: &mut ScheduledTcpTransport, frame: &ProtocolFrame<'_>) {
    let mut scratch = vec![0_u8; frame.frame_len()];
    let mut transmitter = FrameTransmitter::new(frame, &mut scratch).unwrap();

    while !transmitter.is_complete() {
        match transmitter.advance(transport) {
            Ok(_) => {}
            Err(FrameTransferError::Transport(
                TransportError::Pending | TransportError::Interrupted,
            )) => continue,
            Err(error) => panic!("frame transmission failed: {error:?}"),
        }
    }

    assert_eq!(transmitter.transmitted_len(), transmitter.encoded_len());
}

fn receive_frame(transport: &mut ScheduledTcpTransport) -> Vec<u8> {
    let mut storage = vec![0_u8; FRAME_STORAGE_LEN];

    let expected = {
        let mut receiver = FrameReceiver::new(&mut storage).unwrap();

        while !receiver.is_complete() {
            match receiver.advance(transport) {
                Ok(_) => {}
                Err(FrameTransferError::Transport(
                    TransportError::Pending | TransportError::Interrupted,
                )) => continue,
                Err(error) => panic!("frame reception failed: {error:?}"),
            }
        }

        let expected = receiver.expected_len().unwrap();

        assert_eq!(receiver.received_len(), expected);
        assert!(receiver.frame().unwrap().is_some());

        expected
    };

    storage.truncate(expected);
    storage
}

fn validate_frame(
    frame: &ProtocolFrame<'_>,
    message_id: MessageId,
    message_class: MessageClass,
    direction: ProtocolDirection,
) {
    let header = frame.header();

    assert_eq!(header.protocol_id(), PROTOCOL_ID);
    assert_eq!(header.protocol_version(), PROTOCOL_VERSION);
    assert_eq!(header.message_id(), message_id);
    assert_eq!(header.message_class(), message_class);
    assert_eq!(header.direction(), direction);
}

fn send_response(
    transport: &mut ScheduledTcpTransport,
    response: pqc_protocol::OutboundResponse<'_>,
    direction: ProtocolDirection,
) {
    let frame = ProtocolFrame::current(
        PROTOCOL_VERSION,
        PROTOCOL_ID,
        response.message_id(),
        response.message_class(),
        direction,
        response.payload(),
    )
    .unwrap();

    send_frame(transport, &frame);
}

fn send_application_payload(
    transport: &mut ScheduledTcpTransport,
    message_id: MessageId,
    direction: ProtocolDirection,
    payload: &[u8],
) {
    let frame = ProtocolFrame::current(
        PROTOCOL_VERSION,
        PROTOCOL_ID,
        message_id,
        MessageClass::Application,
        direction,
        payload,
    )
    .unwrap();

    send_frame(transport, &frame);
}

fn establish(
    negotiated: pqc_protocol::NegotiatedCapability,
    session_byte: u8,
    role: ProtocolRole,
) -> pqc_protocol::EstablishedProtocolContext {
    TypedProtocolSession::new(
        SessionId::from_bytes([session_byte; 16]),
        PROTOCOL_ID,
        PROTOCOL_VERSION,
        role,
    )
    .begin_establishment()
    .establish_with_negotiation(negotiated)
}

#[derive(Debug)]
struct ServerObservation {
    capability: CapabilityId,
    request_len: usize,
    receiver_sequence: u64,
    sender_sequence: u64,
    transport: TransportStats,
}

fn run_server(
    listener: TcpListener,
    capability: CapabilityId,
    client_public_key: Vec<u8>,
    server_private_key: Vec<u8>,
    schedule: Schedule,
) -> ServerObservation {
    let (stream, _) = listener.accept().unwrap();
    let mut transport = ScheduledTcpTransport::new(stream, schedule);

    let capabilities = ordered_capabilities(capability);
    let allowed = capabilities;

    let mut handshake = ServerCapabilityHandshake::new(
        CapabilityOffer::new(&capabilities).unwrap(),
        CapabilityPolicy::new(SERVER_POLICY_ID, &allowed).unwrap(),
    );

    let offer_bytes = receive_frame(&mut transport);
    let offer_frame = ProtocolFrame::decode_exact(&offer_bytes).unwrap();

    validate_frame(
        &offer_frame,
        pqc_protocol::CAPABILITY_OFFER_MESSAGE_ID,
        MessageClass::Handshake,
        ProtocolDirection::ClientToServer,
    );

    let outcome = handshake.handle_frame(&offer_frame).unwrap();
    assert_eq!(outcome.action(), HandlerAction::Respond);

    let server_negotiated = handshake.pending_negotiated().unwrap();
    assert_eq!(server_negotiated.capability(), capability);
    assert_eq!(server_negotiated.policy_id(), SERVER_POLICY_ID);

    let mut payload = [0_u8; HANDSHAKE_PAYLOAD_LEN];
    let selection = handshake.write_response(&mut payload).unwrap();

    send_response(&mut transport, selection, ProtocolDirection::ServerToClient);

    let established = establish(server_negotiated, SERVER_SESSION_BYTE, ProtocolRole::Server);

    assert_eq!(established.capability(), capability);

    /*
     * Client -> server channel activation.
     */
    let client_activation_bytes = receive_frame(&mut transport);
    let client_activation_frame = ProtocolFrame::decode_exact(&client_activation_bytes).unwrap();

    validate_frame(
        &client_activation_frame,
        CLIENT_ACTIVATION_MESSAGE_ID,
        MessageClass::Application,
        ProtocolDirection::ClientToServer,
    );

    let mut receiver = activate_receiver(
        &established,
        &server_private_key,
        client_activation_frame.payload(),
        APPLICATION_CONTEXT,
    )
    .unwrap();

    assert_eq!(receiver.sequence_number(), 0);

    /*
     * Server -> client channel activation.
     */
    let mut rng = DeterministicRng::new(0x91);

    let activation = activate_sender(
        &established,
        &client_public_key,
        APPLICATION_CONTEXT,
        &mut rng,
    )
    .unwrap();

    let (server_encapsulated_key, mut sender) = activation.into_parts();

    assert_eq!(sender.sequence_number(), 0);

    send_application_payload(
        &mut transport,
        SERVER_ACTIVATION_MESSAGE_ID,
        ProtocolDirection::ServerToClient,
        &server_encapsulated_key,
    );

    /*
     * Protected request.
     */
    let request_bytes = receive_frame(&mut transport);
    let request_frame = ProtocolFrame::decode_exact(&request_bytes).unwrap();

    validate_frame(
        &request_frame,
        PROTECTED_REQUEST_MESSAGE_ID,
        MessageClass::Application,
        ProtocolDirection::ClientToServer,
    );

    let request = receiver.open(REQUEST_AAD, request_frame.payload()).unwrap();

    assert_eq!(request.as_slice(), REQUEST);
    assert_eq!(receiver.sequence_number(), 1);

    /*
     * Protected response.
     */
    let response_ciphertext = sender.seal(RESPONSE_AAD, &RESPONSE).unwrap();

    assert_eq!(sender.sequence_number(), 1);

    send_application_payload(
        &mut transport,
        PROTECTED_RESPONSE_MESSAGE_ID,
        ProtocolDirection::ServerToClient,
        &response_ciphertext,
    );

    ServerObservation {
        capability,
        request_len: request.len(),
        receiver_sequence: receiver.sequence_number(),
        sender_sequence: sender.sequence_number(),
        transport: transport.stats(),
    }
}

fn exercise_profile(fixture: ProfileFixture, schedule: Schedule) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();

    assert!(address.ip().is_loopback());

    let server_capability = fixture.capability;
    let server_client_public_key = fixture.client_public_key.clone();
    let server_private_key = fixture.server_private_key.clone();

    let server = thread::spawn(move || {
        run_server(
            listener,
            server_capability,
            server_client_public_key,
            server_private_key,
            schedule,
        )
    });

    let stream = TcpStream::connect(address).unwrap();
    let mut transport = ScheduledTcpTransport::new(stream, schedule);

    let capabilities = ordered_capabilities(fixture.capability);
    let allowed = capabilities;

    let mut handshake = ClientCapabilityHandshake::new(
        CapabilityOffer::new(&capabilities).unwrap(),
        CapabilityPolicy::new(CLIENT_POLICY_ID, &allowed).unwrap(),
    );

    /*
     * Client -> server capability offer.
     */
    let mut payload = [0_u8; HANDSHAKE_PAYLOAD_LEN];
    let offer = handshake.write_response(&mut payload).unwrap();

    send_response(&mut transport, offer, ProtocolDirection::ClientToServer);

    /*
     * Server -> client capability selection.
     */
    let selection_bytes = receive_frame(&mut transport);
    let selection_frame = ProtocolFrame::decode_exact(&selection_bytes).unwrap();

    validate_frame(
        &selection_frame,
        pqc_protocol::CAPABILITY_SELECTION_MESSAGE_ID,
        MessageClass::Handshake,
        ProtocolDirection::ServerToClient,
    );

    let outcome = handshake.handle_frame(&selection_frame).unwrap();
    assert_eq!(outcome.action(), HandlerAction::Continue);

    let client_negotiated = handshake.validated_negotiated().unwrap();

    assert_eq!(client_negotiated.capability(), fixture.capability);
    assert_eq!(client_negotiated.policy_id(), CLIENT_POLICY_ID);

    let established = establish(client_negotiated, CLIENT_SESSION_BYTE, ProtocolRole::Client);

    assert_eq!(established.capability(), fixture.capability);

    /*
     * Client -> server channel activation.
     */
    let mut rng = DeterministicRng::new(0x51);

    let activation = activate_sender(
        &established,
        &fixture.server_public_key,
        APPLICATION_CONTEXT,
        &mut rng,
    )
    .unwrap();

    let (client_encapsulated_key, mut sender) = activation.into_parts();

    assert_eq!(sender.sequence_number(), 0);

    send_application_payload(
        &mut transport,
        CLIENT_ACTIVATION_MESSAGE_ID,
        ProtocolDirection::ClientToServer,
        &client_encapsulated_key,
    );

    /*
     * Server -> client channel activation.
     */
    let server_activation_bytes = receive_frame(&mut transport);
    let server_activation_frame = ProtocolFrame::decode_exact(&server_activation_bytes).unwrap();

    validate_frame(
        &server_activation_frame,
        SERVER_ACTIVATION_MESSAGE_ID,
        MessageClass::Application,
        ProtocolDirection::ServerToClient,
    );

    let mut receiver = activate_receiver(
        &established,
        &fixture.client_private_key,
        server_activation_frame.payload(),
        APPLICATION_CONTEXT,
    )
    .unwrap();

    assert_eq!(receiver.sequence_number(), 0);

    /*
     * Protected request.
     */
    let request_ciphertext = sender.seal(REQUEST_AAD, &REQUEST).unwrap();

    assert_eq!(sender.sequence_number(), 1);

    send_application_payload(
        &mut transport,
        PROTECTED_REQUEST_MESSAGE_ID,
        ProtocolDirection::ClientToServer,
        &request_ciphertext,
    );

    /*
     * Protected response.
     */
    let response_bytes = receive_frame(&mut transport);
    let response_frame = ProtocolFrame::decode_exact(&response_bytes).unwrap();

    validate_frame(
        &response_frame,
        PROTECTED_RESPONSE_MESSAGE_ID,
        MessageClass::Application,
        ProtocolDirection::ServerToClient,
    );

    let response = receiver
        .open(RESPONSE_AAD, response_frame.payload())
        .unwrap();

    assert_eq!(response.as_slice(), RESPONSE);
    assert_eq!(receiver.sequence_number(), 1);

    let client_stats = transport.stats();
    let server_observation = server.join().unwrap();

    assert_eq!(server_observation.capability, fixture.capability);
    assert_eq!(server_observation.request_len, REQUEST.len());
    assert_eq!(server_observation.receiver_sequence, 1);
    assert_eq!(server_observation.sender_sequence, 1);

    for direction in [
        client_stats.transmit,
        client_stats.receive,
        server_observation.transport.transmit,
        server_observation.transport.receive,
    ] {
        assert_eq!(
            direction.calls,
            direction.progress_calls + direction.pending + direction.interrupted,
        );

        assert!(direction.progress_calls > 0);
        assert!(direction.committed_bytes > 0);
        assert!(direction.max_progress > 0);
        assert!(direction.max_progress <= schedule.transfer_limit);
    }

    assert_eq!(
        client_stats.transmit.committed_bytes,
        server_observation.transport.receive.committed_bytes,
    );
    assert_eq!(
        server_observation.transport.transmit.committed_bytes,
        client_stats.receive.committed_bytes,
    );

    match schedule.kind {
        AdverseKind::None => {
            for direction in [
                client_stats.transmit,
                client_stats.receive,
                server_observation.transport.transmit,
                server_observation.transport.receive,
            ] {
                assert_eq!(direction.pending, 0);
                assert_eq!(direction.interrupted, 0);
            }
        }

        AdverseKind::PeriodicPending | AdverseKind::AlternatingPending => {
            for direction in [
                client_stats.transmit,
                client_stats.receive,
                server_observation.transport.transmit,
                server_observation.transport.receive,
            ] {
                assert!(direction.pending > 0);
                assert_eq!(direction.interrupted, 0);
            }
        }

        AdverseKind::PeriodicInterrupted | AdverseKind::AlternatingInterrupted => {
            for direction in [
                client_stats.transmit,
                client_stats.receive,
                server_observation.transport.transmit,
                server_observation.transport.receive,
            ] {
                assert_eq!(direction.pending, 0);
                assert!(direction.interrupted > 0);
            }
        }
    }

    assert_eq!(sender.sequence_number(), 1);
    assert_eq!(receiver.sequence_number(), 1);

    println!(
        "E6|{}|{}|limit={}|schedule={}|\
client_tx_pending={}|client_tx_interrupted={}|\
client_rx_pending={}|client_rx_interrupted={}|\
server_tx_pending={}|server_tx_interrupted={}|\
server_rx_pending={}|server_rx_interrupted={}|\
client_tx_calls={}|client_rx_calls={}|\
server_tx_calls={}|server_rx_calls={}|\
client_tx_progress={}|client_rx_progress={}|\
server_tx_progress={}|server_rx_progress={}|\
client_tx_bytes={}|client_rx_bytes={}|\
server_tx_bytes={}|server_rx_bytes={}|\
request_bytes={}|response_bytes={}|\
client_tx_sequence={}|client_rx_sequence={}|\
server_tx_sequence={}|server_rx_sequence={}|PASS",
        schedule.id,
        fixture.label,
        schedule.transfer_limit,
        schedule.kind.label(),
        client_stats.transmit.pending,
        client_stats.transmit.interrupted,
        client_stats.receive.pending,
        client_stats.receive.interrupted,
        server_observation.transport.transmit.pending,
        server_observation.transport.transmit.interrupted,
        server_observation.transport.receive.pending,
        server_observation.transport.receive.interrupted,
        client_stats.transmit.calls,
        client_stats.receive.calls,
        server_observation.transport.transmit.calls,
        server_observation.transport.receive.calls,
        client_stats.transmit.progress_calls,
        client_stats.receive.progress_calls,
        server_observation.transport.transmit.progress_calls,
        server_observation.transport.receive.progress_calls,
        client_stats.transmit.committed_bytes,
        client_stats.receive.committed_bytes,
        server_observation.transport.transmit.committed_bytes,
        server_observation.transport.receive.committed_bytes,
        REQUEST.len(),
        RESPONSE.len(),
        sender.sequence_number(),
        receiver.sequence_number(),
        server_observation.sender_sequence,
        server_observation.receiver_sequence,
    );
}

#[test]
fn adverse_schedules_preserve_secure_channel_semantics() {
    for schedule in SCHEDULES {
        for fixture in fixtures() {
            exercise_profile(fixture, schedule);
        }
    }
}
