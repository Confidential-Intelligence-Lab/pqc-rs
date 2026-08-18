//! Negotiated post-quantum secure channel over loopback TCP.
//!
//! This example demonstrates the application-facing PQC-rs secure-channel
//! workflow:
//!
//! 1. client and server exchange cryptographic capabilities;
//! 2. protocol policy validates the selected capability;
//! 3. the negotiated capability is retained in established protocol state;
//! 4. the secure-channel layer resolves that capability to a closed HPKE
//!    profile;
//! 5. both directions activate HPKE contexts; and
//! 6. application data is encrypted and authenticated over TCP.
//!
//! The example intentionally uses one registered profile, ML-KEM-768, to keep
//! the protocol flow visible. The secure-channel implementation supports other
//! registered profiles without allowing the peer to directly choose arbitrary
//! KEM, KDF, or AEAD identifiers.

use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use pqc_hpke::MlKemHpke;
use pqc_protocol::{
    CapabilityId, CapabilityOffer, CapabilityPolicy, ClientCapabilityHandshake, HandlerAction,
    PolicyId, ProtocolEncode, ProtocolFrame, ProtocolHandler, ProtocolId, ProtocolResponder,
    ProtocolRole, ProtocolVersion, ServerCapabilityHandshake, SessionId, TypedProtocolSession,
    HPKE_ML_KEM_768,
};
use pqc_secure_channel::{activate_receiver, activate_sender};
use rand_core::OsRng;

const PROTOCOL_ID: ProtocolId = ProtocolId::new(0x1300);
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
const CLIENT_POLICY_ID: PolicyId = PolicyId::new(0x1010);
const SERVER_POLICY_ID: PolicyId = PolicyId::new(0x2020);

const APPLICATION_CONTEXT: &[u8] = b"pqc-rs/example/negotiated-tcp/v1";
const REQUEST_AAD: &[u8] = b"direction=client-to-server";
const RESPONSE_AAD: &[u8] = b"direction=server-to-client";

const REQUEST: &[u8] = b"post-quantum hello from the client";
const RESPONSE: &[u8] = b"authenticated response from the server";

fn write_record(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let len = u32::try_from(bytes.len())?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}

fn read_record(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut len = [0_u8; 4];
    stream.read_exact(&mut len)?;

    let len = usize::try_from(u32::from_be_bytes(len))?;
    let mut bytes = vec![0_u8; len];
    stream.read_exact(&mut bytes)?;

    Ok(bytes)
}

fn write_protocol_frame(
    stream: &mut TcpStream,
    frame: &ProtocolFrame<'_>,
) -> Result<(), Box<dyn Error>> {
    let mut encoded = vec![0_u8; frame.frame_len()];
    let written = frame.encode_into(&mut encoded)?;
    encoded.truncate(written);
    write_record(stream, &encoded)
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

fn main() -> Result<(), Box<dyn Error>> {
    /*
     * Provision independent recipient keys for each channel direction.
     *
     * The capability negotiation below selects the cryptographic profile.
     * Applications do not pass independent KEM/KDF/AEAD identifiers to the
     * secure-channel activation API.
     */
    let kem = MlKemHpke::MlKem768;
    let client_keys = kem.generate_key_pair(&mut OsRng)?;
    let server_keys = kem.generate_key_pair(&mut OsRng)?;

    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;

    let client_public_key_for_server = client_keys.public_key.clone();
    let server_private_key = server_keys.private_key_seed.as_bytes().to_vec();

    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;

        let capabilities = [HPKE_ML_KEM_768];

        let mut handshake = ServerCapabilityHandshake::new(
            CapabilityOffer::new(&capabilities).map_err(|error| format!("{error:?}"))?,
            CapabilityPolicy::new(SERVER_POLICY_ID, &capabilities)
                .map_err(|error| format!("{error:?}"))?,
        );

        /*
         * Receive and validate the client's capability offer.
         */
        let offer_bytes = read_record(&mut stream).map_err(|error| error.to_string())?;
        let offer_frame =
            ProtocolFrame::decode_exact(&offer_bytes).map_err(|error| format!("{error:?}"))?;

        let outcome = handshake
            .handle_frame(&offer_frame)
            .map_err(|error| format!("{error:?}"))?;

        if outcome.action() != HandlerAction::Respond {
            return Err("server did not produce a capability selection".into());
        }

        let negotiated = handshake
            .pending_negotiated()
            .ok_or_else(|| "server has no negotiated capability".to_string())?;

        /*
         * Return the policy-approved capability selection.
         */
        let mut payload = [0_u8; 64];
        let selection = handshake
            .write_response(&mut payload)
            .map_err(|error| format!("{error:?}"))?;

        let selection_frame = ProtocolFrame::current(
            PROTOCOL_VERSION,
            PROTOCOL_ID,
            selection.message_id(),
            selection.message_class(),
            pqc_protocol::ProtocolDirection::ServerToClient,
            selection.payload(),
        )
        .map_err(|error| format!("{error:?}"))?;

        write_protocol_frame(&mut stream, &selection_frame).map_err(|error| error.to_string())?;

        let established = establish(negotiated, 0x42, ProtocolRole::Server);

        /*
         * Activate the client -> server direction.
         */
        let client_encapsulated_key =
            read_record(&mut stream).map_err(|error| error.to_string())?;

        let mut receiver = activate_receiver(
            &established,
            &server_private_key,
            &client_encapsulated_key,
            APPLICATION_CONTEXT,
        )
        .map_err(|error| error.to_string())?;

        /*
         * Activate the server -> client direction.
         */
        let activation = activate_sender(
            &established,
            &client_public_key_for_server,
            APPLICATION_CONTEXT,
            &mut OsRng,
        )
        .map_err(|error| error.to_string())?;

        let (server_encapsulated_key, mut sender) = activation.into_parts();

        write_record(&mut stream, &server_encapsulated_key).map_err(|error| error.to_string())?;

        /*
         * Receive an authenticated application request.
         */
        let request_ciphertext = read_record(&mut stream).map_err(|error| error.to_string())?;

        let request = receiver
            .open(REQUEST_AAD, &request_ciphertext)
            .map_err(|error| error.to_string())?;

        if request != REQUEST {
            return Err("server received unexpected plaintext".into());
        }

        /*
         * Send an authenticated application response.
         */
        let response_ciphertext = sender
            .seal(RESPONSE_AAD, RESPONSE)
            .map_err(|error| error.to_string())?;

        write_record(&mut stream, &response_ciphertext).map_err(|error| error.to_string())?;

        Ok(())
    });

    let mut stream = TcpStream::connect(address)?;

    let capabilities: [CapabilityId; 1] = [HPKE_ML_KEM_768];

    let mut handshake = ClientCapabilityHandshake::new(
        CapabilityOffer::new(&capabilities)?,
        CapabilityPolicy::new(CLIENT_POLICY_ID, &capabilities)?,
    );

    /*
     * Send the client's capability offer.
     */
    let mut payload = [0_u8; 64];
    let offer = handshake.write_response(&mut payload)?;

    let offer_frame = ProtocolFrame::current(
        PROTOCOL_VERSION,
        PROTOCOL_ID,
        offer.message_id(),
        offer.message_class(),
        pqc_protocol::ProtocolDirection::ClientToServer,
        offer.payload(),
    )?;

    write_protocol_frame(&mut stream, &offer_frame)?;

    /*
     * Receive and validate the server's capability selection.
     */
    let selection_bytes = read_record(&mut stream)?;
    let selection_frame = ProtocolFrame::decode_exact(&selection_bytes)?;

    let outcome = handshake.handle_frame(&selection_frame)?;

    if outcome.action() != HandlerAction::Continue {
        return Err("client rejected the capability selection".into());
    }

    let negotiated = handshake
        .validated_negotiated()
        .ok_or("client has no validated negotiated capability")?;

    let established = establish(negotiated, 0x41, ProtocolRole::Client);

    /*
     * Activate the client -> server direction.
     */
    let activation = activate_sender(
        &established,
        &server_keys.public_key,
        APPLICATION_CONTEXT,
        &mut OsRng,
    )?;

    let (client_encapsulated_key, mut sender) = activation.into_parts();
    write_record(&mut stream, &client_encapsulated_key)?;

    /*
     * Activate the server -> client direction.
     */
    let server_encapsulated_key = read_record(&mut stream)?;

    let mut receiver = activate_receiver(
        &established,
        client_keys.private_key_seed.as_bytes(),
        &server_encapsulated_key,
        APPLICATION_CONTEXT,
    )?;

    /*
     * Exchange protected application data.
     */
    let request_ciphertext = sender.seal(REQUEST_AAD, REQUEST)?;
    write_record(&mut stream, &request_ciphertext)?;

    let response_ciphertext = read_record(&mut stream)?;
    let response = receiver.open(RESPONSE_AAD, &response_ciphertext)?;

    if response != RESPONSE {
        return Err("client received unexpected plaintext".into());
    }

    server
        .join()
        .map_err(|_| "server thread panicked")?
        .map_err(|error| -> Box<dyn Error> { error.into() })?;

    println!("negotiated secure channel over loopback TCP: pass");
    println!(
        "selected capability: {:#06x}",
        established.capability().value()
    );
    println!("request authenticated and decrypted: pass");
    println!("response authenticated and decrypted: pass");

    Ok(())
}
