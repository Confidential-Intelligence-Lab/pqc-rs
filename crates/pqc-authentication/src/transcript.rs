use pqc_protocol::EstablishedProtocolContext;

use crate::AuthenticationError;

/// Size in bytes of a PQC-Forge authentication challenge.
pub const AUTHENTICATION_CHALLENGE_BYTES: usize = 32;

/// Maximum application-context length accepted by the canonical transcript.
pub const MAX_APPLICATION_CONTEXT_BYTES: usize = u16::MAX as usize;

const TRANSCRIPT_DOMAIN: &[u8] = b"PQC-FORGE-AUTH-TRANSCRIPT";
const TRANSCRIPT_VERSION: u8 = 1;

/// Fresh verifier-provided challenge bound into an authentication proof.
///
/// Challenge generation and single-use lifecycle management are deliberately
/// left to the verifier. This type preserves the fixed-width challenge value
/// used by the canonical authentication transcript.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthenticationChallenge([u8; AUTHENTICATION_CHALLENGE_BYTES]);

impl AuthenticationChallenge {
    /// Construct a challenge from its fixed-width representation.
    pub const fn from_bytes(bytes: [u8; AUTHENTICATION_CHALLENGE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Return the challenge bytes.
    pub const fn as_bytes(&self) -> &[u8; AUTHENTICATION_CHALLENGE_BYTES] {
        &self.0
    }
}

/// Construct the canonical bytes authenticated by the PQC-Forge
/// challenge-response ceremony.
///
/// Fixed-width integer fields use network byte order. The variable-width
/// application context is preceded by a 16-bit length. The transcript binds
/// the proof to the established session, protocol and version, negotiated
/// policy and capability, verifier challenge, and application context.
pub fn authentication_transcript(
    established: &EstablishedProtocolContext,
    challenge: &AuthenticationChallenge,
    application_context: &[u8],
) -> Result<Vec<u8>, AuthenticationError> {
    let application_context_len = u16::try_from(application_context.len()).map_err(|_| {
        AuthenticationError::ApplicationContextTooLong {
            length: application_context.len(),
            maximum: MAX_APPLICATION_CONTEXT_BYTES,
        }
    })?;
    let session = established.session();
    let protocol_version = session.protocol_version();

    let mut transcript = Vec::with_capacity(
        TRANSCRIPT_DOMAIN.len()
            + 1
            + 16
            + 2
            + 2
            + 2
            + 2
            + 2
            + AUTHENTICATION_CHALLENGE_BYTES
            + 2
            + application_context.len(),
    );

    transcript.extend_from_slice(TRANSCRIPT_DOMAIN);
    transcript.push(TRANSCRIPT_VERSION);
    transcript.extend_from_slice(session.session_id().as_bytes());
    transcript.extend_from_slice(&session.protocol_id().value().to_be_bytes());
    transcript.extend_from_slice(&protocol_version.major().to_be_bytes());
    transcript.extend_from_slice(&protocol_version.minor().to_be_bytes());
    transcript.extend_from_slice(&established.policy_id().value().to_be_bytes());
    transcript.extend_from_slice(&established.capability().value().to_be_bytes());
    transcript.extend_from_slice(challenge.as_bytes());

    transcript.extend_from_slice(&application_context_len.to_be_bytes());
    transcript.extend_from_slice(application_context);

    Ok(transcript)
}
