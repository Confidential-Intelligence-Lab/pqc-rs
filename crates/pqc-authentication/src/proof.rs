use pqc_ml_dsa::{MlDsa, MlDsaPrivateKey, MlDsaPublicKey, MlDsaSignature};
use pqc_protocol::EstablishedProtocolContext;
use rand_core::{CryptoRng, RngCore};

use crate::{
    authentication_transcript, resolve_authentication_profile, AuthenticationChallenge,
    AuthenticationError,
};

const ML_DSA_AUTHENTICATION_CONTEXT: &[u8] = b"PQC-FORGE-AUTH-v1";

/// ML-DSA proof over a canonical PQC-Forge authentication transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationProof {
    signature: MlDsaSignature,
}

impl AuthenticationProof {
    /// Return the ML-DSA signature carried by this proof.
    pub const fn signature(&self) -> &MlDsaSignature {
        &self.signature
    }

    /// Construct a proof from a previously decoded ML-DSA signature.
    pub const fn from_signature(signature: MlDsaSignature) -> Self {
        Self { signature }
    }
}

/// Generate a deterministic authentication proof.
///
/// Deterministic signing is useful for reproducibility and tests. Applications
/// should normally prefer [`prove_authentication_hedged`].
pub fn prove_authentication_deterministic(
    established: &EstablishedProtocolContext,
    challenge: &AuthenticationChallenge,
    application_context: &[u8],
    private_key: &MlDsaPrivateKey,
) -> Result<AuthenticationProof, AuthenticationError> {
    let profile = resolve_authentication_profile(established)?;
    let implementation = MlDsa::new(profile.parameter_set());
    let transcript = authentication_transcript(established, challenge, application_context)?;

    let signature = implementation
        .sign_deterministic(private_key, &transcript, ML_DSA_AUTHENTICATION_CONTEXT)
        .map_err(AuthenticationError::MlDsa)?;

    Ok(AuthenticationProof { signature })
}

/// Generate a hedged authentication proof using fresh caller-supplied
/// cryptographic randomness.
pub fn prove_authentication_hedged<R>(
    established: &EstablishedProtocolContext,
    challenge: &AuthenticationChallenge,
    application_context: &[u8],
    private_key: &MlDsaPrivateKey,
    rng: &mut R,
) -> Result<AuthenticationProof, AuthenticationError>
where
    R: CryptoRng + RngCore,
{
    let profile = resolve_authentication_profile(established)?;
    let implementation = MlDsa::new(profile.parameter_set());
    let transcript = authentication_transcript(established, challenge, application_context)?;

    let signature = implementation
        .sign_hedged(private_key, &transcript, ML_DSA_AUTHENTICATION_CONTEXT, rng)
        .map_err(AuthenticationError::MlDsa)?;

    Ok(AuthenticationProof { signature })
}

/// Verify an authentication proof against the exact established context,
/// verifier challenge, and application context.
pub fn verify_authentication(
    established: &EstablishedProtocolContext,
    challenge: &AuthenticationChallenge,
    application_context: &[u8],
    public_key: &MlDsaPublicKey,
    proof: &AuthenticationProof,
) -> Result<bool, AuthenticationError> {
    let profile = resolve_authentication_profile(established)?;
    let implementation = MlDsa::new(profile.parameter_set());
    let transcript = authentication_transcript(established, challenge, application_context)?;

    implementation
        .verify(
            public_key,
            &transcript,
            ML_DSA_AUTHENTICATION_CONTEXT,
            proof.signature(),
        )
        .map_err(AuthenticationError::MlDsa)
}
