use pqc_ml_dsa::MlDsaPublicKey;
use pqc_protocol::EstablishedProtocolContext;
use rand_core::{CryptoRng, RngCore};

use crate::{
    verify_authentication, AuthenticationChallenge, AuthenticationError, AuthenticationProof,
    AUTHENTICATION_CHALLENGE_BYTES,
};

/// Verifier capable of issuing fresh single-use authentication challenges.
///
/// The verifier borrows the established protocol context and the public key
/// associated by the application with the prover being authenticated.
#[derive(Debug)]
pub struct AuthenticationVerifier<'a> {
    established: &'a EstablishedProtocolContext,
    public_key: &'a MlDsaPublicKey,
    application_context: &'a [u8],
}

impl<'a> AuthenticationVerifier<'a> {
    /// Construct a verifier for one established protocol context, prover
    /// public key, and application context.
    pub const fn new(
        established: &'a EstablishedProtocolContext,
        public_key: &'a MlDsaPublicKey,
        application_context: &'a [u8],
    ) -> Self {
        Self {
            established,
            public_key,
            application_context,
        }
    }

    /// Issue a fresh verifier challenge.
    ///
    /// The returned pending authentication owns the challenge and can be
    /// consumed by exactly one verification attempt.
    pub fn issue_challenge<R>(&self, rng: &mut R) -> PendingAuthentication<'a>
    where
        R: CryptoRng + RngCore,
    {
        let mut challenge = [0u8; AUTHENTICATION_CHALLENGE_BYTES];
        rng.fill_bytes(&mut challenge);

        PendingAuthentication {
            established: self.established,
            public_key: self.public_key,
            application_context: self.application_context,
            challenge: AuthenticationChallenge::from_bytes(challenge),
        }
    }
}

/// Verifier-side state for one issued, not-yet-consumed authentication
/// challenge.
///
/// Verification consumes this value. A challenge therefore cannot be verified
/// twice through this API, regardless of whether the first proof succeeds or
/// fails.
#[derive(Debug)]
pub struct PendingAuthentication<'a> {
    established: &'a EstablishedProtocolContext,
    public_key: &'a MlDsaPublicKey,
    application_context: &'a [u8],
    challenge: AuthenticationChallenge,
}

impl PendingAuthentication<'_> {
    /// Return the verifier challenge that the prover must authenticate.
    pub const fn challenge(&self) -> &AuthenticationChallenge {
        &self.challenge
    }

    /// Consume this pending challenge and verify the supplied proof.
    ///
    /// The challenge is consumed on every verification attempt. A failed
    /// proof must therefore be followed by issuance of a new challenge.
    pub fn verify(self, proof: &AuthenticationProof) -> Result<Authenticated, AuthenticationError> {
        if verify_authentication(
            self.established,
            &self.challenge,
            self.application_context,
            self.public_key,
            proof,
        )? {
            Ok(Authenticated { _private: () })
        } else {
            Err(AuthenticationError::InvalidProof)
        }
    }
}

/// Evidence that a pending authentication challenge was successfully
/// consumed by a valid proof.
///
/// Values of this type can only be produced by successful verifier-side proof
/// verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Authenticated {
    _private: (),
}
