//! Profile-driven HPKE secure-channel activation.

use core::fmt;

use pqc_hpke::{
    context::{ReceiverContext, SenderContext},
    hybrid_setup::{setup_hybrid_base_receiver, setup_hybrid_base_sender},
    setup::{setup_base_receiver_with_suite, setup_base_sender_with_suite},
    HpkeError, MlKemHpke,
};
use pqc_protocol::{EstablishedProtocolContext, NegotiatedCapability};
use rand_core::{CryptoRng, RngCore};

use crate::{
    resolve_hpke_profile, HpkeProfileKind, HpkeProfileResolutionError, ResolvedHpkeProfile,
    SecureChannelBinding,
};

/// Error returned by secure-channel activation or message processing.
#[derive(Debug)]
pub enum SecureChannelError {
    /// Negotiated protocol evidence could not be resolved to a supported HPKE profile.
    ProfileResolution(HpkeProfileResolutionError),
    /// The underlying HPKE operation failed.
    Hpke(HpkeError),
}

impl fmt::Display for SecureChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfileResolution(error) => {
                write!(formatter, "HPKE profile resolution failed: {error}")
            }
            Self::Hpke(error) => write!(formatter, "HPKE operation failed: {error}"),
        }
    }
}

impl std::error::Error for SecureChannelError {}

impl From<HpkeError> for SecureChannelError {
    fn from(error: HpkeError) -> Self {
        Self::Hpke(error)
    }
}

impl From<HpkeProfileResolutionError> for SecureChannelError {
    fn from(error: HpkeProfileResolutionError) -> Self {
        Self::ProfileResolution(error)
    }
}

/// Activated sender side of a negotiated secure channel.
///
/// Construction requires a previously resolved HPKE profile. The profile is
/// retained with the cryptographic context so that the negotiation and policy
/// evidence authorizing the channel remains associated with it.
pub struct SecureChannelSender {
    profile: ResolvedHpkeProfile,
    context: SenderContext,
}

impl SecureChannelSender {
    /// Return the profile that authorized this channel.
    pub const fn profile(&self) -> ResolvedHpkeProfile {
        self.profile
    }

    /// Return the negotiation evidence that authorized this channel.
    pub const fn negotiated(&self) -> NegotiatedCapability {
        self.profile.negotiated()
    }

    /// Encrypt and authenticate one application message.
    ///
    /// # Errors
    ///
    /// Returns [`SecureChannelError`] if HPKE encryption fails or the context
    /// has exhausted its message sequence.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SecureChannelError> {
        self.context.seal(aad, plaintext).map_err(Into::into)
    }

    /// Return the sequence number that will be used by the next message.
    pub const fn sequence_number(&self) -> u64 {
        self.context.sequence_number()
    }

    /// Return whether this channel has consumed its final sequence number.
    pub const fn is_exhausted(&self) -> bool {
        self.context.is_exhausted()
    }
}

/// Activated receiver side of a negotiated secure channel.
///
/// The resolved profile is retained alongside the receiver context.
pub struct SecureChannelReceiver {
    profile: ResolvedHpkeProfile,
    context: ReceiverContext,
}

impl SecureChannelReceiver {
    /// Return the profile that authorized this channel.
    pub const fn profile(&self) -> ResolvedHpkeProfile {
        self.profile
    }

    /// Return the negotiation evidence that authorized this channel.
    pub const fn negotiated(&self) -> NegotiatedCapability {
        self.profile.negotiated()
    }

    /// Authenticate and decrypt one application message.
    ///
    /// # Errors
    ///
    /// Returns [`SecureChannelError`] when authentication or decryption fails
    /// or the context has exhausted its message sequence.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SecureChannelError> {
        self.context.open(aad, ciphertext).map_err(Into::into)
    }

    /// Return the sequence number that will be used by the next message.
    pub const fn sequence_number(&self) -> u64 {
        self.context.sequence_number()
    }

    /// Return whether this channel has consumed its final sequence number.
    pub const fn is_exhausted(&self) -> bool {
        self.context.is_exhausted()
    }
}

/// Result of activating the sender side of a secure channel.
pub struct SenderActivation {
    encapsulated_key: Vec<u8>,
    channel: SecureChannelSender,
}

impl SenderActivation {
    /// Borrow the serialized HPKE encapsulated key that must be delivered to
    /// the receiver.
    pub fn encapsulated_key(&self) -> &[u8] {
        &self.encapsulated_key
    }

    /// Consume the activation result and return its encapsulated key and
    /// activated sender channel.
    pub fn into_parts(self) -> (Vec<u8>, SecureChannelSender) {
        (self.encapsulated_key, self.channel)
    }
}

/// Activate the sender side of an established negotiated secure channel.
///
/// The HPKE profile is resolved internally from the validated negotiation
/// evidence retained by `established`. The HPKE key-schedule context is
/// constructed canonically from the peer-agreed protocol identifier, protocol
/// version, negotiated capability, and `application_context`.
///
/// Callers cannot independently supply a KEM, KDF, AEAD, resolved profile, or
/// raw HPKE `info` value.
///
/// # Errors
///
/// Returns [`SecureChannelError`] if profile resolution, recipient-key
/// validation, encapsulation, randomness generation, or HPKE key scheduling
/// fails.
pub fn activate_sender<R>(
    established: &EstablishedProtocolContext,
    recipient_public_key: &[u8],
    application_context: &[u8],
    rng: &mut R,
) -> Result<SenderActivation, SecureChannelError>
where
    R: CryptoRng + RngCore,
{
    let profile = resolve_hpke_profile(established.negotiated())?;
    let binding = SecureChannelBinding::new(established, application_context);
    let info = binding.as_bytes();

    let (encapsulated_key, context) = match profile.kind() {
        HpkeProfileKind::MlKem768 { suite } => {
            let setup = setup_base_sender_with_suite(
                MlKemHpke::MlKem768,
                suite,
                recipient_public_key,
                info,
                rng,
            )?;
            (setup.encapsulated_key, setup.context)
        }

        HpkeProfileKind::MlKem1024 { suite } => {
            let setup = setup_base_sender_with_suite(
                MlKemHpke::MlKem1024,
                suite,
                recipient_public_key,
                info,
                rng,
            )?;
            (setup.encapsulated_key, setup.context)
        }

        HpkeProfileKind::MlKem768X25519 { kem, suite } => {
            let setup = setup_hybrid_base_sender(kem, suite, recipient_public_key, info, rng)?;
            (setup.encapsulated_key, setup.context)
        }
    };

    Ok(SenderActivation {
        encapsulated_key,
        channel: SecureChannelSender { profile, context },
    })
}

/// Activate the receiver side of an established negotiated secure channel.
///
/// The HPKE profile is resolved internally from the validated negotiation
/// evidence retained by `established`. The receiver independently constructs
/// the same canonical HPKE key-schedule binding from the peer-agreed protocol
/// identifier, protocol version, negotiated capability, and
/// `application_context`.
///
/// These shared values must match those used by the sender. Endpoint-local
/// session identifiers, participant roles, and policy identifiers are not part
/// of the shared cryptographic binding.
///
/// # Errors
///
/// Returns [`SecureChannelError`] if profile resolution, recipient private
/// material validation, decapsulation, or HPKE key scheduling fails.
pub fn activate_receiver(
    established: &EstablishedProtocolContext,
    recipient_private_key: &[u8],
    encapsulated_key: &[u8],
    application_context: &[u8],
) -> Result<SecureChannelReceiver, SecureChannelError> {
    let profile = resolve_hpke_profile(established.negotiated())?;
    let binding = SecureChannelBinding::new(established, application_context);
    let info = binding.as_bytes();

    let context = match profile.kind() {
        HpkeProfileKind::MlKem768 { suite } => setup_base_receiver_with_suite(
            MlKemHpke::MlKem768,
            suite,
            recipient_private_key,
            encapsulated_key,
            info,
        )?,

        HpkeProfileKind::MlKem1024 { suite } => setup_base_receiver_with_suite(
            MlKemHpke::MlKem1024,
            suite,
            recipient_private_key,
            encapsulated_key,
            info,
        )?,

        HpkeProfileKind::MlKem768X25519 { kem, suite } => {
            setup_hybrid_base_receiver(kem, suite, recipient_private_key, encapsulated_key, info)?
        }
    };

    Ok(SecureChannelReceiver { profile, context })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqc_hpke::hybrid_kem::HybridKem;
    use pqc_protocol::{
        negotiate_policy_permitted_common, CapabilityId, CapabilityOffer, CapabilityPolicy,
        EstablishedProtocolContext, PolicyId, ProtocolId, ProtocolRole, ProtocolVersion, SessionId,
        TypedProtocolSession, HPKE_ML_KEM_1024, HPKE_ML_KEM_768, HPKE_ML_KEM_768_X25519,
    };
    use rand_core::{CryptoRng, Error as RandError, RngCore};

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

    fn established(
        capability: CapabilityId,
        policy_id: PolicyId,
        session_byte: u8,
        protocol_id: ProtocolId,
        protocol_version: ProtocolVersion,
        role: ProtocolRole,
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
            protocol_version,
            role,
        )
        .begin_establishment()
        .establish_with_negotiation(negotiated)
    }

    fn endpoint_pair(
        capability: CapabilityId,
    ) -> (EstablishedProtocolContext, EstablishedProtocolContext) {
        let protocol_id = ProtocolId::new(0x1300);
        let version = ProtocolVersion::new(1, 0);

        let client = established(
            capability,
            PolicyId::new(0x101),
            0x41,
            protocol_id,
            version,
            ProtocolRole::Client,
        );

        let server = established(
            capability,
            PolicyId::new(0x202),
            0x42,
            protocol_id,
            version,
            ProtocolRole::Server,
        );

        (client, server)
    }

    fn ml_kem_key_material(kem: MlKemHpke, seed: u8) -> (Vec<u8>, Vec<u8>) {
        let key_pair = kem.derive_key_pair(&[seed; 64]).unwrap();

        (
            key_pair.public_key,
            key_pair.private_key_seed.as_bytes().to_vec(),
        )
    }

    fn hybrid_key_material(kem: HybridKem, seed: u8) -> (Vec<u8>, Vec<u8>) {
        let key_pair = kem.derive_key_pair(&[seed; 64]).unwrap();

        (
            key_pair.public_key,
            key_pair.private_seed.as_bytes().to_vec(),
        )
    }

    fn exercise_round_trip(
        client: &EstablishedProtocolContext,
        server: &EstablishedProtocolContext,
        public_key: &[u8],
        private_key: &[u8],
    ) {
        let mut rng = DeterministicRng::new(0x41);

        let sender_activation =
            activate_sender(client, public_key, b"activation-test", &mut rng).unwrap();

        let (encapsulated_key, mut sender) = sender_activation.into_parts();

        let mut receiver =
            activate_receiver(server, private_key, &encapsulated_key, b"activation-test").unwrap();

        assert_eq!(sender.negotiated().capability(), client.capability());
        assert_eq!(receiver.negotiated().capability(), server.capability());

        /*
         * Endpoint-local evidence is deliberately different, but both sides
         * derive the same HPKE binding from their shared protocol semantics.
         */
        assert_ne!(client.session().session_id(), server.session().session_id());
        assert_ne!(client.session().role(), server.session().role());
        assert_ne!(client.policy_id(), server.policy_id());

        assert_eq!(sender.sequence_number(), 0);
        assert_eq!(receiver.sequence_number(), 0);

        let ciphertext = sender
            .seal(b"application-aad", b"protected application message")
            .unwrap();

        assert_eq!(sender.sequence_number(), 1);

        let plaintext = receiver.open(b"application-aad", &ciphertext).unwrap();

        assert_eq!(plaintext, b"protected application message");
        assert_eq!(receiver.sequence_number(), 1);
    }

    fn exercise_authentication_failures(
        client: &EstablishedProtocolContext,
        server: &EstablishedProtocolContext,
        public_key: &[u8],
        private_key: &[u8],
    ) {
        let mut rng = DeterministicRng::new(0x61);

        let sender_activation =
            activate_sender(client, public_key, b"negative-test", &mut rng).unwrap();

        let (encapsulated_key, mut sender) = sender_activation.into_parts();

        let mut receiver =
            activate_receiver(server, private_key, &encapsulated_key, b"negative-test").unwrap();

        let ciphertext = sender.seal(b"correct-aad", b"message").unwrap();

        let mut modified = ciphertext.clone();
        modified[0] ^= 1;

        assert!(receiver.open(b"correct-aad", &modified).is_err());
        assert_eq!(receiver.sequence_number(), 0);

        assert!(receiver.open(b"wrong-aad", &ciphertext).is_err());
        assert_eq!(receiver.sequence_number(), 0);

        assert_eq!(
            receiver.open(b"correct-aad", &ciphertext).unwrap(),
            b"message"
        );
        assert_eq!(receiver.sequence_number(), 1);
    }

    #[test]
    fn ml_kem_768_profile_activates_and_protects_messages() {
        let (client, server) = endpoint_pair(HPKE_ML_KEM_768);
        let (public_key, private_key) = ml_kem_key_material(MlKemHpke::MlKem768, 0x11);

        exercise_round_trip(&client, &server, &public_key, &private_key);

        exercise_authentication_failures(&client, &server, &public_key, &private_key);
    }

    #[test]
    fn ml_kem_1024_profile_activates_and_protects_messages() {
        let (client, server) = endpoint_pair(HPKE_ML_KEM_1024);
        let (public_key, private_key) = ml_kem_key_material(MlKemHpke::MlKem1024, 0x21);

        exercise_round_trip(&client, &server, &public_key, &private_key);

        exercise_authentication_failures(&client, &server, &public_key, &private_key);
    }

    #[test]
    fn hybrid_profile_activates_and_protects_messages() {
        let (client, server) = endpoint_pair(HPKE_ML_KEM_768_X25519);

        let kem = HybridKem::MlKem768X25519;
        let (public_key, private_key) = hybrid_key_material(kem, 0x31);

        exercise_round_trip(&client, &server, &public_key, &private_key);

        exercise_authentication_failures(&client, &server, &public_key, &private_key);
    }

    #[test]
    fn malformed_recipient_material_is_rejected() {
        let (client, server) = endpoint_pair(HPKE_ML_KEM_768);

        let mut rng = DeterministicRng::new(0x51);

        assert!(activate_sender(&client, &[0_u8; 7], b"bad-key", &mut rng,).is_err());

        let (public_key, _) = ml_kem_key_material(MlKemHpke::MlKem768, 0x51);

        let sender_activation =
            activate_sender(&client, &public_key, b"bad-private", &mut rng).unwrap();

        assert!(activate_receiver(
            &server,
            &[0_u8; 7],
            sender_activation.encapsulated_key(),
            b"bad-private",
        )
        .is_err());

        assert!(
            activate_receiver(&server, &[0_u8; 64], &[0_u8; 7], b"bad-encapsulation",).is_err()
        );
    }

    #[test]
    fn different_application_context_breaks_channel_binding() {
        let (client, server) = endpoint_pair(HPKE_ML_KEM_768);
        let (public_key, private_key) = ml_kem_key_material(MlKemHpke::MlKem768, 0x71);

        let mut rng = DeterministicRng::new(0x71);

        let sender_activation =
            activate_sender(&client, &public_key, b"application-a", &mut rng).unwrap();

        let (encapsulated_key, mut sender) = sender_activation.into_parts();

        let mut receiver =
            activate_receiver(&server, &private_key, &encapsulated_key, b"application-b").unwrap();

        let ciphertext = sender.seal(b"aad", b"message").unwrap();

        assert!(receiver.open(b"aad", &ciphertext).is_err());
        assert_eq!(receiver.sequence_number(), 0);
    }

    #[test]
    fn different_protocol_id_breaks_channel_binding() {
        let client = established(
            HPKE_ML_KEM_768,
            PolicyId::new(1),
            0x41,
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Client,
        );

        let server = established(
            HPKE_ML_KEM_768,
            PolicyId::new(2),
            0x42,
            ProtocolId::new(0x1301),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Server,
        );

        let (public_key, private_key) = ml_kem_key_material(MlKemHpke::MlKem768, 0x72);

        let mut rng = DeterministicRng::new(0x72);

        let sender_activation = activate_sender(&client, &public_key, b"app", &mut rng).unwrap();

        let (encapsulated_key, mut sender) = sender_activation.into_parts();

        let mut receiver =
            activate_receiver(&server, &private_key, &encapsulated_key, b"app").unwrap();

        let ciphertext = sender.seal(b"aad", b"message").unwrap();

        assert!(receiver.open(b"aad", &ciphertext).is_err());
        assert_eq!(receiver.sequence_number(), 0);
    }

    #[test]
    fn different_protocol_version_breaks_channel_binding() {
        let client = established(
            HPKE_ML_KEM_768,
            PolicyId::new(1),
            0x41,
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Client,
        );

        let server = established(
            HPKE_ML_KEM_768,
            PolicyId::new(2),
            0x42,
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 1),
            ProtocolRole::Server,
        );

        let (public_key, private_key) = ml_kem_key_material(MlKemHpke::MlKem768, 0x73);

        let mut rng = DeterministicRng::new(0x73);

        let sender_activation = activate_sender(&client, &public_key, b"app", &mut rng).unwrap();

        let (encapsulated_key, mut sender) = sender_activation.into_parts();

        let mut receiver =
            activate_receiver(&server, &private_key, &encapsulated_key, b"app").unwrap();

        let ciphertext = sender.seal(b"aad", b"message").unwrap();

        assert!(receiver.open(b"aad", &ciphertext).is_err());
        assert_eq!(receiver.sequence_number(), 0);
    }
    #[test]
    fn different_negotiated_capability_fails_closed() {
        let client = established(
            HPKE_ML_KEM_768,
            PolicyId::new(1),
            0x41,
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Client,
        );

        let server = established(
            HPKE_ML_KEM_1024,
            PolicyId::new(2),
            0x42,
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Server,
        );

        let (public_key, private_key) = ml_kem_key_material(MlKemHpke::MlKem768, 0x74);

        let mut rng = DeterministicRng::new(0x74);

        let sender_activation = activate_sender(&client, &public_key, b"app", &mut rng).unwrap();

        assert!(activate_receiver(
            &server,
            &private_key,
            sender_activation.encapsulated_key(),
            b"app",
        )
        .is_err());
    }

    #[test]
    fn unsupported_established_capability_is_rejected_before_hpke_setup() {
        let unsupported = CapabilityId::new(0xfefe);

        let context = established(
            unsupported,
            PolicyId::new(3),
            0x43,
            ProtocolId::new(0x1300),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Client,
        );

        let mut rng = DeterministicRng::new(0x75);

        let error = match activate_sender(&context, &[0_u8; 32], b"app", &mut rng) {
            Ok(_) => panic!("unsupported capability unexpectedly activated"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            SecureChannelError::ProfileResolution(
                HpkeProfileResolutionError::UnsupportedCapability {
                    capability
                }
            ) if capability == unsupported
        ));
    }
}
