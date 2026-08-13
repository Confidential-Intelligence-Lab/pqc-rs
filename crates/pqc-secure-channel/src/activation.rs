//! Profile-driven HPKE secure-channel activation.

use core::fmt;

use pqc_hpke::{
    context::{ReceiverContext, SenderContext},
    hybrid_setup::{setup_hybrid_base_receiver, setup_hybrid_base_sender},
    setup::{setup_base_receiver_with_suite, setup_base_sender_with_suite},
    HpkeError, MlKemHpke,
};
use pqc_protocol::NegotiatedCapability;
use rand_core::{CryptoRng, RngCore};

use crate::{HpkeProfileKind, ResolvedHpkeProfile};

/// Error returned by secure-channel activation or message processing.
#[derive(Debug)]
pub enum SecureChannelError {
    /// The underlying HPKE operation failed.
    Hpke(HpkeError),
}

impl fmt::Display for SecureChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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

/// Activate the sender side of a secure channel from a resolved profile.
///
/// The cryptographic KEM, KDF, and AEAD are determined entirely by `profile`;
/// callers cannot independently select cryptographic algorithms.
///
/// `info` is passed directly to the HPKE key schedule. A subsequent protocol
/// stage will define canonical binding of protocol establishment evidence into
/// this input.
///
/// # Errors
///
/// Returns [`SecureChannelError`] if recipient key validation, encapsulation,
/// randomness generation, or HPKE key scheduling fails.
pub fn activate_sender<R>(
    profile: ResolvedHpkeProfile,
    recipient_public_key: &[u8],
    info: &[u8],
    rng: &mut R,
) -> Result<SenderActivation, SecureChannelError>
where
    R: CryptoRng + RngCore,
{
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

/// Activate the receiver side of a secure channel from a resolved profile.
///
/// The receiver must use the same resolved profile and HPKE `info` value as
/// the sender.
///
/// # Errors
///
/// Returns [`SecureChannelError`] if recipient private material,
/// encapsulated-key validation, decapsulation, or HPKE key scheduling fails.
pub fn activate_receiver(
    profile: ResolvedHpkeProfile,
    recipient_private_key: &[u8],
    encapsulated_key: &[u8],
    info: &[u8],
) -> Result<SecureChannelReceiver, SecureChannelError> {
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
    use crate::resolve_hpke_profile;
    use pqc_hpke::hybrid_kem::HybridKem;
    use pqc_protocol::{
        negotiate_policy_permitted_common, CapabilityId, CapabilityOffer, CapabilityPolicy,
        PolicyId, HPKE_ML_KEM_1024, HPKE_ML_KEM_768, HPKE_ML_KEM_768_X25519,
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

    fn negotiated(capability: CapabilityId) -> NegotiatedCapability {
        let local_ids = [capability];
        let peer_ids = [capability];
        let allowed = [capability];

        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(PolicyId::new(7), &allowed).unwrap();

        negotiate_policy_permitted_common(local, peer, policy).unwrap()
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

    fn exercise_round_trip(profile: ResolvedHpkeProfile, public_key: &[u8], private_key: &[u8]) {
        let mut rng = DeterministicRng::new(0x41);

        let sender_activation =
            activate_sender(profile, public_key, b"activation-test", &mut rng).unwrap();

        let (encapsulated_key, mut sender) = sender_activation.into_parts();

        let mut receiver =
            activate_receiver(profile, private_key, &encapsulated_key, b"activation-test").unwrap();

        assert_eq!(sender.profile(), profile);
        assert_eq!(receiver.profile(), profile);
        assert_eq!(sender.negotiated(), profile.negotiated());
        assert_eq!(receiver.negotiated(), profile.negotiated());

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
        profile: ResolvedHpkeProfile,
        public_key: &[u8],
        private_key: &[u8],
    ) {
        let mut rng = DeterministicRng::new(0x61);

        let sender_activation =
            activate_sender(profile, public_key, b"negative-test", &mut rng).unwrap();

        let (encapsulated_key, mut sender) = sender_activation.into_parts();

        let mut receiver =
            activate_receiver(profile, private_key, &encapsulated_key, b"negative-test").unwrap();

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
        let profile = resolve_hpke_profile(negotiated(HPKE_ML_KEM_768)).unwrap();
        let (public_key, private_key) = ml_kem_key_material(MlKemHpke::MlKem768, 0x11);

        exercise_round_trip(profile, &public_key, &private_key);
        exercise_authentication_failures(profile, &public_key, &private_key);
    }

    #[test]
    fn ml_kem_1024_profile_activates_and_protects_messages() {
        let profile = resolve_hpke_profile(negotiated(HPKE_ML_KEM_1024)).unwrap();
        let (public_key, private_key) = ml_kem_key_material(MlKemHpke::MlKem1024, 0x21);

        exercise_round_trip(profile, &public_key, &private_key);
        exercise_authentication_failures(profile, &public_key, &private_key);
    }

    #[test]
    fn hybrid_profile_activates_and_protects_messages() {
        let profile = resolve_hpke_profile(negotiated(HPKE_ML_KEM_768_X25519)).unwrap();
        let kem = HybridKem::MlKem768X25519;
        let (public_key, private_key) = hybrid_key_material(kem, 0x31);

        exercise_round_trip(profile, &public_key, &private_key);
        exercise_authentication_failures(profile, &public_key, &private_key);
    }

    #[test]
    fn malformed_recipient_material_is_rejected() {
        let profile = resolve_hpke_profile(negotiated(HPKE_ML_KEM_768)).unwrap();

        let mut rng = DeterministicRng::new(0x51);

        assert!(activate_sender(profile, &[0_u8; 7], b"bad-key", &mut rng).is_err());

        let (public_key, _) = ml_kem_key_material(MlKemHpke::MlKem768, 0x51);

        let sender_activation =
            activate_sender(profile, &public_key, b"bad-private", &mut rng).unwrap();

        assert!(activate_receiver(
            profile,
            &[0_u8; 7],
            sender_activation.encapsulated_key(),
            b"bad-private",
        )
        .is_err());

        assert!(
            activate_receiver(profile, &[0_u8; 64], &[0_u8; 7], b"bad-encapsulation",).is_err()
        );
    }
}
