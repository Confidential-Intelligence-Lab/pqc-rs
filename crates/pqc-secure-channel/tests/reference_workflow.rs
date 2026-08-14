use pqc_hpke::{hybrid_kem::HybridKem, MlKemHpke};
use pqc_protocol::{
    negotiate_policy_permitted_common, CapabilityId, CapabilityOffer, CapabilityPolicy,
    EstablishedProtocolContext, PolicyId, ProtocolId, ProtocolRole, ProtocolVersion, SessionId,
    TypedProtocolSession, HPKE_ML_KEM_1024, HPKE_ML_KEM_768, HPKE_ML_KEM_768_X25519,
};
use pqc_secure_channel::{activate_receiver, activate_sender};
use rand_core::{CryptoRng, Error as RandError, RngCore};

const PROTOCOL_ID: ProtocolId = ProtocolId::new(0x1300);
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

const CLIENT_POLICY_ID: PolicyId = PolicyId::new(0x1010);
const SERVER_POLICY_ID: PolicyId = PolicyId::new(0x2020);

const CLIENT_SESSION_BYTE: u8 = 0x41;
const SERVER_SESSION_BYTE: u8 = 0x42;

const APPLICATION_CONTEXT: &[u8] = b"pqc-forge-reference-workflow";
const AAD: &[u8] = b"pqc-forge-reference-aad";
const PAYLOAD: [u8; 1024] = [0xa5; 1024];

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
    capability: CapabilityId,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

fn ml_kem_fixture(capability: CapabilityId, kem: MlKemHpke, seed: u8) -> ProfileFixture {
    let key_pair = kem.derive_key_pair(&[seed; 64]).unwrap();

    ProfileFixture {
        capability,
        public_key: key_pair.public_key,
        private_key: key_pair.private_key_seed.as_bytes().to_vec(),
    }
}

fn hybrid_fixture(capability: CapabilityId, kem: HybridKem, seed: u8) -> ProfileFixture {
    let key_pair = kem.derive_key_pair(&[seed; 64]).unwrap();

    ProfileFixture {
        capability,
        public_key: key_pair.public_key,
        private_key: key_pair.private_seed.as_bytes().to_vec(),
    }
}

fn fixtures() -> [ProfileFixture; 3] {
    [
        ml_kem_fixture(HPKE_ML_KEM_768, MlKemHpke::MlKem768, 0x11),
        ml_kem_fixture(HPKE_ML_KEM_1024, MlKemHpke::MlKem1024, 0x21),
        hybrid_fixture(
            HPKE_ML_KEM_768_X25519,
            HybridKem::MlKem768X25519,
            0x31,
        ),
    ]
}

fn other_capabilities(target: CapabilityId) -> [CapabilityId; 2] {
    let mut others = [CapabilityId::new(0); 2];
    let mut index = 0;

    for capability in [
        HPKE_ML_KEM_768,
        HPKE_ML_KEM_1024,
        HPKE_ML_KEM_768_X25519,
    ] {
        if capability != target {
            others[index] = capability;
            index += 1;
        }
    }

    assert_eq!(index, 2);
    others
}

fn negotiate(
    capability: CapabilityId,
    policy_id: PolicyId,
) -> pqc_protocol::NegotiatedCapability {
    let [a, b] = other_capabilities(capability);

    let local_ids = [capability, a, b];
    let peer_ids = [a, capability, b];
    let allowed = [a, b, capability];

    let local = CapabilityOffer::new(&local_ids).unwrap();
    let peer = CapabilityOffer::new(&peer_ids).unwrap();
    let policy = CapabilityPolicy::new(policy_id, &allowed).unwrap();

    let negotiated = negotiate_policy_permitted_common(local, peer, policy).unwrap();

    assert_eq!(negotiated.capability(), capability);
    assert_eq!(negotiated.policy_id(), policy_id);

    negotiated
}

fn establish_endpoint(
    capability: CapabilityId,
    policy_id: PolicyId,
    session_byte: u8,
    role: ProtocolRole,
) -> EstablishedProtocolContext {
    let negotiated = negotiate(capability, policy_id);

    TypedProtocolSession::new(
        SessionId::from_bytes([session_byte; 16]),
        PROTOCOL_ID,
        PROTOCOL_VERSION,
        role,
    )
    .begin_establishment()
    .establish_with_negotiation(negotiated)
}

fn exercise_reference_workflow(fixture: &ProfileFixture) {
    let client = establish_endpoint(
        fixture.capability,
        CLIENT_POLICY_ID,
        CLIENT_SESSION_BYTE,
        ProtocolRole::Client,
    );

    let server = establish_endpoint(
        fixture.capability,
        SERVER_POLICY_ID,
        SERVER_SESSION_BYTE,
        ProtocolRole::Server,
    );

    assert_eq!(client.capability(), fixture.capability);
    assert_eq!(server.capability(), fixture.capability);

    assert_eq!(client.session().protocol_id(), PROTOCOL_ID);
    assert_eq!(server.session().protocol_id(), PROTOCOL_ID);
    assert_eq!(client.session().protocol_version(), PROTOCOL_VERSION);
    assert_eq!(server.session().protocol_version(), PROTOCOL_VERSION);

    assert_ne!(client.session().session_id(), server.session().session_id());
    assert_ne!(client.session().role(), server.session().role());
    assert_ne!(client.policy_id(), server.policy_id());

    let mut rng = DeterministicRng::new(0x51);

    let sender_activation = activate_sender(
        &client,
        &fixture.public_key,
        APPLICATION_CONTEXT,
        &mut rng,
    )
    .unwrap();

    let (encapsulated_key, mut sender) = sender_activation.into_parts();

    let mut receiver = activate_receiver(
        &server,
        &fixture.private_key,
        &encapsulated_key,
        APPLICATION_CONTEXT,
    )
    .unwrap();

    assert_eq!(sender.negotiated().capability(), fixture.capability);
    assert_eq!(receiver.negotiated().capability(), fixture.capability);

    assert_eq!(sender.sequence_number(), 0);
    assert_eq!(receiver.sequence_number(), 0);

    let ciphertext = sender.seal(AAD, &PAYLOAD).unwrap();

    assert_eq!(sender.sequence_number(), 1);

    let plaintext = receiver.open(AAD, &ciphertext).unwrap();

    assert_eq!(receiver.sequence_number(), 1);
    assert_eq!(plaintext.as_slice(), PAYLOAD);
}

#[test]
fn reference_workflow_succeeds_for_all_registered_secure_channel_profiles() {
    for fixture in fixtures() {
        exercise_reference_workflow(&fixture);
    }
}
