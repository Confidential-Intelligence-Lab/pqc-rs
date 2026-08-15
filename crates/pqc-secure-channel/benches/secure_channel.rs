use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use pqc_hpke::{hybrid_kem::HybridKem, MlKemHpke};
use pqc_protocol::{
    negotiate_policy_permitted_common, CapabilityId, CapabilityOffer, CapabilityPolicy,
    EstablishedProtocolContext, NegotiatedCapability, PolicyId, ProtocolId, ProtocolRole,
    ProtocolVersion, SessionId, TypedProtocolSession, HPKE_ML_KEM_1024, HPKE_ML_KEM_768,
    HPKE_ML_KEM_768_X25519,
};
use pqc_secure_channel::{
    activate_receiver, activate_sender, resolve_hpke_profile, SecureChannelBinding,
    SecureChannelReceiver, SecureChannelSender,
};
use rand_core::OsRng;

const PROTOCOL_ID: ProtocolId = ProtocolId::new(0x1300);
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

const CLIENT_POLICY_ID: PolicyId = PolicyId::new(0x1010);
const SERVER_POLICY_ID: PolicyId = PolicyId::new(0x2020);

const CLIENT_SESSION_BYTE: u8 = 0x41;
const SERVER_SESSION_BYTE: u8 = 0x42;

const APPLICATION_CONTEXT: &[u8] = b"pqc-forge-reference-workflow";
const AAD: &[u8] = b"pqc-forge-reference-aad";
const PAYLOAD: [u8; 1024] = [0xa5; 1024];

struct ProfileFixture {
    label: &'static str,
    capability: CapabilityId,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

fn ml_kem_fixture(
    label: &'static str,
    capability: CapabilityId,
    kem: MlKemHpke,
    seed: u8,
) -> ProfileFixture {
    let key_pair = kem.derive_key_pair(&[seed; 64]).unwrap();

    ProfileFixture {
        label,
        capability,
        public_key: key_pair.public_key,
        private_key: key_pair.private_key_seed.as_bytes().to_vec(),
    }
}

fn hybrid_fixture(
    label: &'static str,
    capability: CapabilityId,
    kem: HybridKem,
    seed: u8,
) -> ProfileFixture {
    let key_pair = kem.derive_key_pair(&[seed; 64]).unwrap();

    ProfileFixture {
        label,
        capability,
        public_key: key_pair.public_key,
        private_key: key_pair.private_seed.as_bytes().to_vec(),
    }
}

fn fixtures() -> [ProfileFixture; 3] {
    [
        ml_kem_fixture("MLKEM768", HPKE_ML_KEM_768, MlKemHpke::MlKem768, 0x11),
        ml_kem_fixture("MLKEM1024", HPKE_ML_KEM_1024, MlKemHpke::MlKem1024, 0x21),
        hybrid_fixture(
            "MLKEM768-X25519",
            HPKE_ML_KEM_768_X25519,
            HybridKem::MlKem768X25519,
            0x31,
        ),
    ]
}

fn other_capabilities(target: CapabilityId) -> [CapabilityId; 2] {
    let mut others = [CapabilityId::new(0); 2];
    let mut index = 0;

    for capability in [HPKE_ML_KEM_768, HPKE_ML_KEM_1024, HPKE_ML_KEM_768_X25519] {
        if capability != target {
            others[index] = capability;
            index += 1;
        }
    }

    assert_eq!(index, 2);
    others
}

fn negotiation_arrays(
    target: CapabilityId,
) -> ([CapabilityId; 3], [CapabilityId; 3], [CapabilityId; 3]) {
    let [a, b] = other_capabilities(target);

    ([target, a, b], [a, target, b], [a, b, target])
}

fn negotiate(target: CapabilityId, policy_id: PolicyId) -> NegotiatedCapability {
    let (local_ids, peer_ids, allowed) = negotiation_arrays(target);

    let local = CapabilityOffer::new(&local_ids).unwrap();
    let peer = CapabilityOffer::new(&peer_ids).unwrap();
    let policy = CapabilityPolicy::new(policy_id, &allowed).unwrap();

    let negotiated = negotiate_policy_permitted_common(local, peer, policy).unwrap();

    assert_eq!(negotiated.capability(), target);
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

fn established_pair(
    capability: CapabilityId,
) -> (EstablishedProtocolContext, EstablishedProtocolContext) {
    (
        establish_endpoint(
            capability,
            CLIENT_POLICY_ID,
            CLIENT_SESSION_BYTE,
            ProtocolRole::Client,
        ),
        establish_endpoint(
            capability,
            SERVER_POLICY_ID,
            SERVER_SESSION_BYTE,
            ProtocolRole::Server,
        ),
    )
}

fn activated_pair(fixture: &ProfileFixture) -> (SecureChannelSender, SecureChannelReceiver) {
    let (client, server) = established_pair(fixture.capability);
    let mut rng = OsRng;

    let activation =
        activate_sender(&client, &fixture.public_key, APPLICATION_CONTEXT, &mut rng).unwrap();

    let (encapsulated_key, sender) = activation.into_parts();

    let receiver = activate_receiver(
        &server,
        &fixture.private_key,
        &encapsulated_key,
        APPLICATION_CONTEXT,
    )
    .unwrap();

    (sender, receiver)
}

fn establish_channel(fixture: &ProfileFixture) -> (SecureChannelSender, SecureChannelReceiver) {
    let (client_local_ids, client_peer_ids, client_allowed) =
        negotiation_arrays(fixture.capability);
    let client_local = CapabilityOffer::new(&client_local_ids).unwrap();
    let client_peer = CapabilityOffer::new(&client_peer_ids).unwrap();
    let client_policy = CapabilityPolicy::new(CLIENT_POLICY_ID, &client_allowed).unwrap();

    let (server_local_ids, server_peer_ids, server_allowed) =
        negotiation_arrays(fixture.capability);
    let server_local = CapabilityOffer::new(&server_local_ids).unwrap();
    let server_peer = CapabilityOffer::new(&server_peer_ids).unwrap();
    let server_policy = CapabilityPolicy::new(SERVER_POLICY_ID, &server_allowed).unwrap();

    let client_negotiated =
        negotiate_policy_permitted_common(client_local, client_peer, client_policy).unwrap();

    let server_negotiated =
        negotiate_policy_permitted_common(server_local, server_peer, server_policy).unwrap();

    let client = TypedProtocolSession::new(
        SessionId::from_bytes([CLIENT_SESSION_BYTE; 16]),
        PROTOCOL_ID,
        PROTOCOL_VERSION,
        ProtocolRole::Client,
    )
    .begin_establishment()
    .establish_with_negotiation(client_negotiated);

    let server = TypedProtocolSession::new(
        SessionId::from_bytes([SERVER_SESSION_BYTE; 16]),
        PROTOCOL_ID,
        PROTOCOL_VERSION,
        ProtocolRole::Server,
    )
    .begin_establishment()
    .establish_with_negotiation(server_negotiated);

    let mut rng = OsRng;
    let activation =
        activate_sender(&client, &fixture.public_key, APPLICATION_CONTEXT, &mut rng).unwrap();

    let (encapsulated_key, sender) = activation.into_parts();

    let receiver = activate_receiver(
        &server,
        &fixture.private_key,
        &encapsulated_key,
        APPLICATION_CONTEXT,
    )
    .unwrap();

    (sender, receiver)
}

fn bench_secure_channel(c: &mut Criterion) {
    let fixtures = fixtures();
    let mut group = c.benchmark_group("secure_channel");

    for fixture in &fixtures {
        let (local_ids, peer_ids, allowed) = negotiation_arrays(fixture.capability);
        let local = CapabilityOffer::new(&local_ids).unwrap();
        let peer = CapabilityOffer::new(&peer_ids).unwrap();
        let policy = CapabilityPolicy::new(CLIENT_POLICY_ID, &allowed).unwrap();

        group.bench_function(BenchmarkId::new("negotiation", fixture.label), |b| {
            b.iter(|| {
                black_box(
                    negotiate_policy_permitted_common(
                        black_box(local),
                        black_box(peer),
                        black_box(policy),
                    )
                    .unwrap(),
                )
            })
        });

        let negotiated = negotiate(fixture.capability, CLIENT_POLICY_ID);

        group.bench_function(BenchmarkId::new("profile_resolution", fixture.label), |b| {
            b.iter(|| black_box(resolve_hpke_profile(black_box(negotiated)).unwrap()))
        });

        let client = establish_endpoint(
            fixture.capability,
            CLIENT_POLICY_ID,
            CLIENT_SESSION_BYTE,
            ProtocolRole::Client,
        );

        group.bench_function(BenchmarkId::new("binding", fixture.label), |b| {
            b.iter(|| {
                black_box(SecureChannelBinding::new(
                    black_box(&client),
                    black_box(APPLICATION_CONTEXT),
                ))
            })
        });

        group.bench_function(BenchmarkId::new("activate_sender", fixture.label), |b| {
            b.iter_batched(
                || OsRng,
                |mut rng| {
                    black_box(
                        activate_sender(
                            black_box(&client),
                            black_box(&fixture.public_key),
                            black_box(APPLICATION_CONTEXT),
                            &mut rng,
                        )
                        .unwrap(),
                    )
                },
                BatchSize::SmallInput,
            )
        });

        let server = establish_endpoint(
            fixture.capability,
            SERVER_POLICY_ID,
            SERVER_SESSION_BYTE,
            ProtocolRole::Server,
        );

        group.bench_function(BenchmarkId::new("activate_receiver", fixture.label), |b| {
            b.iter_batched(
                || {
                    let mut rng = OsRng;
                    let activation = activate_sender(
                        &client,
                        &fixture.public_key,
                        APPLICATION_CONTEXT,
                        &mut rng,
                    )
                    .unwrap();

                    activation.encapsulated_key().to_vec()
                },
                |encapsulated_key| {
                    black_box(
                        activate_receiver(
                            black_box(&server),
                            black_box(&fixture.private_key),
                            black_box(&encapsulated_key),
                            black_box(APPLICATION_CONTEXT),
                        )
                        .unwrap(),
                    )
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_function(BenchmarkId::new("seal_1k", fixture.label), |b| {
            b.iter_batched(
                || activated_pair(fixture).0,
                |mut sender| black_box(sender.seal(black_box(AAD), black_box(&PAYLOAD)).unwrap()),
                BatchSize::SmallInput,
            )
        });

        group.bench_function(BenchmarkId::new("open_1k", fixture.label), |b| {
            b.iter_batched(
                || {
                    let (mut sender, receiver) = activated_pair(fixture);
                    let ciphertext = sender.seal(AAD, &PAYLOAD).unwrap();
                    (receiver, ciphertext)
                },
                |(mut receiver, ciphertext)| {
                    black_box(
                        receiver
                            .open(black_box(AAD), black_box(&ciphertext))
                            .unwrap(),
                    )
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_function(BenchmarkId::new("establish_channel", fixture.label), |b| {
            b.iter(|| black_box(establish_channel(black_box(fixture))))
        });
    }

    group.finish();
}

criterion_group!(benches, bench_secure_channel);
criterion_main!(benches);
