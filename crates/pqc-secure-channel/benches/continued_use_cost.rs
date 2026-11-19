//! Per-message cost of opt-in continued-use HPKE authorization.
//!
//! Sender measurements reuse one established context to measure steady-state
//! `seal` operations. Receiver measurements use batches of fresh, sequential
//! ciphertexts; batch preparation and key setup are outside the timed closure.
//! These are local measurements, not assurance verification or remote revocation.

use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use pqc_hpke::MlKemHpke;
use pqc_protocol::{
    negotiate_policy_permitted_common, AlgorithmId, CapabilityOffer, CapabilityPolicy,
    ConfigurationIdentity, CryptographicTransition, EstablishedProtocolContext,
    EvidenceApplicability, EvidenceScope, ImplementationRevision, OperationalReadiness,
    ParameterSetId, PolicyAssessment, PolicyId, ProtocolId, ProtocolRole, ProtocolVersion,
    ProviderId, SessionId, TransitionAssessments, TransitionExecutionGate, TypedProtocolSession,
    HPKE_ML_KEM_768,
};
use pqc_secure_channel::{
    activate_receiver, activate_receiver_continuous, activate_sender, activate_sender_continuous,
    ContinuedUseReceiver, ContinuedUseSender, SecureChannelReceiver, SecureChannelSender,
    SharedTransitionGate,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};

const AAD: &[u8] = b"per-message-benchmark-aad";
const CONTEXT: &[u8] = b"per-message-benchmark-v1";
const OPEN_BATCH: usize = 16;

struct BenchRng(u8);

impl RngCore for BenchRng {
    fn next_u32(&mut self) -> u32 {
        let mut result = [0_u8; 4];
        self.fill_bytes(&mut result);
        u32::from_le_bytes(result)
    }
    fn next_u64(&mut self) -> u64 {
        let mut result = [0_u8; 8];
        self.fill_bytes(&mut result);
        u64::from_le_bytes(result)
    }
    fn fill_bytes(&mut self, output: &mut [u8]) {
        for byte in output {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(output);
        Ok(())
    }
}
impl CryptoRng for BenchRng {}

fn endpoint(role: ProtocolRole) -> EstablishedProtocolContext {
    let capabilities = [HPKE_ML_KEM_768];
    let offer = CapabilityOffer::new(&capabilities).unwrap();
    let policy = CapabilityPolicy::new(PolicyId::new(0x1010), &capabilities).unwrap();
    let negotiated = negotiate_policy_permitted_common(offer, offer, policy).unwrap();
    TypedProtocolSession::new(
        SessionId::from_bytes([0x31; 16]),
        ProtocolId::new(0x1300),
        ProtocolVersion::new(1, 0),
        role,
    )
    .begin_establishment()
    .establish_with_negotiation(negotiated)
}

fn make_gate(scope: EvidenceScope) -> SharedTransitionGate {
    let config = |provider| {
        ConfigurationIdentity::new(
            AlgorithmId::new(u32::from(HPKE_ML_KEM_768.value())),
            ParameterSetId::new(768),
            ProviderId::new(provider),
            ImplementationRevision::new(1),
        )
    };
    let request = CryptographicTransition::new(config(1), config(2), scope);
    let assessment = TransitionAssessments {
        assessed_transition: request,
        transition_policy: PolicyAssessment::Permitted,
        source_policy: PolicyAssessment::Permitted,
        destination_policy: PolicyAssessment::Permitted,
        destination_evidence: EvidenceApplicability::Applicable,
        readiness: OperationalReadiness::Ready,
    };
    SharedTransitionGate::new(TransitionExecutionGate::new(request, assessment))
}

struct Fixture {
    client: EstablishedProtocolContext,
    server: EstablishedProtocolContext,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    sender_gate: SharedTransitionGate,
    receiver_gate: SharedTransitionGate,
}

impl Fixture {
    fn new() -> Self {
        let pair = MlKemHpke::MlKem768.derive_key_pair(&[0x11; 64]).unwrap();
        Self {
            client: endpoint(ProtocolRole::Client),
            server: endpoint(ProtocolRole::Server),
            public_key: pair.public_key,
            private_key: pair.private_key_seed.as_bytes().to_vec(),
            sender_gate: make_gate(EvidenceScope::Encapsulation),
            receiver_gate: make_gate(EvidenceScope::Decapsulation),
        }
    }

    fn baseline_sender(&self) -> (Vec<u8>, SecureChannelSender) {
        let mut rng = BenchRng(0x51);
        activate_sender(&self.client, &self.public_key, CONTEXT, &mut rng)
            .unwrap()
            .into_parts()
    }

    fn continuous_sender(&self) -> (Vec<u8>, ContinuedUseSender) {
        let mut rng = BenchRng(0x51);
        activate_sender_continuous(
            &self.sender_gate,
            self.sender_gate.snapshot().unwrap(),
            &self.client,
            &self.public_key,
            CONTEXT,
            &mut rng,
        )
        .unwrap()
        .into_parts()
    }

    fn baseline_open_batch(&self, payload: &[u8]) -> (SecureChannelReceiver, Vec<Vec<u8>>) {
        let (encapsulated, mut sender) = self.baseline_sender();
        let ciphertexts = (0..OPEN_BATCH)
            .map(|_| sender.seal(AAD, payload).unwrap())
            .collect();
        let receiver =
            activate_receiver(&self.server, &self.private_key, &encapsulated, CONTEXT).unwrap();
        (receiver, ciphertexts)
    }

    fn continued_open_batch(&self, payload: &[u8]) -> (ContinuedUseReceiver, Vec<Vec<u8>>) {
        let (encapsulated, mut sender) = self.continuous_sender();
        let ciphertexts = (0..OPEN_BATCH)
            .map(|_| sender.seal(AAD, payload).unwrap())
            .collect();
        let receiver = activate_receiver_continuous(
            &self.receiver_gate,
            self.receiver_gate.snapshot().unwrap(),
            &self.server,
            &self.private_key,
            &encapsulated,
            CONTEXT,
        )
        .unwrap();
        (receiver, ciphertexts)
    }
}

fn bench_messages(c: &mut Criterion) {
    let fixture = Fixture::new();
    let lengths = [64_usize, 1024, 16384];

    for size in lengths {
        let payload = vec![0xa5; size];
        let mut group = c.benchmark_group("continued_use_seal");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("baseline", size),
            &payload,
            |b, message| {
                let (_, mut sender) = fixture.baseline_sender();
                b.iter(|| {
                    black_box(sender.seal(AAD, black_box(message)).unwrap());
                });
            },
        );
        group.bench_with_input(BenchmarkId::new("guarded", size), &payload, |b, message| {
            let (_, mut sender) = fixture.continuous_sender();
            b.iter(|| {
                black_box(sender.seal(AAD, black_box(message)).unwrap());
            });
        });
        group.finish();
    }

    for size in lengths {
        let payload = vec![0x5a; size];
        let mut group = c.benchmark_group("continued_use_open_batch16");
        group.throughput(Throughput::Bytes((size * OPEN_BATCH) as u64));
        group.bench_with_input(
            BenchmarkId::new("baseline", size),
            &payload,
            |b, message| {
                b.iter_batched(
                    || fixture.baseline_open_batch(message),
                    |(mut receiver, ciphertexts)| {
                        for ciphertext in ciphertexts {
                            black_box(receiver.open(AAD, &ciphertext).unwrap());
                        }
                    },
                    BatchSize::SmallInput,
                );
            },
        );
        group.bench_with_input(BenchmarkId::new("guarded", size), &payload, |b, message| {
            b.iter_batched(
                || fixture.continued_open_batch(message),
                |(mut receiver, ciphertexts)| {
                    for ciphertext in ciphertexts {
                        black_box(receiver.open(AAD, &ciphertext).unwrap());
                    }
                },
                BatchSize::SmallInput,
            );
        });
        group.finish();
    }
}

fn benchmark_config() -> Criterion {
    Criterion::default()
        .sample_size(30)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
}

criterion_group! {
    name = benches;
    config = benchmark_config();
    targets = bench_messages
}
criterion_main!(benches);
