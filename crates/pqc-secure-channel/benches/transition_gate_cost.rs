//! Criterion measurements of opt-in admissibility-enforcement overhead.
//!
//! The benchmark reuses one ML-KEM-768 key pair and the same deterministic
//! test-only RNG stream for matched baseline and guarded activations. It does
//! not include assurance verification, distribution, revocation propagation,
//! network latency, or the performance of switching a physical provider.

use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use pqc_hpke::MlKemHpke;
use pqc_protocol::{
    negotiate_policy_permitted_common, AlgorithmId, CapabilityOffer, CapabilityPolicy,
    ConfigurationIdentity, CryptographicTransition, EvidenceApplicability, EvidenceScope,
    ImplementationRevision, OperationalReadiness, ParameterSetId, PolicyAssessment, PolicyId,
    ProtocolId, ProtocolRole, ProtocolVersion, ProviderId, SessionId, TransitionAssessments,
    TransitionExecutionGate, TypedProtocolSession, HPKE_ML_KEM_768,
};
use pqc_secure_channel::{activate_sender, activate_sender_guarded};
use rand_core::{CryptoRng, Error as RandError, RngCore};

struct BenchRng(u8);

impl RngCore for BenchRng {
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

fn measure(c: &mut Criterion) {
    let key_pair = MlKemHpke::MlKem768.derive_key_pair(&[0x11; 64]).unwrap();
    let capabilities = [HPKE_ML_KEM_768];
    let offered = CapabilityOffer::new(&capabilities).unwrap();
    let policy = CapabilityPolicy::new(PolicyId::new(0x1010), &capabilities).unwrap();
    let negotiated = negotiate_policy_permitted_common(offered, offered, policy).unwrap();
    let client = TypedProtocolSession::new(
        SessionId::from_bytes([0x31; 16]),
        ProtocolId::new(0x1300),
        ProtocolVersion::new(1, 0),
        ProtocolRole::Client,
    )
    .begin_establishment()
    .establish_with_negotiation(negotiated);

    let source = ConfigurationIdentity::new(
        AlgorithmId::new(u32::from(HPKE_ML_KEM_768.value())),
        ParameterSetId::new(768),
        ProviderId::new(1),
        ImplementationRevision::new(1),
    );
    let destination = ConfigurationIdentity::new(
        AlgorithmId::new(u32::from(HPKE_ML_KEM_768.value())),
        ParameterSetId::new(768),
        ProviderId::new(2),
        ImplementationRevision::new(1),
    );
    let transition =
        CryptographicTransition::new(source, destination, EvidenceScope::Encapsulation);
    let assessed = TransitionAssessments {
        assessed_transition: transition,
        transition_policy: PolicyAssessment::Permitted,
        source_policy: PolicyAssessment::Permitted,
        destination_policy: PolicyAssessment::Permitted,
        destination_evidence: EvidenceApplicability::Applicable,
        readiness: OperationalReadiness::Ready,
    };
    let gate = TransitionExecutionGate::new(transition, assessed);
    let snapshot = gate.snapshot();

    let mut group = c.benchmark_group("mlkem768_sender_activation");
    group.bench_function("baseline", |b| {
        b.iter_batched(
            || BenchRng(0x51),
            |mut rng| {
                let result = activate_sender(
                    &client,
                    &key_pair.public_key,
                    b"transition-comparison-v1",
                    &mut rng,
                )
                .unwrap();
                black_box(result.encapsulated_key().len());
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("guarded_allow", |b| {
        b.iter_batched(
            || BenchRng(0x51),
            |mut rng| {
                let result = activate_sender_guarded(
                    &gate,
                    snapshot,
                    &client,
                    &key_pair.public_key,
                    b"transition-comparison-v1",
                    &mut rng,
                )
                .unwrap();
                black_box(result.encapsulated_key().len());
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();

    c.bench_function("admissibility_gate_decision_only", |b| {
        b.iter(|| {
            let result = gate.execute(black_box(snapshot), || black_box(7_u8));
            black_box(result.unwrap());
        });
    });
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .sample_size(40)
        .warm_up_time(Duration::from_millis(600))
        .measurement_time(Duration::from_secs(3))
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = measure
}
criterion_main!(benches);
