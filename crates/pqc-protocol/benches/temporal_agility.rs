//! Criterion measurements of advisory temporal-agility evaluation.
//!
//! Logical times and security assessments are synthetic inputs.
//! Fixture construction and validation occur outside timed iterations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pqc_protocol::{
    evaluate_continuous_migration, evaluate_security_continuity,
    evaluate_security_continuity_with_scratch, AlgorithmId, AuthorizationDecision,
    ConfigurationIdentity, ContinuousMigrationEvaluation, FourPredicateEvaluation,
    ImplementationRevision, MigrationDuration, MigrationTiming, MigrationTimingEvidence, ModelTime,
    ParameterSetId, ProtectionHorizon, ProviderId, SecurityAcceptability, SecurityAssessment,
    SecurityAssessmentBinding, SecurityContinuityEvaluation, SecurityRequirementId, ThreatPhase,
    ThreatPhaseId, ThreatSchedule, TimeInterval, TransitionInterval,
};

fn t(value: u64) -> ModelTime {
    ModelTime::new(value)
}

fn config(revision: u64) -> ConfigurationIdentity {
    ConfigurationIdentity::new(
        AlgorithmId::new(1),
        ParameterSetId::new(768),
        ProviderId::new(2),
        ImplementationRevision::new(revision),
    )
}

struct Fixture {
    phases: Vec<ThreatPhase>,
    assessments: Vec<SecurityAssessment>,
    protection: ProtectionHorizon,
    transition: TransitionInterval,
    source: ConfigurationIdentity,
    destination: ConfigurationIdentity,
    requirement: SecurityRequirementId,
}

impl Fixture {
    fn new(count: usize, cutover: u64) -> Self {
        assert!(count > 0);
        let horizon_end = count as u64 * 2;
        assert!(cutover <= horizon_end);

        let protection = ProtectionHorizon::new(t(0), t(horizon_end)).unwrap();
        let transition = TransitionInterval::new(protection, t(cutover)).unwrap();
        let source = config(1);
        let destination = config(2);
        let requirement = SecurityRequirementId::new(1);

        let mut phases = Vec::with_capacity(count);
        let mut assessments = Vec::with_capacity(count + 1);

        for index in 0..count {
            let start = index as u64 * 2;
            let end = start + 2;
            let threat = ThreatPhaseId::new(index as u64 + 1);

            phases.push(ThreatPhase::new(
                TimeInterval::new(t(start), t(end)).unwrap(),
                threat,
            ));

            if start < cutover {
                assessments.push(SecurityAssessment::new(
                    SecurityAssessmentBinding::new(source, threat, requirement),
                    SecurityAcceptability::Acceptable,
                ));
            }

            if end > cutover {
                assessments.push(SecurityAssessment::new(
                    SecurityAssessmentBinding::new(destination, threat, requirement),
                    SecurityAcceptability::Acceptable,
                ));
            }
        }

        let schedule = ThreatSchedule::new(&phases, protection).unwrap();
        let result = evaluate_security_continuity(
            &schedule,
            transition,
            source,
            destination,
            requirement,
            &assessments,
        );

        assert_eq!(result, Ok(SecurityContinuityEvaluation::Continuous));

        Self {
            phases,
            assessments,
            protection,
            transition,
            source,
            destination,
            requirement,
        }
    }

    fn continuity(&self) -> SecurityContinuityEvaluation {
        let schedule = ThreatSchedule::new(&self.phases, self.protection).unwrap();

        evaluate_security_continuity(
            &schedule,
            self.transition,
            self.source,
            self.destination,
            self.requirement,
            &self.assessments,
        )
        .unwrap()
    }
}

fn bench_continuity(c: &mut Criterion) {
    let mut group = c.benchmark_group("temporal_agility/continuity");

    for count in [1usize, 2, 4, 8, 16, 32, 64, 128] {
        let fixture = Fixture::new(count, count as u64);

        group.bench_with_input(BenchmarkId::new("phases", count), &fixture, |b, fixture| {
            let schedule = ThreatSchedule::new(&fixture.phases, fixture.protection).unwrap();

            b.iter(|| {
                black_box(evaluate_security_continuity(
                    black_box(&schedule),
                    black_box(fixture.transition),
                    black_box(fixture.source),
                    black_box(fixture.destination),
                    black_box(fixture.requirement),
                    black_box(&fixture.assessments),
                ))
            });
        });
    }

    group.finish();
}

fn bench_continuity_scratch(c: &mut Criterion) {
    let mut group = c.benchmark_group("temporal_agility/continuity_scratch");

    for count in [1usize, 2, 4, 8, 16, 32, 64, 128] {
        let fixture = Fixture::new(count, count as u64);
        let schedule = ThreatSchedule::new(&fixture.phases, fixture.protection).unwrap();

        let mut scratch = vec![usize::MAX; fixture.assessments.len()];

        let reference = evaluate_security_continuity(
            &schedule,
            fixture.transition,
            fixture.source,
            fixture.destination,
            fixture.requirement,
            &fixture.assessments,
        );

        let optimized = evaluate_security_continuity_with_scratch(
            &schedule,
            fixture.transition,
            fixture.source,
            fixture.destination,
            fixture.requirement,
            &fixture.assessments,
            &mut scratch,
        );

        assert_eq!(
            optimized,
            reference.map_err(pqc_protocol::SecurityContinuityScratchError::Evaluation)
        );

        group.bench_with_input(BenchmarkId::new("phases", count), &fixture, |b, fixture| {
            b.iter(|| {
                black_box(evaluate_security_continuity_with_scratch(
                    black_box(&schedule),
                    black_box(fixture.transition),
                    black_box(fixture.source),
                    black_box(fixture.destination),
                    black_box(fixture.requirement),
                    black_box(&fixture.assessments),
                    black_box(&mut scratch),
                ))
            });
        });
    }

    group.finish();
}

fn bench_integrated(c: &mut Criterion) {
    let mut group = c.benchmark_group("temporal_agility/integrated");

    let count = 64usize;
    let horizon = count as u64 * 2;

    for (label, cutover) in [
        ("early", 2u64),
        ("middle", horizon / 2),
        ("late", horizon - 2),
    ] {
        let fixture = Fixture::new(count, cutover);
        let continuity = fixture.continuity();

        let timing = MigrationTimingEvidence::Known(
            MigrationTiming::new(t(0), t(1), MigrationDuration::new(1)).unwrap(),
        );

        let deadline = t(horizon - 1);
        let admissibility = FourPredicateEvaluation::Evaluated(AuthorizationDecision::Allow);

        let expected = evaluate_continuous_migration(
            Ok(continuity),
            fixture.transition,
            timing,
            deadline,
            admissibility,
        );

        assert!(matches!(
            expected,
            ContinuousMigrationEvaluation::Evaluated {
                decision: AuthorizationDecision::Allow,
                ..
            }
        ));

        group.bench_function(label, |b| {
            b.iter(|| {
                black_box(evaluate_continuous_migration(
                    black_box(Ok(continuity)),
                    black_box(fixture.transition),
                    black_box(timing),
                    black_box(deadline),
                    black_box(admissibility),
                ))
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_continuity,
    bench_continuity_scratch,
    bench_integrated
);
criterion_main!(benches);
