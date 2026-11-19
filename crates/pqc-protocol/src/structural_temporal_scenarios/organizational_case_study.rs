//! Synthetic organizational migration plans; not observed deployments.
//! All durations, security assessments, and policy revisions are illustrative.
use super::*;
use crate::{revalidate_transition, RevalidationResult};

#[derive(Clone, Copy)]
struct Plan {
    environment: &'static str,
    strategy: &'static str,
    cutover: u64,
    deadline: u64,
    earliest_start: u64,
    duration: u64,
    threat_change: u64,
    expected: AuthorizationDecision,
}

// Model ticks are synthetic units, not calendar dates. Different deadlines
// represent distinct policy constraints; none is asserted as a NIST mandate.
const PLANS: [Plan; 9] = [
    Plan {
        environment: "internet_services",
        strategy: "deadline_first",
        cutover: 3,
        deadline: 8,
        earliest_start: 1,
        duration: 2,
        threat_change: 4,
        expected: AuthorizationDecision::Allow,
    },
    Plan {
        environment: "internet_services",
        strategy: "disruption_first",
        cutover: 7,
        deadline: 8,
        earliest_start: 1,
        duration: 2,
        threat_change: 4,
        expected: AuthorizationDecision::Deny,
    },
    Plan {
        environment: "internet_services",
        strategy: "continuity_aware",
        cutover: 4,
        deadline: 8,
        earliest_start: 1,
        duration: 2,
        threat_change: 4,
        expected: AuthorizationDecision::Allow,
    },
    Plan {
        environment: "signing_pki",
        strategy: "deadline_first",
        cutover: 3,
        deadline: 9,
        earliest_start: 1,
        duration: 2,
        threat_change: 5,
        expected: AuthorizationDecision::Allow,
    },
    Plan {
        environment: "signing_pki",
        strategy: "disruption_first",
        cutover: 8,
        deadline: 9,
        earliest_start: 1,
        duration: 2,
        threat_change: 5,
        expected: AuthorizationDecision::Deny,
    },
    Plan {
        environment: "signing_pki",
        strategy: "continuity_aware",
        cutover: 5,
        deadline: 9,
        earliest_start: 1,
        duration: 2,
        threat_change: 5,
        expected: AuthorizationDecision::Allow,
    },
    Plan {
        environment: "legacy_infrastructure",
        strategy: "deadline_first",
        cutover: 3,
        deadline: 8,
        earliest_start: 3,
        duration: 4,
        threat_change: 6,
        expected: AuthorizationDecision::Deny,
    },
    Plan {
        environment: "legacy_infrastructure",
        strategy: "disruption_first",
        cutover: 9,
        deadline: 8,
        earliest_start: 3,
        duration: 4,
        threat_change: 6,
        expected: AuthorizationDecision::Deny,
    },
    Plan {
        environment: "legacy_infrastructure",
        strategy: "continuity_aware",
        cutover: 6,
        deadline: 8,
        earliest_start: 3,
        duration: 4,
        threat_change: 6,
        expected: AuthorizationDecision::Deny,
    },
];

fn evaluate_plan(plan: Plan) -> ContinuousMigrationEvaluation {
    let horizon = ProtectionHorizon::new(t(0), t(12)).unwrap();
    let phases = [
        phase(0, plan.threat_change, 1),
        phase(plan.threat_change, 12, 2),
    ];
    let schedule = ThreatSchedule::new(&phases, horizon).unwrap();
    let transition = TransitionInterval::new(horizon, t(plan.cutover)).unwrap();
    let mut assessments = vec![assessment(1, 1, SecurityAcceptability::Acceptable)];
    if plan.cutover < plan.threat_change {
        assessments.push(assessment(2, 1, SecurityAcceptability::Acceptable));
    } else if plan.cutover > plan.threat_change {
        assessments.push(assessment(1, 2, SecurityAcceptability::Unacceptable));
    }
    assessments.push(assessment(2, 2, SecurityAcceptability::Acceptable));
    let continuity = evaluate_security_continuity(
        &schedule,
        transition,
        configuration(1),
        configuration(2),
        SecurityRequirementId::new(1),
        &assessments,
    );
    let timing = MigrationTimingEvidence::Known(
        MigrationTiming::new(
            t(0),
            t(plan.earliest_start),
            MigrationDuration::new(plan.duration),
        )
        .unwrap(),
    );
    let admissibility = independently_derived_admissibility(structural_evaluation(bound_step()));
    evaluate_continuous_migration(
        continuity,
        transition,
        timing,
        t(plan.deadline),
        admissibility,
    )
}

#[test]
fn synthetic_organizational_strategy_matrix() {
    for plan in PLANS {
        let ContinuousMigrationEvaluation::Evaluated {
            decision,
            diagnostics,
        } = evaluate_plan(plan)
        else {
            panic!("invalid plan {} / {}", plan.environment, plan.strategy);
        };
        assert_eq!(
            decision, plan.expected,
            "{} / {}",
            plan.environment, plan.strategy
        );
        println!(
            "ORG_CASE environment={} strategy={} cutover={} deadline={} decision={:?} continuity={:?} cutover_feasibility={:?} deadline_feasibility={:?} within_deadline={} status=PASS",
            plan.environment, plan.strategy, plan.cutover, plan.deadline, decision,
            diagnostics.continuity, diagnostics.cutover_feasibility,
            diagnostics.deadline_feasibility, diagnostics.cutover_within_deadline
        );
    }
    println!("ORG_CASE_MATRIX_STATUS=PASS");
}

#[test]
fn organizational_revalidation_requires_current_context() {
    let step = bound_step();
    let mut changed = step.current_context;
    changed.revisions.policy = ContextRevision::new(2);
    assert_eq!(
        revalidate_transition(step.assessed_context, changed, step.assessments),
        RevalidationResult::StaleContext
    );
    changed = step.current_context;
    changed.revisions.deployment = ContextRevision::new(2);
    assert_eq!(
        revalidate_transition(step.assessed_context, changed, step.assessments),
        RevalidationResult::StaleContext
    );
    assert_eq!(
        revalidate_transition(
            step.assessed_context,
            step.current_context,
            step.assessments
        ),
        RevalidationResult::Evaluated(AuthorizationDecision::Allow)
    );
    println!("ORG_CASE_REVALIDATION_STATUS=PASS");
}
