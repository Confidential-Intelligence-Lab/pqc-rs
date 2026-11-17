//! Opt-in, state-versioned execution gating for cryptographic transitions.
//!
//! Unlike the advisory transition evaluators, this module prevents the supplied
//! operation from running unless the current decision is affirmative. Revisions
//! are advanced by the gate itself, so reusing a pre-change snapshot is rejected.
//!
//! This is a local enforcement boundary, not an assurance verifier. The caller
//! is responsible for supplying trustworthy policy, evidence, deployment, and
//! configuration assessments and for routing all protected operations through
//! the same gate. The gate does not observe changes outside its own update API.

use crate::{
    revalidate_transition, AssessedExecutionContext, AuthorizationDecision, ContextRevision,
    CryptographicTransition, CurrentExecutionContext, ExecutionRevisions, RevalidationResult,
    TransitionAssessments,
};

/// Security-relevant part of the execution context that has changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionContextChange {
    /// Resolved policy or its trusted inputs changed.
    Policy,
    /// Assurance evidence, its status, or its applicability changed.
    Evidence,
    /// Operational deployment state or prerequisites changed.
    Deployment,
    /// Source configuration, including provider or implementation revision, changed.
    SourceState,
}

/// A context revision cannot be advanced without wrapping its identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionGateUpdateError {
    /// The selected context revision has reached its maximum value.
    RevisionExhausted,
}

/// A rejected attempt to execute a cryptographic operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionGateError {
    /// The assessed operation or configuration transition was changed.
    TransitionChanged,
    /// At least one context component changed since the snapshot was taken.
    StaleContext,
    /// Current assessments did not provide an affirmative decision.
    NotPermitted(AuthorizationDecision),
}

/// A local, versioned gate around an externally assessed cryptographic change.
///
/// Context revisions are owned by the gate and cannot be modified directly.
/// Updates require exclusive mutable access, while execution borrows the gate
/// immutably. Consequently, a caller using the same gate cannot interleave an
/// update through the gate with a protected operation in safe Rust.
///
/// This guarantee does not extend to external systems whose state changes are
/// not observed through [`Self::advance`]. Neither the assessments nor the
/// underlying cryptographic operation are authenticated by this type.
/// Other, non-gated execution APIs remain outside this enforcement boundary.
pub struct TransitionExecutionGate {
    transition: CryptographicTransition,
    revisions: ExecutionRevisions,
    assessments: TransitionAssessments,
}

impl TransitionExecutionGate {
    /// Construct a gate for a single, exact cryptographic transition.
    ///
    /// Assessments may be unresolved or adverse; only execution-time
    /// revalidation can allow the protected operation to run.
    pub const fn new(
        transition: CryptographicTransition,
        assessments: TransitionAssessments,
    ) -> Self {
        let initial = ContextRevision::new(0);
        Self {
            transition,
            revisions: ExecutionRevisions {
                policy: initial,
                evidence: initial,
                deployment: initial,
                source_state: initial,
            },
            assessments,
        }
    }

    /// Capture a context snapshot for subsequent revalidation.
    ///
    /// A snapshot is not an authorization token. An execution attempt still
    /// evaluates the current assessments and rejects all non-affirmative outcomes.
    pub const fn snapshot(&self) -> AssessedExecutionContext {
        AssessedExecutionContext {
            transition: self.transition,
            revisions: self.revisions,
        }
    }

    /// Record a change and replace its assessed security conditions.
    ///
    /// The selected revision advances monotonically. An overflow is rejected
    /// without changing the revisions or assessments. The caller must submit
    /// the *current* assessments after observing the change; unverifiable or
    /// missing evidence must not be represented as applicable.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionGateUpdateError::RevisionExhausted`] if the selected
    /// revision cannot advance without wrapping.
    pub fn advance(
        &mut self,
        change: ExecutionContextChange,
        assessments: TransitionAssessments,
    ) -> Result<(), ExecutionGateUpdateError> {
        let target = match change {
            ExecutionContextChange::Policy => &mut self.revisions.policy,
            ExecutionContextChange::Evidence => &mut self.revisions.evidence,
            ExecutionContextChange::Deployment => &mut self.revisions.deployment,
            ExecutionContextChange::SourceState => &mut self.revisions.source_state,
        };
        let next = target
            .value()
            .checked_add(1)
            .ok_or(ExecutionGateUpdateError::RevisionExhausted)?;
        *target = ContextRevision::new(next);
        self.assessments = assessments;
        Ok(())
    }

    /// Execute the supplied operation only after affirmative revalidation.
    ///
    /// An old snapshot is rejected after any recorded change, even when
    /// replacement assessments would otherwise permit the transition. A fresh
    /// snapshot does not bypass policy, evidence, or readiness checks.
    ///
    /// This function gates the *supplied closure*. The caller is responsible
    /// for ensuring that closure performs the operation named by the recorded
    /// transition and does not invoke a separate, unguarded execution path.
    ///
    /// # Errors
    ///
    /// Returns an error for a changed transition, a stale context, or any
    /// authorization outcome other than `Allow`; the closure is not invoked.
    pub fn execute<T, F>(
        &self,
        assessed: AssessedExecutionContext,
        operation: F,
    ) -> Result<T, ExecutionGateError>
    where
        F: FnOnce() -> T,
    {
        let current = CurrentExecutionContext {
            transition: self.transition,
            revisions: self.revisions,
        };
        match revalidate_transition(assessed, current, self.assessments) {
            RevalidationResult::TransitionChanged => Err(ExecutionGateError::TransitionChanged),
            RevalidationResult::StaleContext => Err(ExecutionGateError::StaleContext),
            RevalidationResult::Evaluated(AuthorizationDecision::Allow) => Ok(operation()),
            RevalidationResult::Evaluated(decision) => {
                Err(ExecutionGateError::NotPermitted(decision))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AlgorithmId, ConfigurationIdentity, EvidenceApplicability, EvidenceScope,
        ImplementationRevision, OperationalReadiness, ParameterSetId, PolicyAssessment, ProviderId,
    };
    use core::cell::Cell;

    fn configuration(provider: u32) -> ConfigurationIdentity {
        ConfigurationIdentity::new(
            AlgorithmId::new(1),
            ParameterSetId::new(768),
            ProviderId::new(provider),
            ImplementationRevision::new(1),
        )
    }

    fn transition() -> CryptographicTransition {
        CryptographicTransition::new(
            configuration(1),
            configuration(2),
            EvidenceScope::Encapsulation,
        )
    }

    fn assessments() -> TransitionAssessments {
        TransitionAssessments {
            assessed_transition: transition(),
            transition_policy: PolicyAssessment::Permitted,
            source_policy: PolicyAssessment::Permitted,
            destination_policy: PolicyAssessment::Permitted,
            destination_evidence: EvidenceApplicability::Applicable,
            readiness: OperationalReadiness::Ready,
        }
    }

    fn not_executed(
        gate: &TransitionExecutionGate,
        snapshot: AssessedExecutionContext,
        expected: ExecutionGateError,
    ) {
        let invoked = Cell::new(false);
        let result = gate.execute(snapshot, || invoked.set(true));
        assert_eq!(result, Err(expected));
        assert!(!invoked.get());
    }

    #[test]
    fn affirmative_current_assessment_executes_exactly_once() {
        let gate = TransitionExecutionGate::new(transition(), assessments());
        let invoked = Cell::new(0);
        assert_eq!(
            gate.execute(gate.snapshot(), || {
                invoked.set(invoked.get() + 1);
                42
            }),
            Ok(42)
        );
        assert_eq!(invoked.get(), 1);
    }

    #[test]
    fn evidence_withdrawal_invalidates_snapshot_and_blocks_refresh() {
        let mut gate = TransitionExecutionGate::new(transition(), assessments());
        let old = gate.snapshot();
        let mut withdrawn = assessments();
        withdrawn.destination_evidence = EvidenceApplicability::Missing;
        gate.advance(ExecutionContextChange::Evidence, withdrawn)
            .unwrap();

        not_executed(&gate, old, ExecutionGateError::StaleContext);
        not_executed(
            &gate,
            gate.snapshot(),
            ExecutionGateError::NotPermitted(AuthorizationDecision::Defer),
        );
    }

    #[test]
    fn refreshed_applicable_evidence_can_restore_execution() {
        let mut gate = TransitionExecutionGate::new(transition(), assessments());
        let old = gate.snapshot();
        let mut withdrawn = assessments();
        withdrawn.destination_evidence = EvidenceApplicability::Missing;
        gate.advance(ExecutionContextChange::Evidence, withdrawn)
            .unwrap();
        gate.advance(ExecutionContextChange::Evidence, assessments())
            .unwrap();

        not_executed(&gate, old, ExecutionGateError::StaleContext);
        assert_eq!(gate.execute(gate.snapshot(), || 13), Ok(13));
    }

    #[test]
    fn policy_prohibition_prevents_execution_after_refresh() {
        let mut gate = TransitionExecutionGate::new(transition(), assessments());
        let old = gate.snapshot();
        let mut denied = assessments();
        denied.destination_policy = PolicyAssessment::Prohibited;
        gate.advance(ExecutionContextChange::Policy, denied)
            .unwrap();

        not_executed(&gate, old, ExecutionGateError::StaleContext);
        not_executed(
            &gate,
            gate.snapshot(),
            ExecutionGateError::NotPermitted(AuthorizationDecision::Deny),
        );
    }

    #[test]
    fn changes_to_deployment_and_source_invalidate_snapshots() {
        for change in [
            ExecutionContextChange::Deployment,
            ExecutionContextChange::SourceState,
        ] {
            let mut gate = TransitionExecutionGate::new(transition(), assessments());
            let old = gate.snapshot();
            gate.advance(change, assessments()).unwrap();
            not_executed(&gate, old, ExecutionGateError::StaleContext);
        }
    }

    #[test]
    fn mismatched_transition_never_executes() {
        let gate = TransitionExecutionGate::new(transition(), assessments());
        let mut wrong = gate.snapshot();
        wrong.transition = CryptographicTransition::new(
            configuration(1),
            configuration(3),
            EvidenceScope::Encapsulation,
        );
        not_executed(&gate, wrong, ExecutionGateError::TransitionChanged);
    }

    #[test]
    fn unknown_and_pending_assessments_fail_closed() {
        let mut unknown = assessments();
        unknown.destination_evidence = EvidenceApplicability::Indeterminate;
        let gate = TransitionExecutionGate::new(transition(), unknown);
        not_executed(
            &gate,
            gate.snapshot(),
            ExecutionGateError::NotPermitted(AuthorizationDecision::Unknown),
        );
        let mut pending = assessments();
        pending.readiness = OperationalReadiness::Pending;
        let gate = TransitionExecutionGate::new(transition(), pending);
        not_executed(
            &gate,
            gate.snapshot(),
            ExecutionGateError::NotPermitted(AuthorizationDecision::Defer),
        );
    }

    #[test]
    fn mismatched_assessment_context_fails_closed() {
        let mut mismatched = assessments();
        mismatched.assessed_transition = CryptographicTransition::new(
            configuration(1),
            configuration(3),
            EvidenceScope::Encapsulation,
        );
        let gate = TransitionExecutionGate::new(transition(), mismatched);
        not_executed(
            &gate,
            gate.snapshot(),
            ExecutionGateError::NotPermitted(AuthorizationDecision::Unknown),
        );
    }

    #[test]
    fn revision_overflow_rejects_update_without_modification() {
        let mut gate = TransitionExecutionGate::new(transition(), assessments());
        gate.revisions.evidence = ContextRevision::new(u64::MAX);
        let initial = gate.snapshot();
        let mut withdrawn = assessments();
        withdrawn.destination_evidence = EvidenceApplicability::Missing;

        assert_eq!(
            gate.advance(ExecutionContextChange::Evidence, withdrawn),
            Err(ExecutionGateUpdateError::RevisionExhausted)
        );
        assert_eq!(gate.snapshot(), initial);
        assert_eq!(gate.execute(initial, || 7), Ok(7));
    }
}
