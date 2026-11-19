//! Advisory revalidation of cryptographic transition assessments.
//!
//! Revision identifiers are supplied by the caller. Equality detects
//! differences but does not establish authenticity, freshness, or trust.

use crate::{
    authorize_transition, AuthorizationDecision, CryptographicTransition, TransitionAssessments,
};

/// Caller-assigned revision of a security-relevant context component.
///
/// Revisions must be advanced by an external trusted authority whenever
/// the corresponding state changes. This type does not enforce that rule.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContextRevision(u64);

impl ContextRevision {
    /// Construct a caller-assigned revision identifier.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the numeric revision identifier.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Revisions of the state relevant to a transition decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionRevisions {
    /// Revision of the resolved security policy.
    pub policy: ContextRevision,
    /// Revision of the assurance evidence state.
    pub evidence: ContextRevision,
    /// Revision of operational deployment conditions.
    pub deployment: ContextRevision,
    /// Revision of the source configuration state.
    pub source_state: ContextRevision,
}

/// Transition and revisions recorded at initial assessment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssessedExecutionContext {
    /// Transition for which the original assessment was made.
    pub transition: CryptographicTransition,
    /// Revisions observed at the original assessment.
    pub revisions: ExecutionRevisions,
}

/// Transition and revisions observed before intended execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentExecutionContext {
    /// Transition about to be executed.
    pub transition: CryptographicTransition,
    /// Revisions observed for the current state.
    pub revisions: ExecutionRevisions,
}

/// Result of advisory execution-time revalidation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevalidationResult {
    /// The transition differs from the originally assessed request.
    TransitionChanged,
    /// At least one context revision differs.
    StaleContext,
    /// Context matches and current assessments were evaluated.
    ///
    /// Even `Allow` is advisory, not an execution permit.
    Evaluated(AuthorizationDecision),
}

/// Compare execution contexts and evaluate current assessments.
///
/// A changed transition or context revision prevents reuse of the
/// previous assessment. Matching revisions permit evaluation of the
/// supplied current assessments but do not prove their trustworthiness.
///
/// This function performs no cryptographic operation, state mutation,
/// trusted observation, or enforcement.
pub fn revalidate_transition(
    assessed: AssessedExecutionContext,
    current: CurrentExecutionContext,
    current_assessments: TransitionAssessments,
) -> RevalidationResult {
    if assessed.transition != current.transition {
        return RevalidationResult::TransitionChanged;
    }

    if assessed.revisions != current.revisions {
        return RevalidationResult::StaleContext;
    }

    RevalidationResult::Evaluated(authorize_transition(
        current.transition,
        current_assessments,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AlgorithmId, ConfigurationIdentity, EvidenceApplicability, EvidenceScope,
        ImplementationRevision, OperationalReadiness, ParameterSetId, PolicyAssessment, ProviderId,
    };

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

    fn revisions() -> ExecutionRevisions {
        ExecutionRevisions {
            policy: ContextRevision::new(1),
            evidence: ContextRevision::new(1),
            deployment: ContextRevision::new(1),
            source_state: ContextRevision::new(1),
        }
    }

    fn assessed() -> AssessedExecutionContext {
        AssessedExecutionContext {
            transition: transition(),
            revisions: revisions(),
        }
    }

    fn current() -> CurrentExecutionContext {
        CurrentExecutionContext {
            transition: transition(),
            revisions: revisions(),
        }
    }

    fn permitted() -> TransitionAssessments {
        TransitionAssessments {
            assessed_transition: transition(),
            transition_policy: PolicyAssessment::Permitted,
            source_policy: PolicyAssessment::Permitted,
            destination_policy: PolicyAssessment::Permitted,
            destination_evidence: EvidenceApplicability::Applicable,
            readiness: OperationalReadiness::Ready,
        }
    }

    #[test]
    fn matching_context_with_current_permission_allows() {
        assert_eq!(
            revalidate_transition(assessed(), current(), permitted()),
            RevalidationResult::Evaluated(AuthorizationDecision::Allow)
        );
    }

    #[test]
    fn policy_revision_change_is_stale() {
        let mut now = current();
        now.revisions.policy = ContextRevision::new(2);
        assert_eq!(
            revalidate_transition(assessed(), now, permitted()),
            RevalidationResult::StaleContext
        );
    }

    #[test]
    fn evidence_revision_change_is_stale() {
        let mut now = current();
        now.revisions.evidence = ContextRevision::new(2);
        assert_eq!(
            revalidate_transition(assessed(), now, permitted()),
            RevalidationResult::StaleContext
        );
    }

    #[test]
    fn deployment_revision_change_is_stale() {
        let mut now = current();
        now.revisions.deployment = ContextRevision::new(2);
        assert_eq!(
            revalidate_transition(assessed(), now, permitted()),
            RevalidationResult::StaleContext
        );
    }

    #[test]
    fn source_state_revision_change_is_stale() {
        let mut now = current();
        now.revisions.source_state = ContextRevision::new(2);
        assert_eq!(
            revalidate_transition(assessed(), now, permitted()),
            RevalidationResult::StaleContext
        );
    }

    #[test]
    fn changed_transition_is_rejected_before_assessment() {
        let mut now = current();
        now.transition = CryptographicTransition::new(
            configuration(1),
            configuration(3),
            EvidenceScope::Encapsulation,
        );
        assert_eq!(
            revalidate_transition(assessed(), now, permitted()),
            RevalidationResult::TransitionChanged
        );
    }

    #[test]
    fn current_provider_unavailability_prevents_allow() {
        let mut assessments = permitted();
        assessments.readiness = OperationalReadiness::Pending;
        assert_eq!(
            revalidate_transition(assessed(), current(), assessments),
            RevalidationResult::Evaluated(AuthorizationDecision::Defer)
        );
    }

    #[test]
    fn current_policy_prohibition_prevents_allow() {
        let mut assessments = permitted();
        assessments.transition_policy = PolicyAssessment::Prohibited;
        assert_eq!(
            revalidate_transition(assessed(), current(), assessments),
            RevalidationResult::Evaluated(AuthorizationDecision::Deny)
        );
    }

    #[test]
    fn mismatched_current_assessments_never_allow() {
        let mut assessments = permitted();
        assessments.assessed_transition = CryptographicTransition::new(
            configuration(1),
            configuration(3),
            EvidenceScope::Encapsulation,
        );
        assert_eq!(
            revalidate_transition(assessed(), current(), assessments),
            RevalidationResult::Evaluated(AuthorizationDecision::Unknown)
        );
    }

    #[test]
    fn context_revision_round_trips() {
        assert_eq!(ContextRevision::new(42).value(), 42);
    }
}
