//! Advisory binding of assessments to complete system-state transitions.
//!
//! All identities and assessments are caller-supplied. Equality checks
//! do not establish authenticity, freshness, or execution authorization.

use crate::{
    authorize_transition, AuthorizationDecision, CryptographicSystemState, CryptographicTransition,
    TransitionAssessments,
};

/// Exact full-state transition and requested cryptographic operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemTransitionBinding {
    /// Source system-state identity.
    pub source: CryptographicSystemState,
    /// Destination system-state identity.
    pub destination: CryptographicSystemState,
    /// Configuration-level transition and operation.
    pub transition: CryptographicTransition,
}

/// Result of evaluating full-state assessment binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemBindingEvaluation {
    /// The transition's configurations do not match its full states.
    TransitionConfigurationMismatch,
    /// The assessed full-state binding differs from the requested binding.
    AssessmentBindingMismatch,
    /// Exact binding matches and R7 authorization was evaluated.
    Evaluated(AuthorizationDecision),
}

/// Evaluate assessments only for an exactly matching full-state binding.
///
/// The assessed binding identifies the context for which assessments
/// were resolved. The requested binding identifies the intended change.
/// Both are externally supplied and are not independently authenticated.
///
/// Configuration consistency is checked before binding equality.
/// A matching binding is not proof of freshness or an execution permit.
pub fn evaluate_system_transition_binding(
    assessed: SystemTransitionBinding,
    requested: SystemTransitionBinding,
    assessments: TransitionAssessments,
) -> SystemBindingEvaluation {
    if assessed.transition.source() != assessed.source.configuration()
        || assessed.transition.destination() != assessed.destination.configuration()
        || requested.transition.source() != requested.source.configuration()
        || requested.transition.destination() != requested.destination.configuration()
    {
        return SystemBindingEvaluation::TransitionConfigurationMismatch;
    }

    if assessed != requested {
        return SystemBindingEvaluation::AssessmentBindingMismatch;
    }

    SystemBindingEvaluation::Evaluated(authorize_transition(requested.transition, assessments))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AlgorithmId, ConfigurationIdentity, DeploymentStateIdentity, EvidenceApplicability,
        EvidenceScope, EvidenceStateIdentity, ImplementationRevision, OperationalReadiness,
        ParameterSetId, PolicyAssessment, PolicyStateIdentity, ProviderId,
    };

    fn configuration(provider: u32) -> ConfigurationIdentity {
        ConfigurationIdentity::new(
            AlgorithmId::new(1),
            ParameterSetId::new(768),
            ProviderId::new(provider),
            ImplementationRevision::new(1),
        )
    }

    fn state(
        provider: u32,
        policy: u64,
        evidence: u64,
        deployment: u64,
    ) -> CryptographicSystemState {
        CryptographicSystemState::new(
            configuration(provider),
            PolicyStateIdentity::new(policy),
            EvidenceStateIdentity::new(evidence),
            DeploymentStateIdentity::new(deployment),
        )
    }

    fn binding() -> SystemTransitionBinding {
        let source = state(1, 10, 20, 30);
        let destination = state(2, 11, 21, 31);
        SystemTransitionBinding {
            source,
            destination,
            transition: CryptographicTransition::new(
                source.configuration(),
                destination.configuration(),
                EvidenceScope::Encapsulation,
            ),
        }
    }

    fn permitted() -> TransitionAssessments {
        TransitionAssessments {
            assessed_transition: binding().transition,
            transition_policy: PolicyAssessment::Permitted,
            source_policy: PolicyAssessment::Permitted,
            destination_policy: PolicyAssessment::Permitted,
            destination_evidence: EvidenceApplicability::Applicable,
            readiness: OperationalReadiness::Ready,
        }
    }

    #[test]
    fn exact_binding_preserves_allow() {
        let b = binding();
        assert_eq!(
            evaluate_system_transition_binding(b, b, permitted()),
            SystemBindingEvaluation::Evaluated(AuthorizationDecision::Allow)
        );
    }

    #[test]
    fn policy_substitution_rejects_permitted_assessments() {
        let b = binding();
        let mut changed = b;
        changed.source = state(1, 99, 20, 30);
        assert_eq!(
            evaluate_system_transition_binding(b, changed, permitted()),
            SystemBindingEvaluation::AssessmentBindingMismatch
        );
    }

    #[test]
    fn evidence_substitution_rejects_permitted_assessments() {
        let b = binding();
        let mut changed = b;
        changed.destination = state(2, 11, 99, 31);
        assert_eq!(
            evaluate_system_transition_binding(b, changed, permitted()),
            SystemBindingEvaluation::AssessmentBindingMismatch
        );
    }

    #[test]
    fn deployment_substitution_rejects_permitted_assessments() {
        let b = binding();
        let mut changed = b;
        changed.source = state(1, 10, 20, 99);
        assert_eq!(
            evaluate_system_transition_binding(b, changed, permitted()),
            SystemBindingEvaluation::AssessmentBindingMismatch
        );
    }

    #[test]
    fn configuration_substitution_is_detected() {
        let b = binding();
        let mut changed = b;
        changed.destination = state(3, 11, 21, 31);
        assert_eq!(
            evaluate_system_transition_binding(b, changed, permitted()),
            SystemBindingEvaluation::TransitionConfigurationMismatch
        );
    }

    #[test]
    fn operation_substitution_is_detected() {
        let b = binding();
        let mut changed = b;
        changed.transition = CryptographicTransition::new(
            b.source.configuration(),
            b.destination.configuration(),
            EvidenceScope::Decapsulation,
        );
        assert_eq!(
            evaluate_system_transition_binding(b, changed, permitted()),
            SystemBindingEvaluation::AssessmentBindingMismatch
        );
    }

    #[test]
    fn inconsistent_assessed_configuration_is_detected() {
        let mut b = binding();
        b.transition = CryptographicTransition::new(
            configuration(9),
            b.destination.configuration(),
            EvidenceScope::Encapsulation,
        );
        assert_eq!(
            evaluate_system_transition_binding(b, b, permitted()),
            SystemBindingEvaluation::TransitionConfigurationMismatch
        );
    }

    #[test]
    fn matching_binding_preserves_r7_denial() {
        let b = binding();
        let mut assessments = permitted();
        assessments.transition_policy = PolicyAssessment::Prohibited;
        assert_eq!(
            evaluate_system_transition_binding(b, b, assessments),
            SystemBindingEvaluation::Evaluated(AuthorizationDecision::Deny)
        );
    }

    #[test]
    fn mismatched_assessment_transition_cannot_allow() {
        let b = binding();
        let mut assessments = permitted();
        assessments.assessed_transition = CryptographicTransition::new(
            b.source.configuration(),
            b.destination.configuration(),
            EvidenceScope::Decapsulation,
        );
        assert_eq!(
            evaluate_system_transition_binding(b, b, assessments),
            SystemBindingEvaluation::Evaluated(AuthorizationDecision::Unknown)
        );
    }
}
