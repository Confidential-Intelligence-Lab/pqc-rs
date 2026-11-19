//! Diagnostic decomposition of cryptographic transition admissibility.
//!
//! This module separates authorization, security acceptability,
//! represented-path safety, and operational feasibility.
//!
//! All assessments and path results are externally supplied.
//! Evaluation is advisory and performs no transition execution.

use crate::{
    authorize_transition, AuthorizationDecision, CryptographicTransition, EvidenceApplicability,
    OperationalReadiness, PolicyAssessment, SystemPathEvaluation, TransitionAssessments,
};

/// Individual diagnostic outcomes of an admissibility assessment.
///
/// The R7 authorization result is retained independently for
/// compatibility and comparison. No aggregate admissibility
/// decision is computed by this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissibilityComponents {
    /// Whether the transition policy permits the requested change.
    pub authorized: AuthorizationDecision,
    /// Whether source, destination, and evidence requirements are met.
    pub acceptable: AuthorizationDecision,
    /// Caller-supplied result of full-system-state path evaluation.
    pub path_safe: SystemPathEvaluation,
    /// Whether operational prerequisites are satisfied.
    pub feasible: AuthorizationDecision,
    /// Original R7 authorization decision.
    pub legacy_authorization: AuthorizationDecision,
}

/// Result of decomposing an assessment for an exact transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissibilityComponentEvaluation {
    /// The supplied assessments concern another transition.
    TransitionMismatch,
    /// Components were evaluated for the requested transition.
    Evaluated(AdmissibilityComponents),
}

fn policy_decision(policy: PolicyAssessment) -> AuthorizationDecision {
    match policy {
        PolicyAssessment::Permitted => AuthorizationDecision::Allow,
        PolicyAssessment::Prohibited => AuthorizationDecision::Deny,
        PolicyAssessment::Unknown => AuthorizationDecision::Unknown,
    }
}

fn acceptability_decision(
    source: PolicyAssessment,
    destination: PolicyAssessment,
    evidence: EvidenceApplicability,
) -> AuthorizationDecision {
    use AuthorizationDecision::{Allow, Defer, Deny, Unknown};

    if source == PolicyAssessment::Prohibited
        || destination == PolicyAssessment::Prohibited
        || evidence == EvidenceApplicability::Mismatch
    {
        return Deny;
    }

    if source == PolicyAssessment::Unknown
        || destination == PolicyAssessment::Unknown
        || evidence == EvidenceApplicability::Indeterminate
    {
        return Unknown;
    }

    if evidence == EvidenceApplicability::Missing {
        return Defer;
    }

    Allow
}

fn feasibility_decision(readiness: OperationalReadiness) -> AuthorizationDecision {
    match readiness {
        OperationalReadiness::Ready => AuthorizationDecision::Allow,
        OperationalReadiness::Pending => AuthorizationDecision::Defer,
        OperationalReadiness::Unknown => AuthorizationDecision::Unknown,
    }
}

/// Decompose existing assessments into admissibility diagnostics.
///
/// The assessment's transition must match the requested transition.
/// The supplied path result is not independently recomputed or
/// verified against the transition in this increment.
///
/// The returned legacy authorization preserves R7 semantics.
/// No result constitutes an execution permit.
pub fn evaluate_admissibility_components(
    transition: CryptographicTransition,
    assessments: TransitionAssessments,
    path: SystemPathEvaluation,
) -> AdmissibilityComponentEvaluation {
    if assessments.assessed_transition != transition {
        return AdmissibilityComponentEvaluation::TransitionMismatch;
    }

    AdmissibilityComponentEvaluation::Evaluated(AdmissibilityComponents {
        authorized: policy_decision(assessments.transition_policy),
        acceptable: acceptability_decision(
            assessments.source_policy,
            assessments.destination_policy,
            assessments.destination_evidence,
        ),
        path_safe: path,
        feasible: feasibility_decision(assessments.readiness),
        legacy_authorization: authorize_transition(transition, assessments),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AlgorithmId, ConfigurationIdentity, EvidenceScope, ImplementationRevision, ParameterSetId,
        ProviderId,
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

    fn components(
        assessments: TransitionAssessments,
        path: SystemPathEvaluation,
    ) -> AdmissibilityComponents {
        match evaluate_admissibility_components(transition(), assessments, path) {
            AdmissibilityComponentEvaluation::Evaluated(value) => value,
            AdmissibilityComponentEvaluation::TransitionMismatch => {
                panic!("unexpected transition mismatch")
            }
        }
    }

    #[test]
    fn all_satisfied_components_allow() {
        let result = components(permitted(), SystemPathEvaluation::Complete);

        assert_eq!(result.authorized, AuthorizationDecision::Allow);
        assert_eq!(result.acceptable, AuthorizationDecision::Allow);
        assert_eq!(result.path_safe, SystemPathEvaluation::Complete);
        assert_eq!(result.feasible, AuthorizationDecision::Allow);
        assert_eq!(result.legacy_authorization, AuthorizationDecision::Allow);
    }

    #[test]
    fn transition_prohibition_is_authorization_denial() {
        let mut a = permitted();
        a.transition_policy = PolicyAssessment::Prohibited;

        let result = components(a, SystemPathEvaluation::Complete);

        assert_eq!(result.authorized, AuthorizationDecision::Deny);
        assert_eq!(result.acceptable, AuthorizationDecision::Allow);
        assert_eq!(result.feasible, AuthorizationDecision::Allow);
        assert_eq!(result.legacy_authorization, AuthorizationDecision::Deny);
    }

    #[test]
    fn source_prohibition_is_acceptability_denial() {
        let mut a = permitted();
        a.source_policy = PolicyAssessment::Prohibited;

        let result = components(a, SystemPathEvaluation::Complete);

        assert_eq!(result.authorized, AuthorizationDecision::Allow);
        assert_eq!(result.acceptable, AuthorizationDecision::Deny);
        assert_eq!(result.legacy_authorization, AuthorizationDecision::Deny);
    }

    #[test]
    fn destination_prohibition_is_acceptability_denial() {
        let mut a = permitted();
        a.destination_policy = PolicyAssessment::Prohibited;

        let result = components(a, SystemPathEvaluation::Complete);

        assert_eq!(result.acceptable, AuthorizationDecision::Deny);
    }

    #[test]
    fn evidence_mismatch_is_acceptability_denial() {
        let mut a = permitted();
        a.destination_evidence = EvidenceApplicability::Mismatch;

        let result = components(a, SystemPathEvaluation::Complete);

        assert_eq!(result.acceptable, AuthorizationDecision::Deny);
    }

    #[test]
    fn missing_evidence_defers_acceptability() {
        let mut a = permitted();
        a.destination_evidence = EvidenceApplicability::Missing;

        let result = components(a, SystemPathEvaluation::Complete);

        assert_eq!(result.acceptable, AuthorizationDecision::Defer);
        assert_eq!(result.legacy_authorization, AuthorizationDecision::Defer);
    }

    #[test]
    fn indeterminate_evidence_is_unknown() {
        let mut a = permitted();
        a.destination_evidence = EvidenceApplicability::Indeterminate;

        let result = components(a, SystemPathEvaluation::Complete);

        assert_eq!(result.acceptable, AuthorizationDecision::Unknown);
        assert_eq!(result.legacy_authorization, AuthorizationDecision::Unknown);
    }

    #[test]
    fn pending_readiness_defers_feasibility() {
        let mut a = permitted();
        a.readiness = OperationalReadiness::Pending;

        let result = components(a, SystemPathEvaluation::Complete);

        assert_eq!(result.feasible, AuthorizationDecision::Defer);
        assert_eq!(result.legacy_authorization, AuthorizationDecision::Defer);
    }

    #[test]
    fn unknown_readiness_is_unknown_feasibility() {
        let mut a = permitted();
        a.readiness = OperationalReadiness::Unknown;

        let result = components(a, SystemPathEvaluation::Complete);

        assert_eq!(result.feasible, AuthorizationDecision::Unknown);
        assert_eq!(result.legacy_authorization, AuthorizationDecision::Unknown);
    }

    #[test]
    fn unsafe_path_is_preserved_independently() {
        let result = components(
            permitted(),
            SystemPathEvaluation::InvariantViolation { step: 2 },
        );

        assert_eq!(
            result.path_safe,
            SystemPathEvaluation::InvariantViolation { step: 2 }
        );
        assert_eq!(result.legacy_authorization, AuthorizationDecision::Allow);
    }

    #[test]
    fn simultaneous_failures_remain_visible() {
        let mut a = permitted();
        a.transition_policy = PolicyAssessment::Prohibited;
        a.destination_evidence = EvidenceApplicability::Indeterminate;
        a.readiness = OperationalReadiness::Pending;

        let result = components(a, SystemPathEvaluation::Disconnected { step: 1 });

        assert_eq!(result.authorized, AuthorizationDecision::Deny);
        assert_eq!(result.acceptable, AuthorizationDecision::Unknown);
        assert_eq!(result.feasible, AuthorizationDecision::Defer);
        assert_eq!(
            result.path_safe,
            SystemPathEvaluation::Disconnected { step: 1 }
        );
        assert_eq!(result.legacy_authorization, AuthorizationDecision::Deny);
    }

    #[test]
    fn unknown_precedes_pending_in_legacy_decision() {
        let mut a = permitted();
        a.source_policy = PolicyAssessment::Unknown;
        a.readiness = OperationalReadiness::Pending;

        let result = components(a, SystemPathEvaluation::Complete);

        assert_eq!(result.acceptable, AuthorizationDecision::Unknown);
        assert_eq!(result.feasible, AuthorizationDecision::Defer);
        assert_eq!(result.legacy_authorization, AuthorizationDecision::Unknown);
    }

    #[test]
    fn mismatched_transition_is_rejected() {
        let mut a = permitted();
        a.assessed_transition = CryptographicTransition::new(
            configuration(1),
            configuration(3),
            EvidenceScope::Encapsulation,
        );

        assert_eq!(
            evaluate_admissibility_components(transition(), a, SystemPathEvaluation::Complete,),
            AdmissibilityComponentEvaluation::TransitionMismatch
        );
    }
}
