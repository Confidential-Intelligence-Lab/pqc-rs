//! Independent four-predicate advisory transition admissibility.
//!
//! The four predicates are authorization, security acceptability,
//! represented-path safety, and operational feasibility.
//!
//! Legacy authorization is retained only for comparison.
//! Inputs are caller-supplied and are not authenticated.
//! No result authorizes or executes a cryptographic transition.

use crate::{AuthorizationDecision, IndependentPathSafety};

/// The four independently assessed admissibility predicates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FourPredicateComponents {
    /// Transition authorization.
    pub authorized: AuthorizationDecision,
    /// Security acceptability.
    pub acceptable: AuthorizationDecision,
    /// Independent structural safety of the represented path.
    pub path_safe: IndependentPathSafety,
    /// Operational feasibility.
    pub feasible: AuthorizationDecision,
}

/// Result of independent four-predicate evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FourPredicateEvaluation {
    /// All four predicates were combined.
    Evaluated(AuthorizationDecision),
    /// The represented path failed structural safety.
    InvalidPath(IndependentPathSafety),
}

/// Combine exactly four admissibility predicates.
///
/// A structurally invalid path is reported separately rather
/// than converted into an unresolved authorization decision.
///
/// For structurally safe paths, precedence is:
/// Deny > Unknown > Defer > Allow.
///
/// This function does not enforce or execute a transition.
pub fn evaluate_four_predicate_admissibility(
    components: FourPredicateComponents,
) -> FourPredicateEvaluation {
    use AuthorizationDecision::{Allow, Defer, Deny, Unknown};

    if components.path_safe != IndependentPathSafety::Safe {
        return FourPredicateEvaluation::InvalidPath(components.path_safe);
    }

    let decisions = [
        components.authorized,
        components.acceptable,
        components.feasible,
    ];

    let decision = if decisions.contains(&Deny) {
        Deny
    } else if decisions.contains(&Unknown) {
        Unknown
    } else if decisions.contains(&Defer) {
        Defer
    } else {
        Allow
    };

    FourPredicateEvaluation::Evaluated(decision)
}

#[cfg(test)]
mod tests {

    #[test]
    fn exhaustive_legacy_equivalence() {
        use crate::{
            authorize_transition, evaluate_admissibility_components,
            AdmissibilityComponentEvaluation, AlgorithmId, ConfigurationIdentity,
            CryptographicTransition, EvidenceApplicability, EvidenceScope, ImplementationRevision,
            OperationalReadiness, ParameterSetId, PolicyAssessment, ProviderId,
            SystemPathEvaluation, TransitionAssessments,
        };

        let source = ConfigurationIdentity::new(
            AlgorithmId::new(1),
            ParameterSetId::new(768),
            ProviderId::new(1),
            ImplementationRevision::new(1),
        );

        let destination = ConfigurationIdentity::new(
            AlgorithmId::new(1),
            ParameterSetId::new(768),
            ProviderId::new(2),
            ImplementationRevision::new(1),
        );

        let transition =
            CryptographicTransition::new(source, destination, EvidenceScope::Encapsulation);

        let policies = [
            PolicyAssessment::Permitted,
            PolicyAssessment::Prohibited,
            PolicyAssessment::Unknown,
        ];

        let evidence = [
            EvidenceApplicability::Applicable,
            EvidenceApplicability::Mismatch,
            EvidenceApplicability::Missing,
            EvidenceApplicability::Indeterminate,
        ];

        let readiness = [
            OperationalReadiness::Ready,
            OperationalReadiness::Pending,
            OperationalReadiness::Unknown,
        ];

        let mut cases = 0_usize;

        for transition_policy in policies {
            for source_policy in policies {
                for destination_policy in policies {
                    for destination_evidence in evidence {
                        for readiness in readiness {
                            let assessments = TransitionAssessments {
                                assessed_transition: transition,
                                transition_policy,
                                source_policy,
                                destination_policy,
                                destination_evidence,
                                readiness,
                            };

                            let legacy = authorize_transition(transition, assessments);

                            let components = evaluate_admissibility_components(
                                transition,
                                assessments,
                                SystemPathEvaluation::Complete,
                            );

                            let components = match components {
                                AdmissibilityComponentEvaluation::Evaluated(components) => {
                                    components
                                }
                                AdmissibilityComponentEvaluation::TransitionMismatch => {
                                    panic!("matching transition was rejected")
                                }
                            };

                            let independent = FourPredicateComponents {
                                authorized: components.authorized,
                                acceptable: components.acceptable,
                                path_safe: IndependentPathSafety::Safe,
                                feasible: components.feasible,
                            };

                            assert_eq!(
                                evaluate_four_predicate_admissibility(independent,),
                                FourPredicateEvaluation::Evaluated(legacy),
                                "equivalence failed at case {cases}",
                            );

                            assert_eq!(components.legacy_authorization, legacy,);

                            cases += 1;
                        }
                    }
                }
            }
        }

        assert_eq!(cases, 324);
    }

    #[test]
    fn exhaustive_four_value_precedence() {
        let values = [
            AuthorizationDecision::Allow,
            AuthorizationDecision::Deny,
            AuthorizationDecision::Defer,
            AuthorizationDecision::Unknown,
        ];

        let mut cases = 0_usize;

        for authorized in values {
            for acceptable in values {
                for feasible in values {
                    let inputs = [authorized, acceptable, feasible];

                    let expected = if inputs.contains(&AuthorizationDecision::Deny) {
                        AuthorizationDecision::Deny
                    } else if inputs.contains(&AuthorizationDecision::Unknown) {
                        AuthorizationDecision::Unknown
                    } else if inputs.contains(&AuthorizationDecision::Defer) {
                        AuthorizationDecision::Defer
                    } else {
                        AuthorizationDecision::Allow
                    };

                    assert_eq!(
                        evaluate_four_predicate_admissibility(FourPredicateComponents {
                            authorized,
                            acceptable,
                            path_safe: IndependentPathSafety::Safe,
                            feasible,
                        },),
                        FourPredicateEvaluation::Evaluated(expected),
                        "precedence failed at case {cases}",
                    );

                    cases += 1;
                }
            }
        }

        assert_eq!(cases, 64);
    }

    #[test]
    fn structural_failure_independence() {
        let failures = [
            IndependentPathSafety::InitialInvariantViolation,
            IndependentPathSafety::Disconnected { step: 0 },
            IndependentPathSafety::InvariantViolation { step: 1 },
            IndependentPathSafety::TargetMismatch,
        ];

        let values = [
            AuthorizationDecision::Allow,
            AuthorizationDecision::Deny,
            AuthorizationDecision::Defer,
            AuthorizationDecision::Unknown,
        ];

        let mut cases = 0_usize;

        for path_safe in failures {
            for authorized in values {
                for acceptable in values {
                    for feasible in values {
                        let result =
                            evaluate_four_predicate_admissibility(FourPredicateComponents {
                                authorized,
                                acceptable,
                                path_safe,
                                feasible,
                            });

                        assert_eq!(result, FourPredicateEvaluation::InvalidPath(path_safe),);

                        cases += 1;
                    }
                }
            }
        }

        assert_eq!(cases, 256);
    }

    use super::*;

    fn components() -> FourPredicateComponents {
        FourPredicateComponents {
            authorized: AuthorizationDecision::Allow,
            acceptable: AuthorizationDecision::Allow,
            path_safe: IndependentPathSafety::Safe,
            feasible: AuthorizationDecision::Allow,
        }
    }

    #[test]
    fn all_four_predicates_satisfied() {
        assert_eq!(
            evaluate_four_predicate_admissibility(components()),
            FourPredicateEvaluation::Evaluated(AuthorizationDecision::Allow)
        );
    }

    #[test]
    fn authorization_denial_dominates() {
        let mut c = components();
        c.authorized = AuthorizationDecision::Deny;
        c.acceptable = AuthorizationDecision::Unknown;
        c.feasible = AuthorizationDecision::Defer;

        assert_eq!(
            evaluate_four_predicate_admissibility(c),
            FourPredicateEvaluation::Evaluated(AuthorizationDecision::Deny)
        );
    }

    #[test]
    fn acceptability_denial_dominates() {
        let mut c = components();
        c.acceptable = AuthorizationDecision::Deny;

        assert_eq!(
            evaluate_four_predicate_admissibility(c),
            FourPredicateEvaluation::Evaluated(AuthorizationDecision::Deny)
        );
    }

    #[test]
    fn unknown_dominates_defer() {
        let mut c = components();
        c.authorized = AuthorizationDecision::Defer;
        c.feasible = AuthorizationDecision::Unknown;

        assert_eq!(
            evaluate_four_predicate_admissibility(c),
            FourPredicateEvaluation::Evaluated(AuthorizationDecision::Unknown)
        );
    }

    #[test]
    fn pending_feasibility_defers() {
        let mut c = components();
        c.feasible = AuthorizationDecision::Defer;

        assert_eq!(
            evaluate_four_predicate_admissibility(c),
            FourPredicateEvaluation::Evaluated(AuthorizationDecision::Defer)
        );
    }

    #[test]
    fn disconnected_path_is_structural_failure() {
        let mut c = components();
        c.path_safe = IndependentPathSafety::Disconnected { step: 2 };

        assert_eq!(
            evaluate_four_predicate_admissibility(c),
            FourPredicateEvaluation::InvalidPath(IndependentPathSafety::Disconnected { step: 2 })
        );
    }

    #[test]
    fn unsafe_path_is_not_masked_by_denial() {
        let mut c = components();
        c.authorized = AuthorizationDecision::Deny;
        c.path_safe = IndependentPathSafety::InvariantViolation { step: 1 };

        assert_eq!(
            evaluate_four_predicate_admissibility(c),
            FourPredicateEvaluation::InvalidPath(IndependentPathSafety::InvariantViolation {
                step: 1,
            })
        );
    }

    #[test]
    fn initial_invariant_failure_is_preserved() {
        let mut c = components();
        c.path_safe = IndependentPathSafety::InitialInvariantViolation;

        assert_eq!(
            evaluate_four_predicate_admissibility(c),
            FourPredicateEvaluation::InvalidPath(IndependentPathSafety::InitialInvariantViolation)
        );
    }

    #[test]
    fn target_mismatch_is_preserved() {
        let mut c = components();
        c.path_safe = IndependentPathSafety::TargetMismatch;

        assert_eq!(
            evaluate_four_predicate_admissibility(c),
            FourPredicateEvaluation::InvalidPath(IndependentPathSafety::TargetMismatch)
        );
    }

    #[test]
    fn all_four_valued_decisions_are_representable() {
        for decision in [
            AuthorizationDecision::Allow,
            AuthorizationDecision::Deny,
            AuthorizationDecision::Defer,
            AuthorizationDecision::Unknown,
        ] {
            let mut c = components();
            c.authorized = decision;

            assert_eq!(
                evaluate_four_predicate_admissibility(c),
                FourPredicateEvaluation::Evaluated(decision)
            );
        }
    }
}
