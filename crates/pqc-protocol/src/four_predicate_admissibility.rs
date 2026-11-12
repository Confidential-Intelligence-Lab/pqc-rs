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
