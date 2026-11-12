//! Advisory authorization decisions for cryptographic transitions.
//!
//! This module evaluates resolved assessments. It does not establish their
//! trustworthiness, execute transitions, or issue execution permits.

use crate::{ConfigurationIdentity, EvidenceApplicability, EvidenceScope};

/// Exact configuration change requested by a caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptographicTransition {
    source: ConfigurationIdentity,
    destination: ConfigurationIdentity,
    operation: EvidenceScope,
}

impl CryptographicTransition {
    /// Construct a transition request.
    pub const fn new(
        source: ConfigurationIdentity,
        destination: ConfigurationIdentity,
        operation: EvidenceScope,
    ) -> Self {
        Self {
            source,
            destination,
            operation,
        }
    }

    /// Return the source configuration.
    pub const fn source(self) -> ConfigurationIdentity {
        self.source
    }

    /// Return the destination configuration.
    pub const fn destination(self) -> ConfigurationIdentity {
        self.destination
    }

    /// Return the requested operation.
    pub const fn operation(self) -> EvidenceScope {
        self.operation
    }
}

/// Externally resolved policy assessment.
///
/// A caller-provided assessment is not proof that policy was evaluated
/// correctly or that its context is current.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyAssessment {
    /// The evaluated constraint permits the request.
    Permitted,
    /// The evaluated constraint prohibits the request.
    Prohibited,
    /// The constraint could not be resolved.
    Unknown,
}

/// Externally observed operational readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalReadiness {
    /// Required operational prerequisites are satisfied.
    Ready,
    /// A known prerequisite remains outstanding.
    Pending,
    /// Readiness cannot be determined.
    Unknown,
}

/// Resolved inputs for an advisory authorization decision.
///
/// Each assessment must correspond to the supplied transition. This module
/// does not authenticate, bind, or independently verify those assessments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionAssessments {
    /// Exact transition for which these assessments were resolved.
    pub assessed_transition: CryptographicTransition,
    /// Whether the requested change is permitted.
    pub transition_policy: PolicyAssessment,
    /// Whether the source configuration satisfies relevant constraints.
    pub source_policy: PolicyAssessment,
    /// Whether the destination satisfies relevant constraints.
    pub destination_policy: PolicyAssessment,
    /// Applicability of required destination assurance evidence.
    pub destination_evidence: EvidenceApplicability,
    /// Readiness of operational prerequisites.
    pub readiness: OperationalReadiness,
}

/// Advisory outcome of evaluating a requested change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// All supplied assessments permit the requested transition.
    ///
    /// This is not an execution permit.
    Allow,
    /// A known prohibition or evidence mismatch prevents authorization.
    Deny,
    /// A known requirement is missing or pending.
    Defer,
    /// Available assessments cannot establish a decision.
    Unknown,
}

/// Evaluate resolved assessments for a cryptographic transition.
///
/// Explicit prohibitions and evidence mismatches take precedence.
/// Unknown assessments take precedence over pending prerequisites.
/// Only fully permitted, applicable, and ready inputs produce `Allow`.
///
/// The transition is retained as an explicit input for future context
/// binding; this evaluator does not independently verify its assessments.
pub fn authorize_transition(
    transition: CryptographicTransition,
    assessments: TransitionAssessments,
) -> AuthorizationDecision {
    use AuthorizationDecision::{Allow, Defer, Deny, Unknown};
    use EvidenceApplicability::{Applicable, Indeterminate, Mismatch, Missing};
    use OperationalReadiness::{Pending, Ready};
    use PolicyAssessment::{Permitted, Prohibited};

    if assessments.assessed_transition != transition {
        return Unknown;
    }

    if assessments.transition_policy == Prohibited
        || assessments.source_policy == Prohibited
        || assessments.destination_policy == Prohibited
        || assessments.destination_evidence == Mismatch
    {
        return Deny;
    }

    if assessments.transition_policy != Permitted
        || assessments.source_policy != Permitted
        || assessments.destination_policy != Permitted
        || assessments.destination_evidence == Indeterminate
        || assessments.readiness == OperationalReadiness::Unknown
    {
        return Unknown;
    }

    if assessments.destination_evidence == Missing || assessments.readiness == Pending {
        return Defer;
    }

    debug_assert_eq!(assessments.destination_evidence, Applicable);
    debug_assert_eq!(assessments.readiness, Ready);

    Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlgorithmId, ImplementationRevision, ParameterSetId, ProviderId};

    fn identity(provider: u32, revision: u64) -> ConfigurationIdentity {
        ConfigurationIdentity::new(
            AlgorithmId::new(1),
            ParameterSetId::new(768),
            ProviderId::new(provider),
            ImplementationRevision::new(revision),
        )
    }

    fn request() -> CryptographicTransition {
        CryptographicTransition::new(
            identity(10, 42),
            identity(11, 43),
            EvidenceScope::Encapsulation,
        )
    }

    fn permitted() -> TransitionAssessments {
        TransitionAssessments {
            assessed_transition: request(),
            transition_policy: PolicyAssessment::Permitted,
            source_policy: PolicyAssessment::Permitted,
            destination_policy: PolicyAssessment::Permitted,
            destination_evidence: EvidenceApplicability::Applicable,
            readiness: OperationalReadiness::Ready,
        }
    }

    #[test]
    fn fully_satisfied_assessments_allow() {
        assert_eq!(
            authorize_transition(request(), permitted()),
            AuthorizationDecision::Allow
        );
    }

    #[test]
    fn explicit_transition_prohibition_denies() {
        let mut a = permitted();
        a.transition_policy = PolicyAssessment::Prohibited;
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn source_prohibition_denies() {
        let mut a = permitted();
        a.source_policy = PolicyAssessment::Prohibited;
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn destination_prohibition_denies() {
        let mut a = permitted();
        a.destination_policy = PolicyAssessment::Prohibited;
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn mismatched_evidence_denies() {
        let mut a = permitted();
        a.destination_evidence = EvidenceApplicability::Mismatch;
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn missing_evidence_defers() {
        let mut a = permitted();
        a.destination_evidence = EvidenceApplicability::Missing;
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Defer
        );
    }

    #[test]
    fn pending_readiness_defers() {
        let mut a = permitted();
        a.readiness = OperationalReadiness::Pending;
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Defer
        );
    }

    #[test]
    fn unverified_evidence_is_unknown() {
        let mut a = permitted();
        a.destination_evidence = EvidenceApplicability::Indeterminate;
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Unknown
        );
    }

    #[test]
    fn unknown_policy_is_unknown() {
        let mut a = permitted();
        a.transition_policy = PolicyAssessment::Unknown;
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Unknown
        );
    }

    #[test]
    fn unknown_readiness_is_unknown() {
        let mut a = permitted();
        a.readiness = OperationalReadiness::Unknown;
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Unknown
        );
    }

    #[test]
    fn prohibition_dominates_missing_evidence() {
        let mut a = permitted();
        a.transition_policy = PolicyAssessment::Prohibited;
        a.destination_evidence = EvidenceApplicability::Missing;
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn prohibition_dominates_unknown_policy() {
        let mut a = permitted();
        a.source_policy = PolicyAssessment::Unknown;
        a.destination_policy = PolicyAssessment::Prohibited;
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn mismatch_dominates_pending_readiness() {
        let mut a = permitted();
        a.destination_evidence = EvidenceApplicability::Mismatch;
        a.readiness = OperationalReadiness::Pending;
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Deny
        );
    }

    #[test]
    fn unknown_dominates_pending() {
        let mut a = permitted();
        a.source_policy = PolicyAssessment::Unknown;
        a.readiness = OperationalReadiness::Pending;
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Unknown
        );
    }

    #[test]
    fn source_substitution_is_unknown() {
        let mut a = permitted();
        a.assessed_transition = CryptographicTransition::new(
            identity(12, 42),
            request().destination(),
            request().operation(),
        );
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Unknown
        );
    }

    #[test]
    fn destination_provider_substitution_is_unknown() {
        let mut a = permitted();
        a.assessed_transition = CryptographicTransition::new(
            request().source(),
            identity(12, 43),
            request().operation(),
        );
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Unknown
        );
    }

    #[test]
    fn destination_revision_substitution_is_unknown() {
        let mut a = permitted();
        a.assessed_transition = CryptographicTransition::new(
            request().source(),
            identity(11, 44),
            request().operation(),
        );
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Unknown
        );
    }

    #[test]
    fn operation_substitution_is_unknown() {
        let mut a = permitted();
        a.assessed_transition = CryptographicTransition::new(
            request().source(),
            request().destination(),
            EvidenceScope::Decapsulation,
        );
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Unknown
        );
    }

    #[test]
    fn context_mismatch_cannot_be_overridden_by_permitted_inputs() {
        let mut a = permitted();
        a.assessed_transition = CryptographicTransition::new(
            request().destination(),
            request().source(),
            request().operation(),
        );
        assert_eq!(
            authorize_transition(request(), a),
            AuthorizationDecision::Unknown
        );
    }

    #[test]
    fn request_accessors_preserve_exact_context() {
        let r = request();
        assert_eq!(r.source(), identity(10, 42));
        assert_eq!(r.destination(), identity(11, 43));
        assert_eq!(r.operation(), EvidenceScope::Encapsulation);
    }

    #[test]
    fn differing_transition_requests_are_distinct() {
        let a = request();
        let b = CryptographicTransition::new(a.source(), identity(11, 44), a.operation());
        assert_ne!(a, b);
    }
}
