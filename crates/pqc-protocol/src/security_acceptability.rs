//! Advisory, context-bound cryptographic security assessments.
//!
//! Assessment outcomes and context identities are supplied by the caller.
//! This module does not estimate cryptographic strength, authenticate
//! evidence, or authorize cryptographic transitions.

use crate::{ConfigurationIdentity, ThreatPhaseId};

/// Opaque identity of externally specified security requirements.
///
/// The identifier does not describe or validate requirement contents.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SecurityRequirementId(u64);

impl SecurityRequirementId {
    /// Construct a caller-assigned requirement identity.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the caller-assigned identity.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Exact context to which a security assessment applies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityAssessmentBinding {
    configuration: ConfigurationIdentity,
    threat: ThreatPhaseId,
    requirement: SecurityRequirementId,
}

impl SecurityAssessmentBinding {
    /// Construct an exact assessment binding.
    pub const fn new(
        configuration: ConfigurationIdentity,
        threat: ThreatPhaseId,
        requirement: SecurityRequirementId,
    ) -> Self {
        Self {
            configuration,
            threat,
            requirement,
        }
    }

    /// Return the assessed configuration.
    pub const fn configuration(self) -> ConfigurationIdentity {
        self.configuration
    }

    /// Return the assessed threat phase.
    pub const fn threat(self) -> ThreatPhaseId {
        self.threat
    }

    /// Return the assessed security requirement.
    pub const fn requirement(self) -> SecurityRequirementId {
        self.requirement
    }
}

/// Externally determined security acceptability.
///
/// These values are not authorization decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityAcceptability {
    /// The supplied assessment establishes acceptability.
    Acceptable,
    /// The supplied assessment establishes unacceptability.
    Unacceptable,
    /// The supplied assessment does not establish either conclusion.
    Unknown,
}

/// A caller-supplied security assessment with explicit context binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityAssessment {
    binding: SecurityAssessmentBinding,
    acceptability: SecurityAcceptability,
}

impl SecurityAssessment {
    /// Associate an externally supplied outcome with its assessed context.
    pub const fn new(
        binding: SecurityAssessmentBinding,
        acceptability: SecurityAcceptability,
    ) -> Self {
        Self {
            binding,
            acceptability,
        }
    }

    /// Return the context covered by this assessment.
    pub const fn binding(self) -> SecurityAssessmentBinding {
        self.binding
    }

    /// Return the externally supplied outcome.
    pub const fn acceptability(self) -> SecurityAcceptability {
        self.acceptability
    }
}

/// Result of checking an assessment against a requested context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityAssessmentEvaluation {
    /// The assessment matches the requested context.
    Matched(SecurityAcceptability),
    /// The assessed configuration differs from the requested one.
    ConfigurationMismatch,
    /// The assessed threat phase differs from the requested one.
    ThreatMismatch,
    /// The assessed security requirement differs from the requested one.
    RequirementMismatch,
}

/// Evaluate a caller-supplied assessment against an exact context.
///
/// Mismatch checks have deterministic precedence: configuration, threat,
/// then requirement. No assessment outcome is returned on a mismatch.
pub fn evaluate_security_assessment(
    requested: SecurityAssessmentBinding,
    assessment: SecurityAssessment,
) -> SecurityAssessmentEvaluation {
    let assessed = assessment.binding();

    if assessed.configuration() != requested.configuration() {
        return SecurityAssessmentEvaluation::ConfigurationMismatch;
    }

    if assessed.threat() != requested.threat() {
        return SecurityAssessmentEvaluation::ThreatMismatch;
    }

    if assessed.requirement() != requested.requirement() {
        return SecurityAssessmentEvaluation::RequirementMismatch;
    }

    SecurityAssessmentEvaluation::Matched(assessment.acceptability())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlgorithmId, ImplementationRevision, ParameterSetId, ProviderId};

    fn configuration(revision: u64) -> ConfigurationIdentity {
        ConfigurationIdentity::new(
            AlgorithmId::new(1),
            ParameterSetId::new(768),
            ProviderId::new(2),
            ImplementationRevision::new(revision),
        )
    }

    fn binding(revision: u64, threat: u64, requirement: u64) -> SecurityAssessmentBinding {
        SecurityAssessmentBinding::new(
            configuration(revision),
            ThreatPhaseId::new(threat),
            SecurityRequirementId::new(requirement),
        )
    }

    #[test]
    fn requirement_identity_round_trip() {
        assert_eq!(SecurityRequirementId::new(42).value(), 42);
        assert_ne!(SecurityRequirementId::new(1), SecurityRequirementId::new(2));
    }

    #[test]
    fn binding_accessors_preserve_exact_context() {
        let context = binding(3, 4, 5);
        assert_eq!(context.configuration(), configuration(3));
        assert_eq!(context.threat(), ThreatPhaseId::new(4));
        assert_eq!(context.requirement(), SecurityRequirementId::new(5));
    }

    #[test]
    fn acceptable_assessment_matches() {
        let context = binding(1, 2, 3);
        let assessment = SecurityAssessment::new(context, SecurityAcceptability::Acceptable);

        assert_eq!(assessment.binding(), context);
        assert_eq!(
            assessment.acceptability(),
            SecurityAcceptability::Acceptable
        );
        assert_eq!(
            evaluate_security_assessment(context, assessment),
            SecurityAssessmentEvaluation::Matched(SecurityAcceptability::Acceptable)
        );
    }

    #[test]
    fn unacceptable_assessment_matches() {
        let context = binding(1, 2, 3);
        let assessment = SecurityAssessment::new(context, SecurityAcceptability::Unacceptable);

        assert_eq!(
            evaluate_security_assessment(context, assessment),
            SecurityAssessmentEvaluation::Matched(SecurityAcceptability::Unacceptable)
        );
    }

    #[test]
    fn unknown_assessment_matches_without_becoming_acceptable() {
        let context = binding(1, 2, 3);
        let assessment = SecurityAssessment::new(context, SecurityAcceptability::Unknown);

        assert_eq!(
            evaluate_security_assessment(context, assessment),
            SecurityAssessmentEvaluation::Matched(SecurityAcceptability::Unknown)
        );
    }

    #[test]
    fn configuration_mismatch_is_distinct() {
        let requested = binding(1, 2, 3);
        let assessment =
            SecurityAssessment::new(binding(9, 2, 3), SecurityAcceptability::Acceptable);

        assert_eq!(
            evaluate_security_assessment(requested, assessment),
            SecurityAssessmentEvaluation::ConfigurationMismatch
        );
    }

    #[test]
    fn threat_mismatch_is_distinct() {
        let requested = binding(1, 2, 3);
        let assessment =
            SecurityAssessment::new(binding(1, 9, 3), SecurityAcceptability::Acceptable);

        assert_eq!(
            evaluate_security_assessment(requested, assessment),
            SecurityAssessmentEvaluation::ThreatMismatch
        );
    }

    #[test]
    fn requirement_mismatch_is_distinct() {
        let requested = binding(1, 2, 3);
        let assessment =
            SecurityAssessment::new(binding(1, 2, 9), SecurityAcceptability::Acceptable);

        assert_eq!(
            evaluate_security_assessment(requested, assessment),
            SecurityAssessmentEvaluation::RequirementMismatch
        );
    }

    #[test]
    fn mismatch_precedence_is_deterministic() {
        let requested = binding(1, 2, 3);
        let assessment =
            SecurityAssessment::new(binding(9, 9, 9), SecurityAcceptability::Unacceptable);

        assert_eq!(
            evaluate_security_assessment(requested, assessment),
            SecurityAssessmentEvaluation::ConfigurationMismatch
        );
    }

    #[test]
    fn matching_outcome_does_not_override_context_mismatch() {
        let requested = binding(1, 2, 3);
        let assessment = SecurityAssessment::new(binding(1, 9, 3), SecurityAcceptability::Unknown);

        assert_eq!(
            evaluate_security_assessment(requested, assessment),
            SecurityAssessmentEvaluation::ThreatMismatch
        );
    }
}
