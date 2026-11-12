//! Independent structural safety evaluation of proposed system-state paths.
//!
//! Authorization is deliberately excluded from this evaluation.
//! States and invariants are caller-supplied and are not authenticated.
//! Only represented states are checked; no transition is executed.

use crate::CryptographicSystemState;

/// A proposed step between complete cryptographic system states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndependentPathStep {
    /// Source system state.
    pub source: CryptographicSystemState,
    /// Destination system state.
    pub destination: CryptographicSystemState,
}

/// Structural outcome of a proposed path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndependentPathSafety {
    /// Every represented state and path connection passed.
    Safe,
    /// Initial state violates the supplied invariant.
    InitialInvariantViolation,
    /// Step source differs from the preceding state.
    Disconnected {
        /// Zero-based step index.
        step: usize,
    },
    /// A represented destination violates the supplied invariant.
    InvariantViolation {
        /// Zero-based step index.
        step: usize,
    },
    /// Final represented state differs from the requested target.
    TargetMismatch,
}

/// Evaluate represented-path safety without authorization decisions.
///
/// This evaluates only caller-supplied state identities and invariants.
/// It does not authenticate inputs, validate unrepresented intermediate
/// execution states, authorize a transition, or execute any operation.
///
/// An empty path is safe only when the initial state satisfies the
/// invariant and equals the target.
pub fn evaluate_independent_path_safety<F>(
    initial: CryptographicSystemState,
    target: CryptographicSystemState,
    steps: &[IndependentPathStep],
    invariant: F,
) -> IndependentPathSafety
where
    F: Fn(CryptographicSystemState) -> bool,
{
    if !invariant(initial) {
        return IndependentPathSafety::InitialInvariantViolation;
    }

    let mut current = initial;

    for (index, step) in steps.iter().enumerate() {
        if step.source != current {
            return IndependentPathSafety::Disconnected { step: index };
        }

        if !invariant(step.destination) {
            return IndependentPathSafety::InvariantViolation { step: index };
        }

        current = step.destination;
    }

    if current != target {
        return IndependentPathSafety::TargetMismatch;
    }

    IndependentPathSafety::Safe
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AlgorithmId, ConfigurationIdentity, DeploymentStateIdentity, EvidenceStateIdentity,
        ImplementationRevision, ParameterSetId, PolicyStateIdentity, ProviderId,
    };

    fn state(provider: u32, policy: u64) -> CryptographicSystemState {
        CryptographicSystemState::new(
            ConfigurationIdentity::new(
                AlgorithmId::new(1),
                ParameterSetId::new(768),
                ProviderId::new(provider),
                ImplementationRevision::new(1),
            ),
            PolicyStateIdentity::new(policy),
            EvidenceStateIdentity::new(20),
            DeploymentStateIdentity::new(30),
        )
    }

    fn step(
        source: CryptographicSystemState,
        destination: CryptographicSystemState,
    ) -> IndependentPathStep {
        IndependentPathStep {
            source,
            destination,
        }
    }

    #[test]
    fn connected_safe_path_passes() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);

        assert_eq!(
            evaluate_independent_path_safety(a, c, &[step(a, b), step(b, c)], |_| true,),
            IndependentPathSafety::Safe,
        );
    }

    #[test]
    fn unsafe_destination_is_detected_independently() {
        let a = state(1, 10);
        let b = state(2, 99);

        assert_eq!(
            evaluate_independent_path_safety(a, b, &[step(a, b)], |s| s.policy().value() != 99,),
            IndependentPathSafety::InvariantViolation { step: 0 },
        );
    }

    #[test]
    fn disconnected_path_is_rejected() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);

        assert_eq!(
            evaluate_independent_path_safety(a, c, &[step(b, c)], |_| true,),
            IndependentPathSafety::Disconnected { step: 0 },
        );
    }

    #[test]
    fn initial_invariant_is_checked() {
        let a = state(1, 99);

        assert_eq!(
            evaluate_independent_path_safety(a, a, &[], |s| s.policy().value() != 99,),
            IndependentPathSafety::InitialInvariantViolation,
        );
    }

    #[test]
    fn target_mismatch_is_rejected() {
        let a = state(1, 10);
        let b = state(2, 11);
        let c = state(3, 12);

        assert_eq!(
            evaluate_independent_path_safety(a, c, &[step(a, b)], |_| true,),
            IndependentPathSafety::TargetMismatch,
        );
    }

    #[test]
    fn empty_path_requires_matching_target() {
        let a = state(1, 10);
        let b = state(2, 11);

        assert_eq!(
            evaluate_independent_path_safety(a, a, &[], |_| true),
            IndependentPathSafety::Safe,
        );

        assert_eq!(
            evaluate_independent_path_safety(a, b, &[], |_| true),
            IndependentPathSafety::TargetMismatch,
        );
    }

    #[test]
    fn represented_intermediate_state_is_checked() {
        let a = state(1, 10);
        let b = state(2, 99);
        let c = state(3, 12);

        assert_eq!(
            evaluate_independent_path_safety(a, c, &[step(a, b), step(b, c)], |s| s
                .policy()
                .value()
                != 99,),
            IndependentPathSafety::InvariantViolation { step: 0 },
        );
    }
}
