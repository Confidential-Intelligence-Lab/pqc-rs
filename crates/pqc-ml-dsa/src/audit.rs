//! Audit-only instrumentation for sparse challenge multiplication.

use crate::{constants::N, poly::Poly, signing_core::multiply_challenge};

/// Operation counts for sparse challenge multiplication.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChallengeMultiplyCounts {
    /// Challenge coefficients inspected.
    pub challenge_coefficients_scanned: usize,
    /// Nonzero challenge coefficients processed.
    pub nonzero_challenge_coefficients: usize,
    /// Polynomial coefficients scanned under nonzero challenge terms.
    pub polynomial_coefficients_scanned: usize,
    /// Signed coefficient multiplications.
    pub coefficient_multiplications: usize,
    /// Direct accumulations.
    pub direct_accumulations: usize,
    /// Negacyclic wrapped accumulations.
    pub wrapped_accumulations: usize,
    /// Final modular reductions.
    pub modular_reductions: usize,
}

impl ChallengeMultiplyCounts {
    /// Total accumulation operations.
    pub const fn total_accumulations(self) -> usize {
        self.direct_accumulations + self.wrapped_accumulations
    }

    /// Check fixed-work invariants for challenge weight `tau`.
    pub const fn obeys_weight_invariants(self, tau: usize) -> bool {
        self.challenge_coefficients_scanned == N
            && self.nonzero_challenge_coefficients == tau
            && self.polynomial_coefficients_scanned == tau * N
            && self.coefficient_multiplications == tau * N
            && self.total_accumulations() == tau * N
            && self.modular_reductions == N
    }
}

/// Return the production result together with audit operation counts.
pub fn multiply_challenge_counted(
    challenge: &Poly,
    polynomial: &Poly,
) -> (Poly, ChallengeMultiplyCounts) {
    let result = multiply_challenge(challenge, polynomial);
    let mut counts = ChallengeMultiplyCounts {
        challenge_coefficients_scanned: N,
        modular_reductions: N,
        ..ChallengeMultiplyCounts::default()
    };

    for (challenge_index, challenge_coefficient) in challenge.coeffs().iter().enumerate() {
        if *challenge_coefficient == 0 {
            continue;
        }

        counts.nonzero_challenge_coefficients += 1;
        counts.polynomial_coefficients_scanned += N;
        counts.coefficient_multiplications += N;

        for polynomial_index in 0..N {
            if challenge_index + polynomial_index < N {
                counts.direct_accumulations += 1;
            } else {
                counts.wrapped_accumulations += 1;
            }
        }
    }

    (result, counts)
}
