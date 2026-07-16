use pqc_ml_dsa::{
    audit::multiply_challenge_counted, challenge::sample_in_ball_bytes, constants::N, poly::Poly,
    signing_core::multiply_challenge,
};

fn polynomial(tag: i32) -> Poly {
    let mut coefficients = [0_i32; N];

    for (index, coefficient) in coefficients.iter_mut().enumerate() {
        *coefficient = (tag + index as i32 * 97).rem_euclid(8_380_417);
    }

    Poly::from_coeffs(coefficients)
}

#[test]
fn counted_result_matches_production_implementation() {
    let polynomial = polynomial(17);

    for seed_byte in 0_u8..32 {
        let challenge = sample_in_ball_bytes(&[seed_byte; 32], 39).unwrap();
        let expected = multiply_challenge(&challenge, &polynomial);
        let (actual, counts) = multiply_challenge_counted(&challenge, &polynomial);

        assert_eq!(actual.coeffs(), expected.coeffs());
        assert!(counts.obeys_weight_invariants(39));
    }
}

#[test]
fn total_work_is_identical_across_support_patterns() {
    let polynomial = polynomial(29);
    let mut reference: Option<pqc_ml_dsa::audit::ChallengeMultiplyCounts> = None;

    for seed_byte in 0_u8..64 {
        let challenge = sample_in_ball_bytes(&[seed_byte; 32], 39).unwrap();
        let (_, counts) = multiply_challenge_counted(&challenge, &polynomial);

        assert!(counts.obeys_weight_invariants(39));

        if let Some(reference_counts) = reference {
            assert_eq!(
                counts.challenge_coefficients_scanned,
                reference_counts.challenge_coefficients_scanned,
            );
            assert_eq!(
                counts.nonzero_challenge_coefficients,
                reference_counts.nonzero_challenge_coefficients,
            );
            assert_eq!(
                counts.coefficient_multiplications,
                reference_counts.coefficient_multiplications,
            );
            assert_eq!(
                counts.total_accumulations(),
                reference_counts.total_accumulations(),
            );
            assert_eq!(
                counts.modular_reductions,
                reference_counts.modular_reductions,
            );
        } else {
            reference = Some(counts);
        }
    }
}
