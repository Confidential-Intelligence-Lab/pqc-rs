use pqc_ml_dsa::challenge::{challenge_weight, is_sparse_signed, sample_in_ball, ChallengeError};
use pqc_ml_dsa::params::MlDsaParameterSet;

#[test]
fn challenge_sampling_matches_all_parameter_weights() {
    for (index, set) in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ]
    .into_iter()
    .enumerate()
    {
        let mut seed = [0_u8; 32];
        seed[0] = index as u8 + 1;

        let tau = set.parameters().tau;
        let challenge = sample_in_ball(&seed, tau).unwrap();

        assert_eq!(challenge_weight(&challenge), tau);
        assert!(is_sparse_signed(&challenge));
    }
}

#[test]
fn challenge_sampling_is_deterministic() {
    let seed = [0x11; 32];

    let first = sample_in_ball(&seed, 49).unwrap();
    let second = sample_in_ball(&seed, 49).unwrap();

    assert!(first == second);
}

#[test]
fn different_seeds_produce_different_challenges() {
    let first = sample_in_ball(&[0x22; 32], 60).unwrap();
    let second = sample_in_ball(&[0x23; 32], 60).unwrap();

    assert!(first != second);
}

#[test]
fn every_nonzero_coefficient_is_signed_unit() {
    let challenge = sample_in_ball(&[0x33; 32], 39).unwrap();

    for coefficient in challenge.coeffs() {
        assert!((-1..=1).contains(coefficient));
    }
}

#[test]
fn invalid_tau_is_rejected_without_debugging_polynomials() {
    assert!(matches!(
        sample_in_ball(&[0x44; 32], 0),
        Err(ChallengeError::InvalidTau)
    ));

    assert!(matches!(
        sample_in_ball(&[0x44; 32], 65),
        Err(ChallengeError::InvalidTau)
    ));
}
