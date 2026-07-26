#![cfg(feature = "internal-api")]

use pqc_ml_dsa::params::MlDsaParameterSet;
use pqc_ml_dsa::sample::{sample_eta_poly, sample_eta_polyvec, SamplingError};

#[test]
fn eta2_samples_are_deterministic_and_bounded() {
    let seed = [0x11; 64];
    let first = sample_eta_poly(&seed, 7, 2).unwrap();
    let second = sample_eta_poly(&seed, 7, 2).unwrap();
    let different = sample_eta_poly(&seed, 8, 2).unwrap();

    assert!(first == second);
    assert!(first != different);
    assert!(first.coeffs().iter().all(|value| (-2..=2).contains(value)));
}

#[test]
fn eta4_samples_are_deterministic_and_bounded() {
    let seed = [0x22; 64];
    let first = sample_eta_poly(&seed, 17, 4).unwrap();
    let second = sample_eta_poly(&seed, 17, 4).unwrap();
    let different = sample_eta_poly(&seed, 18, 4).unwrap();

    assert!(first == second);
    assert!(first != different);
    assert!(first.coeffs().iter().all(|value| (-4..=4).contains(value)));
}

#[test]
fn all_parameter_sets_use_their_declared_eta() {
    let seed = [0x33; 64];

    for set in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ] {
        let eta = set.parameters().eta;
        let polynomial = sample_eta_poly(&seed, 0, eta).unwrap();

        assert!(polynomial
            .coeffs()
            .iter()
            .all(|value| (-eta..=eta).contains(value)));
    }
}

#[test]
fn vector_sampling_uses_consecutive_nonces() {
    let seed = [0x44; 64];
    let vector = sample_eta_polyvec(&seed, 10, 4, 2).unwrap();

    assert_eq!(vector.len(), 4);

    for (index, polynomial) in vector.iter().enumerate() {
        let expected = sample_eta_poly(&seed, 10 + index as u16, 2).unwrap();
        assert!(polynomial == &expected);
    }
}

#[test]
fn unsupported_eta_is_rejected() {
    assert!(matches!(
        sample_eta_poly(&[0x55; 64], 0, 1),
        Err(SamplingError::UnsupportedEta)
    ));
}
