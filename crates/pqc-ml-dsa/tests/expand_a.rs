#![cfg(feature = "internal-api")]

use pqc_ml_dsa::constants::Q;
use pqc_ml_dsa::expand_a::{expand_a, rej_ntt_poly};
use pqc_ml_dsa::params::MlDsaParameterSet;

#[test]
fn matrix_dimensions_match_all_parameter_sets() {
    let rho = [0x11; 32];

    for set in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ] {
        let parameters = set.parameters();
        let matrix = expand_a(&rho, set).unwrap();

        assert_eq!(matrix.rows(), parameters.k);
        assert_eq!(matrix.columns(), parameters.l);
        assert_eq!(matrix.entries().len(), parameters.k * parameters.l);
    }
}

#[test]
fn every_expanded_coefficient_is_canonical() {
    let rho = [0x22; 32];

    for set in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ] {
        let matrix = expand_a(&rho, set).unwrap();

        for polynomial in matrix.entries() {
            assert!(polynomial
                .coeffs()
                .iter()
                .all(|coefficient| (0..Q).contains(coefficient)));
        }
    }
}

#[test]
fn expansion_is_deterministic() {
    let rho = [0x33; 32];
    let first = expand_a(&rho, MlDsaParameterSet::MlDsa65).unwrap();
    let second = expand_a(&rho, MlDsaParameterSet::MlDsa65).unwrap();

    assert!(first == second);
}

#[test]
fn coordinates_are_domain_separated() {
    let rho = [0x44; 32];
    let a01 = rej_ntt_poly(&rho, 0, 1);
    let a10 = rej_ntt_poly(&rho, 1, 0);

    assert!(a01 != a10);
}

#[test]
fn different_seeds_produce_different_matrices() {
    let first = expand_a(&[0x55; 32], MlDsaParameterSet::MlDsa44).unwrap();
    let second = expand_a(&[0x56; 32], MlDsaParameterSet::MlDsa44).unwrap();

    assert!(first != second);
}

#[test]
fn matrix_lookup_is_row_major_and_bounds_checked() {
    let matrix = expand_a(&[0x66; 32], MlDsaParameterSet::MlDsa44).unwrap();

    assert!(matrix.get(0, 0).is_some());
    assert!(matrix
        .get(matrix.rows() - 1, matrix.columns() - 1)
        .is_some());
    assert!(matrix.get(matrix.rows(), 0).is_none());
    assert!(matrix.get(0, matrix.columns()).is_none());
}
