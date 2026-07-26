#![cfg(feature = "internal-api")]

use pqc_ml_dsa::challenge::{challenge_weight, is_sparse_signed};
use pqc_ml_dsa::constants::{N, Q};
use pqc_ml_dsa::expand_a::expand_a;
use pqc_ml_dsa::params::MlDsaParameterSet;
use pqc_ml_dsa::poly::Poly;
use pqc_ml_dsa::signing::sample_mask_vector;
use pqc_ml_dsa::signing_core::{
    challenge_seed_bytes, derive_challenge, encode_w1_vector, gamma2_for, high_bits_vector,
    infinity_norm_below, matrix_vector_product, multiply_challenge, vector_infinity_norm_below,
};

#[test]
fn challenge_seed_lengths_match_fips_security_strengths() {
    assert_eq!(challenge_seed_bytes(MlDsaParameterSet::MlDsa44), 32);
    assert_eq!(challenge_seed_bytes(MlDsaParameterSet::MlDsa65), 48);
    assert_eq!(challenge_seed_bytes(MlDsaParameterSet::MlDsa87), 64);
}

#[test]
fn challenge_derivation_supports_all_parameter_sets() {
    for parameter_set in [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ] {
        let gamma2 = gamma2_for(parameter_set);
        let parameters = parameter_set.parameters();

        let mut w1_coefficients = [0_i32; N];
        for (index, coefficient) in w1_coefficients.iter_mut().enumerate() {
            *coefficient = (index as i32).rem_euclid(gamma2.high_modulus());
        }

        let w1 = vec![Poly::from_coeffs(w1_coefficients); parameters.k];
        let encoded = encode_w1_vector(&w1, gamma2).unwrap();
        let (seed, challenge) = derive_challenge(parameter_set, &[0x11; 64], &encoded).unwrap();

        assert_eq!(seed.len(), challenge_seed_bytes(parameter_set));
        assert_eq!(challenge_weight(&challenge), parameters.tau);
        assert!(is_sparse_signed(&challenge));
    }
}

#[test]
fn matrix_vector_product_has_expected_dimensions() {
    let parameter_set = MlDsaParameterSet::MlDsa44;
    let parameters = parameter_set.parameters();
    let matrix = expand_a(&[0x22; 32], parameter_set).unwrap();
    let vector = sample_mask_vector(&[0x33; 64], 0, parameters.l, parameters.gamma1).unwrap();

    let product = matrix_vector_product(&matrix, &vector).unwrap();
    assert_eq!(product.len(), parameters.k);

    let high = high_bits_vector(&product, gamma2_for(parameter_set));
    assert_eq!(high.len(), parameters.k);
}

#[test]
fn norm_checks_are_strict() {
    let zero = Poly::zero();
    assert!(infinity_norm_below(&zero, 1));
    assert!(!infinity_norm_below(&zero, 0));

    let mut coefficients = [0_i32; N];
    coefficients[7] = 10;
    let polynomial = Poly::from_coeffs(coefficients);

    assert!(!infinity_norm_below(&polynomial, 10));
    assert!(infinity_norm_below(&polynomial, 11));
    assert!(vector_infinity_norm_below(&[zero], 1));
}

#[test]
fn sparse_challenge_multiplication_respects_negacyclic_wrap() {
    let mut challenge_coefficients = [0_i32; N];
    challenge_coefficients[N - 1] = 1;
    let challenge = Poly::from_coeffs(challenge_coefficients);

    let mut polynomial_coefficients = [0_i32; N];
    polynomial_coefficients[1] = 3;
    let polynomial = Poly::from_coeffs(polynomial_coefficients);

    let product = multiply_challenge(&challenge, &polynomial);

    assert_eq!(product.coeffs()[0], Q - 3);
    assert!(product
        .coeffs()
        .iter()
        .enumerate()
        .all(|(index, coefficient)| index == 0 || *coefficient == 0));
}
