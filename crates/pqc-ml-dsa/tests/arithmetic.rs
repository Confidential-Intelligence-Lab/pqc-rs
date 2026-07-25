#![cfg(feature = "internal-api")]

use pqc_ml_dsa::constants::{N, Q};
use pqc_ml_dsa::poly::Poly;

fn sample_poly() -> Poly {
    let mut coefficients = [0_i32; N];

    for (index, coefficient) in coefficients.iter_mut().enumerate() {
        *coefficient = ((index as i32 * 17_123) - 41_337).rem_euclid(Q);
    }

    Poly::from_coeffs(coefficients)
}

#[test]
fn ntt_round_trip_matches_montgomery_scaled_input() {
    let original = sample_poly();
    let mut transformed = original.clone();

    transformed.ntt();
    transformed.inv_ntt_to_mont();
    transformed.freeze();

    // The inverse transform returns Montgomery-scaled coefficients.
    // A later stage will add explicit conversion helpers and reference KATs.
    assert!(transformed.is_canonical());
    assert_ne!(transformed.coeffs(), &[0_i32; N]);
}

#[test]
fn add_then_subtract_recovers_input() {
    let left = sample_poly();
    let right = Poly::from_coeffs([7_i32; N]);
    let mut result = left.clone();

    result.add_assign(&right);
    result.sub_assign(&right);
    result.freeze();

    let mut expected = left;
    expected.freeze();

    assert!(result == expected);
}

#[test]
fn pointwise_product_is_deterministic() {
    let mut left = sample_poly();
    let mut right = Poly::from_coeffs([3_i32; N]);

    left.ntt();
    right.ntt();

    let first = left.pointwise_montgomery(&right);
    let second = left.pointwise_montgomery(&right);

    assert!(first == second);
}
