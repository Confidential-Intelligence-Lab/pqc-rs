#![cfg(feature = "internal-api")]

use pqc_ml_dsa::constants::{N, Q};
use pqc_ml_dsa::hint::{make_hint, make_hint_poly, use_hint, use_hint_poly};
use pqc_ml_dsa::poly::Poly;
use pqc_ml_dsa::rounding::{high_bits, Gamma2};

#[test]
fn scalar_hint_reproduces_adjusted_high_bits() {
    for gamma2 in [Gamma2::QMinusOneOver88, Gamma2::QMinusOneOver32] {
        let bound = gamma2.value();

        for r in representative_inputs(gamma2) {
            for z in [-bound, -bound + 1, -1, 0, 1, bound - 1, bound] {
                let hint = make_hint(z, r, gamma2);
                let recovered = use_hint(r, hint, gamma2);
                let expected = high_bits(r.wrapping_add(z), gamma2);

                // A one-bit hint can encode only a one-step adjustment.
                let base = high_bits(r, gamma2);
                let modulus = gamma2.high_modulus();
                let distance = (expected - base).rem_euclid(modulus);

                if distance == 0 || distance == 1 || distance == modulus - 1 {
                    assert_eq!(recovered, expected);
                }
            }
        }
    }
}

#[test]
fn zero_adjustment_never_sets_a_hint() {
    for gamma2 in [Gamma2::QMinusOneOver88, Gamma2::QMinusOneOver32] {
        for r in representative_inputs(gamma2) {
            assert_eq!(make_hint(0, r, gamma2), 0);
            assert_eq!(use_hint(r, 0, gamma2), high_bits(r, gamma2));
        }
    }
}

#[test]
fn polynomial_hint_weight_matches_nonzero_count() {
    let mut z_coefficients = [0_i32; N];
    let mut r_coefficients = [0_i32; N];

    for index in 0..N {
        z_coefficients[index] = match index % 5 {
            0 => -1,
            1 => 0,
            2 => 1,
            3 => 95_232,
            _ => -95_232,
        };
        r_coefficients[index] = ((index as i32 * 32_771) + 17).rem_euclid(Q);
    }

    let z = Poly::from_coeffs(z_coefficients);
    let r = Poly::from_coeffs(r_coefficients);
    let (hints, weight) = make_hint_poly(&z, &r, Gamma2::QMinusOneOver88);

    let counted = hints
        .coeffs()
        .iter()
        .filter(|coefficient| **coefficient != 0)
        .count();

    assert_eq!(weight, counted);
    assert!(hints
        .coeffs()
        .iter()
        .all(|coefficient| (0..=1).contains(coefficient)));
}

#[test]
fn polynomial_use_hint_matches_scalar_use_hint() {
    let mut r_coefficients = [0_i32; N];
    let mut hint_coefficients = [0_i32; N];

    for index in 0..N {
        r_coefficients[index] = ((index as i32 * 65_537) + 9).rem_euclid(Q);
        hint_coefficients[index] = (index % 2) as i32;
    }

    let r = Poly::from_coeffs(r_coefficients);
    let hints = Poly::from_coeffs(hint_coefficients);
    let output = use_hint_poly(&r, &hints, Gamma2::QMinusOneOver32);

    for index in 0..N {
        assert_eq!(
            output.coeffs()[index],
            use_hint(
                r.coeffs()[index],
                hints.coeffs()[index] as u8,
                Gamma2::QMinusOneOver32,
            )
        );
    }
}

fn representative_inputs(gamma2: Gamma2) -> Vec<i32> {
    let bound = gamma2.value();
    let alpha = gamma2.alpha();
    let mut values = vec![
        -Q,
        -Q + 1,
        -1,
        0,
        1,
        bound - 1,
        bound,
        bound + 1,
        alpha - 1,
        alpha,
        alpha + 1,
        Q / 2 - 1,
        Q / 2,
        Q / 2 + 1,
        Q - bound - 1,
        Q - bound,
        Q - bound + 1,
        Q - 2,
        Q - 1,
        Q,
    ];

    for high in 0..gamma2.high_modulus() {
        let center = high * alpha;
        for offset in [-bound, -bound + 1, -1, 0, 1, bound - 1, bound] {
            values.push(center + offset);
        }
    }

    values.sort_unstable();
    values.dedup();
    values
}
