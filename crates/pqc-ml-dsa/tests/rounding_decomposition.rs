#![cfg(feature = "internal-api")]

use pqc_ml_dsa::constants::Q;
use pqc_ml_dsa::rounding::{decompose, high_bits, low_bits, power2round, Gamma2, D};

#[test]
fn power2round_recombines_representative_inputs() {
    let inputs = [
        0,
        1,
        (1 << (D - 1)) - 1,
        1 << (D - 1),
        (1 << D) - 1,
        1 << D,
        Q - 2,
        Q - 1,
    ];

    for input in inputs {
        let (high, low) = power2round(input);
        assert_eq!((high << D) + low, input);
        assert!(low > -(1 << (D - 1)));
        assert!(low <= 1 << (D - 1));
    }
}

#[test]
fn decomposition_recombines_modulo_q_for_both_gamma2_values() {
    for gamma2 in [Gamma2::QMinusOneOver88, Gamma2::QMinusOneOver32] {
        let alpha = gamma2.alpha();

        for input in representative_inputs(gamma2) {
            let (high, low) = decompose(input, gamma2);
            let recombined = (high * alpha + low).rem_euclid(Q);

            assert_eq!(recombined, input.rem_euclid(Q));
            assert_eq!(high_bits(input, gamma2), high);
            assert_eq!(low_bits(input, gamma2), low);
        }
    }
}

#[test]
fn decomposition_high_bits_are_in_range() {
    for gamma2 in [Gamma2::QMinusOneOver88, Gamma2::QMinusOneOver32] {
        for input in representative_inputs(gamma2) {
            let high = high_bits(input, gamma2);
            assert!((0..gamma2.high_modulus()).contains(&high));
        }
    }
}

#[test]
fn decomposition_low_bits_obey_centered_interval() {
    for gamma2 in [Gamma2::QMinusOneOver88, Gamma2::QMinusOneOver32] {
        let bound = gamma2.value();

        for input in representative_inputs(gamma2) {
            let low = low_bits(input, gamma2);

            // ML-DSA decomposition returns low bits in [-gamma2, gamma2], including the special wrap case.
            assert!(low >= -bound);
            assert!(low <= bound);
        }
    }
}

#[test]
fn decomposition_is_periodic_modulo_q() {
    for gamma2 in [Gamma2::QMinusOneOver88, Gamma2::QMinusOneOver32] {
        for input in representative_inputs(gamma2) {
            assert_eq!(decompose(input, gamma2), decompose(input + Q, gamma2));
            assert_eq!(decompose(input, gamma2), decompose(input - Q, gamma2));
        }
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
        Q - alpha - 1,
        Q - alpha,
        Q - alpha + 1,
        Q - bound - 1,
        Q - bound,
        Q - bound + 1,
        Q - 2,
        Q - 1,
        Q,
    ];

    for high in 0..gamma2.high_modulus() {
        let center = high * alpha;
        for offset in [
            -bound - 1,
            -bound,
            -bound + 1,
            -1,
            0,
            1,
            bound - 1,
            bound,
            bound + 1,
        ] {
            values.push(center + offset);
        }
    }

    values.sort_unstable();
    values.dedup();
    values
}
