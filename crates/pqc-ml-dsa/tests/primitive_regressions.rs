use pqc_ml_dsa::challenge::{challenge_weight, is_sparse_signed, sample_in_ball};
use pqc_ml_dsa::constants::Q;
use pqc_ml_dsa::hint::{make_hint, use_hint};
use pqc_ml_dsa::rounding::{decompose, high_bits, low_bits, power2round, Gamma2, D};
use pqc_ml_dsa::sample::sample_eta_poly;

#[test]
fn exhaustive_power2round_recombination_over_one_radix() {
    for value in 0..(1_i32 << D) {
        let (high, low) = power2round(value);
        assert_eq!((high << D) + low, value);
        assert!(low > -(1 << (D - 1)));
        assert!(low <= 1 << (D - 1));
    }
}

#[test]
fn decomposition_matches_projection_over_representative_domain() {
    for gamma2 in [Gamma2::QMinusOneOver88, Gamma2::QMinusOneOver32] {
        for value in (0..Q).step_by(257) {
            let (high, low) = decompose(value, gamma2);
            assert_eq!(high_bits(value, gamma2), high);
            assert_eq!(low_bits(value, gamma2), low);
            assert_eq!((high * gamma2.alpha() + low).rem_euclid(Q), value);
            assert!((0..gamma2.high_modulus()).contains(&high));
            assert!((-gamma2.value()..=gamma2.value()).contains(&low));
        }
    }
}

#[test]
fn hint_application_is_one_cyclic_step() {
    for gamma2 in [Gamma2::QMinusOneOver88, Gamma2::QMinusOneOver32] {
        let modulus = gamma2.high_modulus();
        for value in (0..Q).step_by(509) {
            let base = high_bits(value, gamma2);
            let adjusted = use_hint(value, 1, gamma2);
            let delta = (adjusted - base).rem_euclid(modulus);
            assert!(delta == 1 || delta == modulus - 1);
        }
    }
}

#[test]
fn generated_hints_are_binary() {
    for gamma2 in [Gamma2::QMinusOneOver88, Gamma2::QMinusOneOver32] {
        let bound = gamma2.value();
        for value in (0..Q).step_by(1021) {
            for adjustment in [-bound, -1, 0, 1, bound] {
                assert!(make_hint(adjustment, value, gamma2) <= 1);
            }
        }
    }
}

#[test]
fn sampling_and_challenge_properties_hold() {
    for eta in [2, 4] {
        for nonce in [0_u16, 1, 255, 256, u16::MAX] {
            let poly = sample_eta_poly(&[nonce as u8; 64], nonce, eta).unwrap();
            assert!(poly
                .coeffs()
                .iter()
                .all(|value| (-eta..=eta).contains(value)));
        }
    }

    for tau in [39, 49, 60] {
        let challenge = sample_in_ball(&[tau as u8; 32], tau).unwrap();
        assert_eq!(challenge_weight(&challenge), tau);
        assert!(is_sparse_signed(&challenge));
    }
}
