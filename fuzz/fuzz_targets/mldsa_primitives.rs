#![no_main]

use libfuzzer_sys::fuzz_target;
use pqc_ml_dsa::challenge::{challenge_weight, is_sparse_signed, sample_in_ball};
use pqc_ml_dsa::constants::Q;
use pqc_ml_dsa::hint::{make_hint, use_hint};
use pqc_ml_dsa::rounding::{decompose, high_bits, low_bits, power2round, Gamma2, D};
use pqc_ml_dsa::sample::sample_eta_poly;

fuzz_target!(|data: &[u8]| {
    if data.len() < 104 {
        return;
    }

    let mut seed64 = [0_u8; 64];
    seed64.copy_from_slice(&data[..64]);
    let mut seed32 = [0_u8; 32];
    seed32.copy_from_slice(&data[64..96]);

    let nonce = u16::from_le_bytes([data[96], data[97]]);
    let eta = if data[98] & 1 == 0 { 2 } else { 4 };
    let tau = [39, 49, 60][usize::from(data[99] % 3)];

    let poly = sample_eta_poly(&seed64, nonce, eta).unwrap();
    assert!(poly.coeffs().iter().all(|value| (-eta..=eta).contains(value)));

    let challenge = sample_in_ball(&seed32, tau).unwrap();
    assert_eq!(challenge_weight(&challenge), tau);
    assert!(is_sparse_signed(&challenge));

    let raw = i32::from_le_bytes([data[100], data[101], data[102], data[103]]);
    let value = raw.rem_euclid(Q);
    let (p1, p0) = power2round(value);
    assert_eq!((p1 << D) + p0, value);

    for gamma2 in [Gamma2::QMinusOneOver88, Gamma2::QMinusOneOver32] {
        let (high, low) = decompose(value, gamma2);
        assert_eq!(high_bits(value, gamma2), high);
        assert_eq!(low_bits(value, gamma2), low);
        assert_eq!((high * gamma2.alpha() + low).rem_euclid(Q), value);
        let hint = make_hint(low, value, gamma2);
        assert!(hint <= 1);
        let adjusted = use_hint(value, hint, gamma2);
        assert!((0..gamma2.high_modulus()).contains(&adjusted));
    }
});
