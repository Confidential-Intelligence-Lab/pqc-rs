#![cfg(feature = "internal-api")]

use pqc_ml_dsa::constants::N;
use pqc_ml_dsa::encoding::{
    decode_eta, decode_t0, decode_t1, decode_w1, decode_z, encode_eta, encode_t0, encode_t1,
    encode_w1, encode_z, EncodingError,
};
use pqc_ml_dsa::poly::Poly;
use pqc_ml_dsa::rounding::{Gamma2, D};

#[test]
fn coefficient_encodings_round_trip() {
    for (eta, min, max) in [(2, -2, 2), (4, -4, 4)] {
        let p = patterned(min, max);
        assert!(decode_eta(&encode_eta(&p, eta).unwrap(), eta).unwrap() == p);
    }

    let t1 = patterned(0, 1023);
    assert!(decode_t1(&encode_t1(&t1).unwrap()).unwrap() == t1);

    let bound = 1_i32 << (D - 1);
    let t0 = patterned(-bound + 1, bound);
    assert!(decode_t0(&encode_t0(&t0).unwrap()).unwrap() == t0);

    for gamma1 in [1 << 17, 1 << 19] {
        let z = patterned(-gamma1 + 1, gamma1);
        assert!(decode_z(&encode_z(&z, gamma1).unwrap(), gamma1).unwrap() == z);
    }

    for (gamma2, max) in [(Gamma2::QMinusOneOver88, 43), (Gamma2::QMinusOneOver32, 15)] {
        let w1 = patterned(0, max);
        assert!(decode_w1(&encode_w1(&w1, gamma2).unwrap(), gamma2).unwrap() == w1);
    }
}

#[test]
fn strict_eta_decoder_rejects_unused_code_points() {
    let mut encoded = vec![0_u8; 96];
    encoded[0] = 0b0000_0111;
    assert!(matches!(
        decode_eta(&encoded, 2),
        Err(EncodingError::NonCanonicalCoefficient)
    ));
}

#[test]
fn encoders_reject_out_of_range_values() {
    let mut coefficients = [0_i32; N];
    coefficients[0] = 3;
    assert!(matches!(
        encode_eta(&Poly::from_coeffs(coefficients), 2),
        Err(EncodingError::NonCanonicalCoefficient)
    ));

    coefficients[0] = 1024;
    assert!(matches!(
        encode_t1(&Poly::from_coeffs(coefficients)),
        Err(EncodingError::NonCanonicalCoefficient)
    ));
}

fn patterned(minimum: i32, maximum: i32) -> Poly {
    let width = maximum - minimum + 1;
    let mut coefficients = [0_i32; N];
    for (index, coefficient) in coefficients.iter_mut().enumerate() {
        *coefficient = minimum + (index as i32 * 17 + 3).rem_euclid(width);
    }
    Poly::from_coeffs(coefficients)
}
