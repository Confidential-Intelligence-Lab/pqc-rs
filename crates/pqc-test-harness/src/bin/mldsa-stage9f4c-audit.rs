//! Stable audit entry points for optimized ML-DSA machine-code recovery.
//!
//! These wrappers are audit-only. They prevent selected call boundaries from
//! disappearing while still allowing LLVM to optimize the called primitive.

use std::hint::black_box;

use pqc_ml_dsa::{
    challenge::sample_in_ball_bytes,
    encoding::{decode_t0, decode_z, encode_t0, encode_z},
    keygen::keygen_internal,
    params::MlDsaParameterSet,
    poly::Poly,
    rounding::{high_bits, low_bits, power2round, Gamma2},
    sample::sample_eta_poly,
    signature::sign_internal,
    signing_core::multiply_challenge,
    verification::verify_internal,
};

#[inline(never)]
fn audit_multiply_challenge() {
    let challenge = sample_in_ball_bytes(&[0x42; 32], 39).unwrap();
    let polynomial = Poly::from_coeffs([7_i32; 256]);
    black_box(multiply_challenge(
        black_box(&challenge),
        black_box(&polynomial),
    ));
}

#[inline(never)]
fn audit_sample_eta() {
    let polynomial = sample_eta_poly(black_box(&[0x24; 64]), black_box(7), black_box(2))
        .expect("audit eta sampling must succeed");

    black_box(polynomial);
}

#[inline(never)]
fn audit_sample_ball() {
    let challenge = sample_in_ball_bytes(black_box(&[0x33; 32]), black_box(39))
        .expect("audit challenge sampling must succeed");

    black_box(challenge);
}

#[inline(never)]
fn audit_rounding() {
    let values = [0_i32, 1, 4095, 4096, 8_380_416, 8_380_000];

    for value in values {
        black_box(power2round(black_box(value)));
        black_box(high_bits(
            black_box(value),
            black_box(Gamma2::QMinusOneOver88),
        ));
        black_box(low_bits(
            black_box(value),
            black_box(Gamma2::QMinusOneOver88),
        ));
    }
}

#[inline(never)]
fn audit_encoding() {
    let polynomial = Poly::from_coeffs([3_i32; 256]);

    let encoded_t0 = encode_t0(black_box(&polynomial)).unwrap();
    black_box(decode_t0(black_box(&encoded_t0)).unwrap());

    let encoded_z = encode_z(black_box(&polynomial), black_box(1 << 17)).unwrap();
    black_box(decode_z(black_box(&encoded_z), black_box(1 << 17)).unwrap());
}

#[inline(never)]
fn audit_sign_verify() {
    let parameter_set = MlDsaParameterSet::MlDsa44;
    let key_pair = keygen_internal(parameter_set, &[0x55; 32]).unwrap();
    let message = b"stage9f4c";
    let context = b"audit";
    let randomness = [0x66; 32];

    let signature = sign_internal(
        parameter_set,
        black_box(key_pair.private_key()),
        black_box(message),
        black_box(context),
        black_box(&randomness),
    )
    .unwrap();

    black_box(
        verify_internal(
            parameter_set,
            black_box(key_pair.public_key()),
            black_box(message),
            black_box(context),
            black_box(&signature),
        )
        .unwrap(),
    );
}

fn main() {
    audit_multiply_challenge();
    audit_sample_eta();
    audit_sample_ball();
    audit_rounding();
    audit_encoding();
    audit_sign_verify();
}
