//! Stable audit entry points for optimized SLH-DSA machine-code recovery.
//!
//! These wrappers are audit-only. They preserve selected secret-bearing call
//! boundaries while allowing LLVM to optimize the underlying hash primitive.

use std::hint::black_box;

use pqc_slh_dsa::{
    address::{Address, AddressType},
    hash::{Sha2TweakableHash, ShakeTweakableHash},
};

fn audit_address() -> Address {
    let mut address = Address::new();
    address.set_layer_address(3);
    address.set_tree_address(0x0102_0304_0506_0708);
    address.set_type_and_clear(AddressType::WotsPrf);
    address.set_key_pair_address(7);
    address.set_chain_address(11);
    address.set_hash_address(13);
    address
}

#[inline(never)]
fn audit_slh_shake_prf() {
    let hash = ShakeTweakableHash::new(32);
    let public_seed = [0x11_u8; 32];
    let secret_seed = [0x22_u8; 32];
    let address = audit_address();
    let mut output = [0_u8; 32];

    hash.prf(
        black_box(&public_seed),
        black_box(&secret_seed),
        black_box(&address),
        black_box(&mut output),
    )
    .expect("SLH-DSA SHAKE PRF audit input must be valid");

    black_box(output);
}

#[inline(never)]
fn audit_slh_shake_prf_msg() {
    let hash = ShakeTweakableHash::new(32);
    let secret_prf = [0x33_u8; 32];
    let optional_randomness = [0x44_u8; 32];
    let message = b"pqc-rs-slh-dsa-s6-machine-code-audit";
    let mut output = [0_u8; 32];

    hash.prf_msg(
        black_box(&secret_prf),
        black_box(&optional_randomness),
        black_box(message),
        black_box(&mut output),
    )
    .expect("SLH-DSA SHAKE PRF_msg audit input must be valid");

    black_box(output);
}

#[inline(never)]
fn audit_slh_sha2_prf() {
    let hash = Sha2TweakableHash::new(32);
    let public_seed = [0x55_u8; 32];
    let secret_seed = [0x66_u8; 32];
    let address = audit_address();
    let mut output = [0_u8; 32];

    hash.prf(
        black_box(&public_seed),
        black_box(&secret_seed),
        black_box(&address),
        black_box(&mut output),
    )
    .expect("SLH-DSA SHA2 PRF audit input must be valid");

    black_box(output);
}

#[inline(never)]
fn audit_slh_sha2_prf_msg() {
    let hash = Sha2TweakableHash::new(32);
    let secret_prf = [0x77_u8; 32];
    let optional_randomness = [0x88_u8; 32];
    let message = b"pqc-rs-slh-dsa-s6-machine-code-audit";
    let mut output = [0_u8; 32];

    hash.prf_msg(
        black_box(&secret_prf),
        black_box(&optional_randomness),
        black_box(message),
        black_box(&mut output),
    )
    .expect("SLH-DSA SHA2 PRF_msg audit input must be valid");

    black_box(output);
}

#[inline(never)]
fn audit_slh_sha2_128_prf_msg() {
    let hash = Sha2TweakableHash::new(16);
    let secret_prf = [0x99_u8; 16];
    let optional_randomness = [0xaa_u8; 16];
    let message = b"pqc-rs-slh-dsa-s6-machine-code-audit";
    let mut output = [0_u8; 16];

    hash.prf_msg(
        black_box(&secret_prf),
        black_box(&optional_randomness),
        black_box(message),
        black_box(&mut output),
    )
    .expect("SLH-DSA SHA2-128 PRF_msg audit input must be valid");

    black_box(output);
}

fn main() {
    audit_slh_shake_prf();
    audit_slh_shake_prf_msg();
    audit_slh_sha2_prf();
    audit_slh_sha2_prf_msg();
    audit_slh_sha2_128_prf_msg();
}
