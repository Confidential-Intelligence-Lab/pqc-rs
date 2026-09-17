//! Linux Valgrind secret-taint audit for SLH-DSA secret-bearing primitives.

use std::{env, hint::black_box};

use pqc_slh_dsa::{
    address::{Address, AddressType},
    hash::{Sha2TweakableHash, ShakeTweakableHash},
};

#[cfg(all(
    target_os = "linux",
    feature = "valgrind-secret-taint",
    pqc_valgrind_available
))]
#[link(name = "pqc_valgrind_secret", kind = "static")]
unsafe extern "C" {
    fn pqc_valgrind_make_secret(ptr: *mut core::ffi::c_void, len: usize);
    fn pqc_valgrind_make_public(ptr: *mut core::ffi::c_void, len: usize);
    fn pqc_valgrind_running() -> core::ffi::c_int;
}

#[cfg(all(
    target_os = "linux",
    feature = "valgrind-secret-taint",
    pqc_valgrind_available
))]
fn make_secret(bytes: &mut [u8]) {
    unsafe {
        pqc_valgrind_make_secret(bytes.as_mut_ptr().cast(), bytes.len());
    }
}

#[cfg(not(all(
    target_os = "linux",
    feature = "valgrind-secret-taint",
    pqc_valgrind_available
)))]
fn make_secret(_bytes: &mut [u8]) {}

#[cfg(all(
    target_os = "linux",
    feature = "valgrind-secret-taint",
    pqc_valgrind_available
))]
fn make_public(bytes: &mut [u8]) {
    unsafe {
        pqc_valgrind_make_public(bytes.as_mut_ptr().cast(), bytes.len());
    }
}

#[cfg(not(all(
    target_os = "linux",
    feature = "valgrind-secret-taint",
    pqc_valgrind_available
)))]
fn make_public(_bytes: &mut [u8]) {}

#[cfg(all(
    target_os = "linux",
    feature = "valgrind-secret-taint",
    pqc_valgrind_available
))]
fn running_on_valgrind() -> bool {
    unsafe { pqc_valgrind_running() != 0 }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("SLH-DSA S6 secret-taint audit failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = env::args().collect();

    if arguments.len() != 2 {
        return Err(format!(
            "usage: {} <positive-control|shake-prf|shake-prf-msg|sha2-prf|sha2-prf-msg-32|sha2-prf-msg-16>",
            arguments
                .first()
                .map(String::as_str)
                .unwrap_or("slhdsa-s6-secret-taint"),
        ));
    }

    #[cfg(all(target_os = "linux", not(feature = "valgrind-secret-taint")))]
    return Err(
        "Linux secret-taint execution requires --features valgrind-secret-taint".to_owned(),
    );

    #[cfg(all(
        target_os = "linux",
        feature = "valgrind-secret-taint",
        pqc_valgrind_available
    ))]
    #[cfg(all(
        target_os = "linux",
        feature = "valgrind-secret-taint",
        not(pqc_valgrind_available)
    ))]
    return Err("Linux secret-taint execution requires Valgrind development headers".to_owned());

    #[cfg(all(
        target_os = "linux",
        feature = "valgrind-secret-taint",
        pqc_valgrind_available
    ))]
    if !running_on_valgrind() {
        return Err("Linux secret-taint audit must run under Valgrind".to_owned());
    }

    match arguments[1].as_str() {
        "positive-control" => positive_control(),
        "shake-prf" => audit_prf(true, 32),
        "shake-prf-msg" => audit_prf_msg(true, 32),
        "sha2-prf" => audit_prf(false, 32),
        "sha2-prf-msg-32" => audit_prf_msg(false, 32),
        "sha2-prf-msg-16" => audit_prf_msg(false, 16),
        operation => Err(format!("unsupported operation {operation}")),
    }
}

fn positive_control() -> Result<(), String> {
    let mut secret = [0x5a_u8; 1];

    make_secret(&mut secret);

    // Intentional secret-dependent branch. Valgrind MUST report this.
    if black_box(secret[0]) == 0x5a {
        black_box(1_u8);
    } else {
        black_box(0_u8);
    }

    make_public(&mut secret);

    Ok(())
}

fn audit_prf(shake: bool, n: usize) -> Result<(), String> {
    let public_seed = vec![0x11_u8; n];
    let mut secret_seed = vec![0x22_u8; n];
    let address = audit_address();
    let mut output = vec![0_u8; n];

    make_secret(&mut secret_seed);

    let result = if shake {
        ShakeTweakableHash::new(n).prf(
            black_box(&public_seed),
            black_box(&secret_seed),
            black_box(&address),
            black_box(&mut output),
        )
    } else {
        Sha2TweakableHash::new(n).prf(
            black_box(&public_seed),
            black_box(&secret_seed),
            black_box(&address),
            black_box(&mut output),
        )
    };

    make_public(&mut secret_seed);

    result.map_err(|error| format!("PRF failed: {error:?}"))?;
    black_box(output);

    Ok(())
}

fn audit_prf_msg(shake: bool, n: usize) -> Result<(), String> {
    let mut secret_prf = vec![0x33_u8; n];
    let mut optional_randomness = vec![0x44_u8; n];
    let message = b"pqc-rs-slh-dsa-s6-secret-taint";
    let mut output = vec![0_u8; n];

    make_secret(&mut secret_prf);
    make_secret(&mut optional_randomness);

    let result = if shake {
        ShakeTweakableHash::new(n).prf_msg(
            black_box(&secret_prf),
            black_box(&optional_randomness),
            black_box(message),
            black_box(&mut output),
        )
    } else {
        Sha2TweakableHash::new(n).prf_msg(
            black_box(&secret_prf),
            black_box(&optional_randomness),
            black_box(message),
            black_box(&mut output),
        )
    };

    make_public(&mut secret_prf);
    make_public(&mut optional_randomness);

    result.map_err(|error| format!("PRF_msg failed: {error:?}"))?;
    black_box(output);

    Ok(())
}

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
