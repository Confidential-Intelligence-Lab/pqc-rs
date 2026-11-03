// SPDX-License-Identifier: MIT
//! Deterministic secret-key parity against HAETAE 1.2.0 C.

use pqc_haetae::keygen_loop::generate_accepted_state;
use pqc_haetae::packing::{pack_sk, pack_vk, public_key_bytes, secret_key_bytes};
use pqc_haetae::params::ParameterSet;
use std::path::PathBuf;

const CASES: usize = 5;
const MAX_ATTEMPTS: usize = 10_000;

fn fixture_path(mode: u8) -> PathBuf {
    let root = std::env::var_os("HAETAE_KEYGEN_KEYPAIR_PARITY_DIR")
        .expect("HAETAE_KEYGEN_KEYPAIR_PARITY_DIR must be set");
    PathBuf::from(root).join(format!("keypair_mode{mode}.txt"))
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "odd-length fixture hex");

    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("invalid fixture hex"))
        .collect()
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.strip_prefix(name)
        .and_then(|rest| rest.strip_prefix('='))
        .unwrap_or_else(|| panic!("expected {name} field"))
}

fn expected_seed(case: usize) -> [u8; 32] {
    std::array::from_fn(|i| match case {
        0 => 0,
        1 => 255,
        2 => i as u8,
        3 => 255 - i as u8,
        4 => (i as u8).wrapping_mul(17).wrapping_add(11),
        _ => panic!("invalid fixture case"),
    })
}

fn section(offset: usize, pk_len: usize, m: usize, mode: u8) -> &'static str {
    let s1_end = pk_len + m * 64;
    let s2_end = if mode == 5 {
        s1_end + 4 * 64
    } else {
        s1_end + (if mode == 2 { 2 } else { 3 }) * 96
    };

    if offset < pk_len {
        "PUBLIC_KEY_PREFIX"
    } else if offset < s1_end {
        "S1"
    } else if offset < s2_end {
        "S2"
    } else {
        "KEY"
    }
}

fn check<const K: usize, const M: usize>(mode_number: u8, mode: ParameterSet) {
    let fixture = std::fs::read_to_string(fixture_path(mode_number))
        .expect("C keypair fixture must be readable");

    let lines: Vec<&str> = fixture.lines().collect();

    assert_eq!(
        lines[0],
        format!("PUBLICKEYBYTES={}", public_key_bytes(mode))
    );
    assert_eq!(
        lines[1],
        format!("SECRETKEYBYTES={}", secret_key_bytes(mode))
    );
    assert_eq!(lines.len(), 2 + CASES * 5);

    let mut compared_bytes = 0;

    for case in 0..CASES {
        let block = &lines[2 + case * 5..2 + (case + 1) * 5];

        assert_eq!(block[0], format!("CASE={case}"));
        assert_eq!(block[4], format!("END_CASE={case}"));

        let seed: [u8; 32] = decode_hex(field(block[1], "SEED"))
            .try_into()
            .expect("reference seed must be 32 bytes");

        assert_eq!(seed, expected_seed(case));

        let expected_pk = decode_hex(field(block[2], "PK"));
        let expected_sk = decode_hex(field(block[3], "SK"));

        assert_eq!(expected_pk.len(), public_key_bytes(mode));
        assert_eq!(expected_sk.len(), secret_key_bytes(mode));
        assert_eq!(&expected_sk[..expected_pk.len()], expected_pk.as_slice());

        let state =
            generate_accepted_state::<K, M>(&seed, mode, MAX_ATTEMPTS).unwrap_or_else(|error| {
                panic!(
                    "MODE={mode_number} CASE={case} \
                         Rust keygen failed: {error:?}"
                )
            });

        let actual_pk = pack_vk(&state.rhoprime, &state.public_b, mode).unwrap_or_else(|error| {
            panic!(
                "MODE={mode_number} CASE={case} \
                 Rust public-key packing failed: {error:?}"
            )
        });

        assert_eq!(
            actual_pk, expected_pk,
            "MODE={mode_number} CASE={case} public-key prerequisite"
        );

        let actual_sk =
            pack_sk(&actual_pk, &state.s1, &state.s2, &state.key, mode).unwrap_or_else(|error| {
                panic!(
                    "MODE={mode_number} CASE={case} \
                 Rust secret-key packing failed: {error:?}"
                )
            });

        assert_eq!(actual_sk.len(), expected_sk.len());

        if let Some(offset) = actual_sk
            .iter()
            .zip(&expected_sk)
            .position(|(actual, expected)| actual != expected)
        {
            panic!(
                "SECRET_KEY_PARITY_FAIL \
                 MODE={mode_number} CASE={case} \
                 SECTION={} OFFSET={offset} \
                 RUST={:02x} C={:02x}",
                section(offset, expected_pk.len(), M, mode_number),
                actual_sk[offset],
                expected_sk[offset],
            );
        }

        compared_bytes += actual_sk.len();

        println!(
            "MODE={mode_number} CASE={case} \
             SK_BYTES={} ATTEMPTS={} NONCE={} STATUS=PASS",
            actual_sk.len(),
            state.attempts,
            state.sampling_nonce
        );
    }

    println!(
        "MODE={mode_number} KEYPAIRS={CASES} \
         EXACT_SECRET_KEY_BYTES={compared_bytes} STATUS=PASS"
    );
}

#[test]
fn reference_secret_keys_mode2() {
    check::<2, 3>(2, ParameterSet::Haetae2);
}

#[test]
fn reference_secret_keys_mode3() {
    check::<3, 5>(3, ParameterSet::Haetae3);
}

#[test]
fn reference_secret_keys_mode5() {
    check::<4, 6>(5, ParameterSet::Haetae5);
}
