// SPDX-License-Identifier: MIT

//! HAETAE 1.2.0 secret-key decoding against authenticated C fixtures.

use pqc_haetae::keygen_loop::generate_accepted_state;
use pqc_haetae::packing::{
    pack_sk, public_key_bytes, secret_key_bytes, unpack_secret_key, POLY_ETA_PACKED_BYTES,
};
use pqc_haetae::params::ParameterSet;
use std::path::PathBuf;

const CASES: usize = 5;
const MAX_ATTEMPTS: usize = 10_000;

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.strip_prefix(name)
        .and_then(|rest| rest.strip_prefix('='))
        .unwrap_or_else(|| panic!("missing field {name}"))
}

fn fixture(mode_number: u8) -> Vec<String> {
    let root = PathBuf::from(
        std::env::var_os("HAETAE_KEYGEN_KEYPAIR_PARITY_DIR")
            .expect("HAETAE_KEYGEN_KEYPAIR_PARITY_DIR required"),
    );

    std::fs::read_to_string(root.join(format!("keypair_mode{mode_number}.txt")))
        .expect("authenticated keypair fixture")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn check<const K: usize, const M: usize>(mode_number: u8, mode: ParameterSet) {
    let lines = fixture(mode_number);

    assert_eq!(
        lines[0],
        format!("PUBLICKEYBYTES={}", public_key_bytes(mode))
    );
    assert_eq!(
        lines[1],
        format!("SECRETKEYBYTES={}", secret_key_bytes(mode))
    );
    assert_eq!(lines.len(), 2 + CASES * 5);

    let mut compared_coefficients = 0_usize;
    let mut compared_bytes = 0_usize;

    for case in 0..CASES {
        let block = &lines[2 + case * 5..2 + (case + 1) * 5];

        assert_eq!(block[0], format!("CASE={case}"));
        assert_eq!(block[4], format!("END_CASE={case}"));

        let seed: [u8; 32] = decode_hex(field(&block[1], "SEED"))
            .try_into()
            .expect("32-byte seed");

        let pk = decode_hex(field(&block[2], "PK"));
        let sk = decode_hex(field(&block[3], "SK"));

        assert_eq!(pk.len(), public_key_bytes(mode));
        assert_eq!(sk.len(), secret_key_bytes(mode));
        assert_eq!(&sk[..pk.len()], pk.as_slice());

        let decoded = unpack_secret_key::<K, M>(&sk, mode).expect("valid reference secret key");

        assert_eq!(decoded.public_key, pk);

        let state = generate_accepted_state::<K, M>(&seed, mode, MAX_ATTEMPTS)
            .expect("reproduce authenticated keygen state");

        for index in 0..M {
            assert_eq!(
                decoded.s0.as_slice()[index],
                state.s1.as_slice()[index],
                "MODE={mode_number} CASE={case} S0[{index}]"
            );
            compared_coefficients += 256;
        }

        for index in 0..K {
            assert_eq!(
                decoded.s1.as_slice()[index],
                state.s2.as_slice()[index],
                "MODE={mode_number} CASE={case} S1[{index}]"
            );
            compared_coefficients += 256;
        }

        assert_eq!(
            decoded.key, state.key,
            "MODE={mode_number} CASE={case} signing key"
        );

        let reencoded = pack_sk(
            &decoded.public_key,
            &decoded.s0,
            &decoded.s1,
            &decoded.key,
            mode,
        )
        .expect("reencode decoded secret key");

        assert_eq!(reencoded, sk, "MODE={mode_number} CASE={case} round-trip");

        compared_bytes += sk.len();

        // Reject both truncated and oversized serialized keys.
        assert!(unpack_secret_key::<K, M>(&sk[..sk.len() - 1], mode).is_err());

        let mut oversized = sk.clone();
        oversized.push(0);
        assert!(unpack_secret_key::<K, M>(&oversized, mode).is_err());

        // The first secret polynomial starts immediately after the PK.
        // Setting its first 2-bit symbol to 3 produces a noncanonical
        // eta encoding (valid symbols are 0, 1, and 2).
        let mut malformed_eta = sk.clone();
        let eta_offset = public_key_bytes(mode);
        malformed_eta[eta_offset] = (malformed_eta[eta_offset] & !0b11) | 0b11;

        assert!(
            unpack_secret_key::<K, M>(&malformed_eta, mode).is_err(),
            "MODE={mode_number} CASE={case} noncanonical eta accepted"
        );

        // For modes 2/3, the first s1 polynomial uses 3-bit
        // 2-eta encoding. Symbol 7 is noncanonical (0..=4 valid).
        if mode_number != 5 {
            let mut malformed_two_eta = sk.clone();
            let offset = public_key_bytes(mode) + M * POLY_ETA_PACKED_BYTES;

            malformed_two_eta[offset] = (malformed_two_eta[offset] & !0b111) | 0b111;

            assert!(
                unpack_secret_key::<K, M>(&malformed_two_eta, mode).is_err(),
                "MODE={mode_number} CASE={case} noncanonical 2-eta accepted"
            );
        }

        println!(
            "MODE={mode_number} CASE={case} \
             DECODE=PASS COEFFICIENTS=PASS \
             REENCODE=PASS NEGATIVE=PASS"
        );
    }

    println!(
        "MODE={mode_number} KEYS={CASES} \
         EXACT_COEFFICIENTS={compared_coefficients} \
         EXACT_SECRET_KEY_BYTES={compared_bytes} STATUS=PASS"
    );
}

#[test]
fn decoder_reference_mode2() {
    check::<2, 3>(2, ParameterSet::Haetae2);
}

#[test]
fn decoder_reference_mode3() {
    check::<3, 5>(3, ParameterSet::Haetae3);
}

#[test]
fn decoder_reference_mode5() {
    check::<4, 6>(5, ParameterSet::Haetae5);
}

#[test]
fn decoder_rejects_parameter_dimension_mismatch() {
    for (mode_number, mode) in [
        (2, ParameterSet::Haetae2),
        (3, ParameterSet::Haetae3),
        (5, ParameterSet::Haetae5),
    ] {
        let lines = fixture(mode_number);
        let sk = decode_hex(field(&lines[5], "SK"));

        assert!(
            unpack_secret_key::<1, 1>(&sk, mode).is_err(),
            "MODE={mode_number} wrong dimensions accepted"
        );
    }
}
