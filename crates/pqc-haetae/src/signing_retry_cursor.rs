//! Authenticated HAETAE signing initialization and retry-cursor parity.
//!
//! Test-only: no production signing API or algorithm changes.

use crate::hyperball::sample_hyperball;
use crate::params::ParameterSet;
use crate::signature_packing::{pack_signature, unpack_signature};
use crate::signing::sign_deterministic;
use crate::signing_challenge_prepare::{
    prepare_signing_challenge, prepare_signing_challenge_complete,
};
use crate::signing_init::derive_signing_initialization;
use crate::signing_response::evaluate_signing_response;
use crate::signing_response::evaluate_signing_response_complete;
use crate::signing_response::tests::reference_response_thresholds;
use crate::signing_signature_assembly::assemble_accepted_signature;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex UTF-8");
            u8::from_str_radix(text, 16).expect("hex byte")
        })
        .collect()
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    let (actual, value) = line.split_once('=').expect("fixture field");
    assert_eq!(actual, name);
    value
}

fn keypairs(mode_number: u8) -> Vec<BTreeMap<String, String>> {
    let root = PathBuf::from(
        std::env::var("HAETAE_KEYGEN_KEYPAIR_PARITY_DIR")
            .expect("HAETAE_KEYGEN_KEYPAIR_PARITY_DIR required"),
    );

    let text = fs::read_to_string(root.join(format!("keypair_mode{mode_number}.txt")))
        .expect("keypair fixture");

    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 27);

    let mut records = Vec::new();

    for case in 0..5 {
        let block = &lines[2 + case * 5..2 + (case + 1) * 5];

        assert_eq!(field(block[0], "CASE"), case.to_string());
        assert_eq!(field(block[4], "END_CASE"), case.to_string());

        let mut record = BTreeMap::new();

        for line in &block[1..4] {
            let (key, value) = line.split_once('=').expect("keypair field");
            assert!(record.insert(key.to_owned(), value.to_owned()).is_none());
        }

        records.push(record);
    }

    records
}

struct AcceptedAttemptInputs<'a> {
    mode_number: u8,
    mode: ParameterSet,
    pk: &'a [u8],
    sk: &'a [u8],
    mu: &'a [u8; 64],
    b: u8,
    y1: &'a [[i32; crate::params::N]],
    y2: &'a [[i32; crate::params::N]],
    thresholds: (u64, u64),
}

fn assemble_accepted_attempt<const K: usize, const L: usize, const M: usize>(
    inputs: &AcceptedAttemptInputs<'_>,
) -> Vec<u8> {
    let prepared = prepare_signing_challenge_complete::<K, L>(
        inputs.mode_number,
        inputs.mode,
        inputs.pk,
        inputs.mu,
        inputs.y1,
        inputs.y2,
    );

    let response = evaluate_signing_response_complete::<K, L, M>(
        inputs.sk,
        inputs.mode,
        &prepared.challenge,
        inputs.b,
        inputs.y1,
        inputs.y2,
        inputs.thresholds,
    );

    assert_eq!(response.reject1 | response.reject2, 0);

    assemble_accepted_signature::<K, L>(inputs.mode, &prepared, &response)
        .expect("accepted signature packing")
}

fn run(mode_number: u8, mode: ParameterSet) {
    let root = PathBuf::from(
        std::env::var("HAETAE_SIGNING_RETRY_PARITY_DIR")
            .expect("HAETAE_SIGNING_RETRY_PARITY_DIR required"),
    );

    let text = fs::read_to_string(root.join(format!("retry_mode{mode_number}.txt")))
        .expect("retry fixture");

    let lines: Vec<&str> = text.lines().collect();

    assert_eq!(lines[0], "FORMAT=HAETAE_RUST_SIGNING_RETRY_V1");
    assert_eq!(field(lines[1], "MODE"), mode_number.to_string());
    assert_eq!(field(lines[2], "CASES"), "5");

    let keys = keypairs(mode_number);
    let thresholds = reference_response_thresholds(mode_number);

    let mut cursor = 3_usize;
    let mut total_attempts = 0_usize;
    let mut total_rejections = 0_usize;

    for (case, key) in keys.iter().enumerate() {
        assert_eq!(field(lines[cursor], "CASE"), case.to_string());
        cursor += 1;

        let seed = decode_hex(field(lines[cursor], "SEED"));
        cursor += 1;

        let pk = decode_hex(field(lines[cursor], "PK"));
        cursor += 1;

        let rnd = decode_hex(field(lines[cursor], "RND"));
        cursor += 1;

        let message = decode_hex(field(lines[cursor], "MESSAGE"));
        cursor += 1;

        let pre = decode_hex(field(lines[cursor], "PRE"));
        cursor += 1;

        let expected_mu = decode_hex(field(lines[cursor], "MU"));
        cursor += 1;

        let expected_seedbuf = decode_hex(field(lines[cursor], "SEEDBUF"));
        cursor += 1;

        let attempts: usize = field(lines[cursor], "ATTEMPTS")
            .parse()
            .expect("attempt count");
        cursor += 1;

        assert!(!attempts.eq(&0));

        assert_eq!(seed, decode_hex(&key["SEED"]));
        assert_eq!(pk, decode_hex(&key["PK"]));

        let sk = decode_hex(&key["SK"]);

        assert_eq!(sk.len(), mode.parameters().secret_key_bytes);
        assert_eq!(pk.len(), mode.parameters().public_key_bytes);
        assert_eq!(&sk[..pk.len()], pk.as_slice());

        assert_eq!(rnd.len(), 32);
        assert_eq!(expected_mu.len(), 64);
        assert_eq!(expected_seedbuf.len(), 64);

        assert!(!pre.is_empty());
        assert_eq!(usize::from(pre[0]), pre.len() - 1);
        let context = &pre[1..];

        let randomness: [u8; 32] = rnd.try_into().expect("32-byte rnd");

        let init = derive_signing_initialization(&sk, &message, context, &randomness, mode)
            .expect("signing initialization");

        assert_eq!(
            init.mu.as_slice(),
            expected_mu.as_slice(),
            "MU mismatch MODE={mode_number} CASE={case}"
        );

        assert_eq!(
            init.signing_seed.as_slice(),
            expected_seedbuf.as_slice(),
            "SEEDBUF mismatch MODE={mode_number} CASE={case}"
        );

        let mut nonce = 0_u16;
        let mut accepted_signature: Option<Vec<u8>> = None;

        for attempt in 0..attempts {
            assert_eq!(field(lines[cursor], "ATTEMPT"), attempt.to_string());
            cursor += 1;

            let nonce_in: u16 = field(lines[cursor], "NONCE_IN").parse().expect("nonce in");
            cursor += 1;

            let nonce_out: u16 = field(lines[cursor], "NONCE_OUT")
                .parse()
                .expect("nonce out");
            cursor += 1;

            let expected_b: u8 = field(lines[cursor], "B").parse().expect("selector");
            cursor += 1;

            assert_eq!(
                nonce, nonce_in,
                "NONCE_IN mismatch MODE={mode_number} CASE={case} ATTEMPT={attempt}"
            );

            let actual =
                sample_hyperball(mode_number, &init.signing_seed, nonce).expect("hyperball sample");

            assert_eq!(
                actual.next_nonce, nonce_out,
                "NONCE_OUT mismatch MODE={mode_number} CASE={case} ATTEMPT={attempt}"
            );

            assert_eq!(
                actual.b, expected_b,
                "B mismatch MODE={mode_number} CASE={case} ATTEMPT={attempt}"
            );

            nonce = actual.next_nonce;

            let expected_challenge: Vec<i32> = field(lines[cursor], "CHALLENGE")
                .split(',')
                .map(|value| value.parse::<i32>().expect("challenge coefficient"))
                .collect();
            cursor += 1;

            assert_eq!(expected_challenge.len(), 256);

            let actual_challenge = match mode_number {
                2 => prepare_signing_challenge::<2, 4>(
                    mode_number,
                    mode,
                    &pk,
                    &init.mu,
                    &actual.y1,
                    &actual.y2,
                ),
                3 => prepare_signing_challenge::<3, 6>(
                    mode_number,
                    mode,
                    &pk,
                    &init.mu,
                    &actual.y1,
                    &actual.y2,
                ),
                5 => prepare_signing_challenge::<4, 7>(
                    mode_number,
                    mode,
                    &pk,
                    &init.mu,
                    &actual.y1,
                    &actual.y2,
                ),
                _ => unreachable!(),
            };

            assert_eq!(
                actual_challenge.coeffs.as_slice(),
                expected_challenge.as_slice(),
                "CHALLENGE mismatch MODE={mode_number} CASE={case} ATTEMPT={attempt}"
            );

            let expected_norm_z: u64 = field(lines[cursor], "NORM_Z").parse().expect("norm z");
            cursor += 1;

            let expected_norm_tmp: u64 = field(lines[cursor], "NORM_2Z_MINUS_Y")
                .parse()
                .expect("temporary norm");
            cursor += 1;

            let expected_reject1: u64 = field(lines[cursor], "REJECT1").parse().expect("reject1");
            cursor += 1;

            let expected_reject2: u64 = field(lines[cursor], "REJECT2").parse().expect("reject2");
            cursor += 1;

            let expected_result = field(lines[cursor], "RESULT");
            cursor += 1;

            let decision = match mode_number {
                2 => evaluate_signing_response::<2, 4, 3>(
                    &sk,
                    mode,
                    &actual_challenge,
                    actual.b,
                    &actual.y1,
                    &actual.y2,
                    thresholds,
                ),
                3 => evaluate_signing_response::<3, 6, 5>(
                    &sk,
                    mode,
                    &actual_challenge,
                    actual.b,
                    &actual.y1,
                    &actual.y2,
                    thresholds,
                ),
                5 => evaluate_signing_response::<4, 7, 6>(
                    &sk,
                    mode,
                    &actual_challenge,
                    actual.b,
                    &actual.y1,
                    &actual.y2,
                    thresholds,
                ),
                _ => unreachable!(),
            };

            let context = format!("MODE={mode_number} CASE={case} ATTEMPT={attempt}");

            assert_eq!(decision.0, expected_norm_z, "{context} NORM_Z");
            assert_eq!(decision.1, expected_norm_tmp, "{context} NORM_TMP");
            assert_eq!(decision.2, expected_reject1, "{context} REJECT1");
            assert_eq!(decision.3, expected_reject2, "{context} REJECT2");

            let rejected = (decision.2 | decision.3) != 0;

            let actual_result = if rejected {
                "RESPONSE_REJECT"
            } else {
                "ACCEPT"
            };

            assert_eq!(actual_result, expected_result, "{context} RESULT");

            assert_eq!(
                rejected,
                attempt + 1 != attempts,
                "{context} RETRY_SEQUENCE"
            );

            if !rejected {
                assert!(
                    accepted_signature.is_none(),
                    "{context} duplicate accepted signature"
                );

                accepted_signature = Some(match mode_number {
                    2 => assemble_accepted_attempt::<2, 4, 3>(&AcceptedAttemptInputs {
                        mode_number,
                        mode,
                        pk: &pk,
                        sk: &sk,
                        mu: &init.mu,
                        b: actual.b,
                        y1: &actual.y1,
                        y2: &actual.y2,
                        thresholds,
                    }),
                    3 => assemble_accepted_attempt::<3, 6, 5>(&AcceptedAttemptInputs {
                        mode_number,
                        mode,
                        pk: &pk,
                        sk: &sk,
                        mu: &init.mu,
                        b: actual.b,
                        y1: &actual.y1,
                        y2: &actual.y2,
                        thresholds,
                    }),
                    5 => assemble_accepted_attempt::<4, 7, 6>(&AcceptedAttemptInputs {
                        mode_number,
                        mode,
                        pk: &pk,
                        sk: &sk,
                        mu: &init.mu,
                        b: actual.b,
                        y1: &actual.y1,
                        y2: &actual.y2,
                        thresholds,
                    }),
                    _ => unreachable!(),
                });
            }

            total_attempts += 1;
        }

        let signature = decode_hex(field(lines[cursor], "SIGNATURE"));
        cursor += 1;

        let digest = field(lines[cursor], "SIGNATURE_SHA256");
        cursor += 1;

        assert_eq!(signature.len(), mode.parameters().signature_bytes);
        assert_eq!(digest.len(), 64);

        let native_signature = accepted_signature.expect("accepted signing attempt");
        assert_eq!(
            native_signature.len(),
            signature.len(),
            "MODE={mode_number} CASE={case} signature length"
        );

        assert_eq!(
            native_signature, signature,
            "MODE={mode_number} CASE={case} complete signature mismatch"
        );
        let orchestrated_signature = sign_deterministic(mode, &sk, &message, context, &randomness)
            .expect("native HAETAE signer");

        assert_eq!(
            orchestrated_signature.len(),
            signature.len(),
            "MODE={mode_number} CASE={case} orchestrated signature length"
        );

        assert_eq!(
            orchestrated_signature, signature,
            "MODE={mode_number} CASE={case} orchestrated C-reference mismatch"
        );

        println!("HAETAE_NATIVE_SIGNER_MODE={mode_number} CASE={case} STATUS=PASS");

        let decoded = unpack_signature(mode, &signature)
            .expect("authenticated C-reference signature decoding");

        assert_eq!(decoded.challenge.len(), 256);
        assert_eq!(decoded.lowbits_z1.len(), mode.parameters().l * 256);
        assert_eq!(decoded.highbits_z1.len(), mode.parameters().l * 256);
        assert_eq!(decoded.hints.len(), mode.parameters().k * 256);

        let repacked = pack_signature(
            mode,
            &decoded.challenge,
            &decoded.lowbits_z1,
            &decoded.highbits_z1,
            &decoded.hints,
        )
        .expect("authenticated signature re-encoding");

        assert_eq!(
            repacked, signature,
            "MODE={mode_number} CASE={case} decoder round-trip mismatch"
        );

        println!("HAETAE_NATIVE_DECODER_MODE={mode_number} CASE={case} STATUS=PASS");

        // Compare Rust decoding with independent HAETAE 1.2.0
        // C-reference coefficient evidence.
        let evidence_root = std::env::var("HAETAE_DECODER_COEFFICIENT_PARITY_DIR")
            .expect("HAETAE_DECODER_COEFFICIENT_PARITY_DIR must be set");

        let evidence_path =
            std::path::Path::new(&evidence_root).join(format!("mode{mode_number}_case{case}.json"));

        let evidence_text =
            std::fs::read_to_string(&evidence_path).expect("read independent C decoder evidence");

        let evidence: serde_json::Value =
            serde_json::from_str(&evidence_text).expect("parse independent C decoder evidence");

        assert_eq!(
            evidence["format"].as_str(),
            Some("HAETAE_DECODER_COEFFICIENT_PARITY_V1")
        );
        assert_eq!(evidence["mode"].as_u64(), Some(mode_number as u64));
        assert_eq!(evidence["case"].as_u64(), Some(case as u64));

        let evidence_signature = evidence["signature_hex"]
            .as_str()
            .expect("C evidence signature");

        assert_eq!(
            evidence_signature,
            signature
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "MODE={mode_number} CASE={case} signature evidence mismatch"
        );

        for (name, rust_coefficients) in [
            ("challenge", &decoded.challenge),
            ("lowbits_z1", &decoded.lowbits_z1),
            ("highbits_z1", &decoded.highbits_z1),
            ("hints", &decoded.hints),
        ] {
            let reference = evidence[name]
                .as_array()
                .expect("C reference coefficient vector");

            assert_eq!(
                reference.len(),
                rust_coefficients.len(),
                "MODE={mode_number} CASE={case} {name} length mismatch"
            );

            for (index, (expected, actual)) in reference.iter().zip(rust_coefficients).enumerate() {
                assert_eq!(
                    expected.as_i64(),
                    Some(i64::from(*actual)),
                    "MODE={mode_number} CASE={case} {name}[{index}] mismatch"
                );
            }

            println!(
                "HAETAE_COEFFICIENT_VECTOR_MODE={mode_number}                  CASE={case} VECTOR={name} STATUS=PASS"
            );
        }

        println!(
            "HAETAE_NATIVE_COEFFICIENT_PARITY_MODE={mode_number}              CASE={case} STATUS=PASS"
        );

        println!(
            "MODE={mode_number} CASE={case} SIGNATURE_BYTES={} SIGNATURE_PARITY=PASS",
            native_signature.len()
        );

        assert_eq!(field(lines[cursor], "END_CASE"), case.to_string());
        cursor += 1;

        total_rejections += attempts - 1;

        println!(
            "MODE={mode_number} CASE={case} ATTEMPTS={attempts} \
             FINAL_NONCE={nonce} MU=PASS SEEDBUF=PASS CURSOR=PASS"
        );
    }

    assert_eq!(cursor, lines.len());

    let expected_attempts = match mode_number {
        2 => 27,
        3 => 15,
        5 => 25,
        _ => unreachable!(),
    };

    assert_eq!(total_attempts, expected_attempts);
    assert_eq!(total_rejections, total_attempts - 5);

    println!(
        "MODE={mode_number} CASES=5 ATTEMPTS={total_attempts} \
         REJECTIONS={total_rejections} STATUS=PASS"
    );
}

#[test]
fn retry_cursor_mode2() {
    run(2, ParameterSet::Haetae2);
}

#[test]
fn retry_cursor_mode3() {
    run(3, ParameterSet::Haetae3);
}

#[test]
fn retry_cursor_mode5() {
    run(5, ParameterSet::Haetae5);
}
