#![cfg(all(feature = "experimental-hkdf-sha3", feature = "internal-api"))]

use pqc_hpke::internal_api::kdf::KdfAlgorithm;
use pqc_hpke::internal_api::key_schedule::{
    key_schedule, AeadParameters, HpkeMode, KeyScheduleInputs,
};
use pqc_hpke::{AeadId, HpkeError, HpkeSuiteId, KdfId, KemId};

const VECTORS: &str = include_str!("fixtures/sha3_key_schedule.tsv");

fn decode(value: &str) -> Vec<u8> {
    hex::decode(value).expect("valid reference hex")
}

fn decode_id(value: &str) -> u16 {
    u16::from_str_radix(value, 16).expect("valid reference identifier")
}

#[test]
fn independent_sha3_key_schedule_matrix() {
    let kdf = KdfAlgorithm::HkdfSha3_256;
    let mut cases = 0;

    for line in VECTORS.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split('\t').collect();

        assert_eq!(fields.len(), 15);

        let kem_id = KemId(decode_id(fields[0]));
        let aead_id = AeadId(decode_id(fields[1]));

        let mode = match fields[2] {
            "0" => HpkeMode::Base,
            "1" => HpkeMode::Psk,
            _ => panic!("invalid fixture mode"),
        };

        let shared_secret = decode(fields[3]);
        let info = decode(fields[4]);
        let psk = decode(fields[5]);
        let psk_id = decode(fields[6]);

        let suite = HpkeSuiteId {
            kem_id,
            kdf_id: KdfId::EXPERIMENTAL_HKDF_SHA3_256,
            aead_id,
        };

        let case = format!("KEM={} AEAD={} mode={}", fields[0], fields[1], fields[2]);

        let suite_bytes = suite.to_bytes();

        assert_eq!(
            suite_bytes.as_slice(),
            decode(fields[7]).as_slice(),
            "{case}: suite identifier"
        );

        let result = key_schedule(
            suite,
            kdf,
            AeadParameters::for_id(aead_id).unwrap(),
            KeyScheduleInputs {
                mode,
                shared_secret: &shared_secret,
                info: &info,
                psk: &psk,
                psk_id: &psk_id,
            },
        )
        .unwrap();

        assert_eq!(
            result.key_schedule_context,
            decode(fields[8]),
            "{case}: key schedule context"
        );

        assert_eq!(
            result.secret.as_bytes(),
            decode(fields[9]).as_slice(),
            "{case}: intermediate secret"
        );

        assert_eq!(
            result.key.as_bytes(),
            decode(fields[10]).as_slice(),
            "{case}: AEAD key"
        );

        assert_eq!(result.base_nonce, decode(fields[11]), "{case}: base nonce");

        assert_eq!(
            result.exporter_secret.as_bytes(),
            decode(fields[12]).as_slice(),
            "{case}: exporter secret"
        );

        let exported = kdf
            .labeled_expand(
                &suite_bytes,
                result.exporter_secret.as_bytes(),
                b"sec",
                &decode(fields[13]),
                80,
            )
            .unwrap();

        assert_eq!(
            exported,
            decode(fields[14]),
            "{case}: exported application material"
        );

        assert_eq!(result.sequence_number, 0, "{case}: initial sequence number");

        println!("KEY_SCHEDULE_VECTOR=PASS {case}");

        cases += 1;
    }

    assert_eq!(cases, 12);

    println!("INDEPENDENT_KEY_SCHEDULE_CASES={cases}");
    println!("INDEPENDENT_OUTPUT_CHECKS={}", cases * 8);
}

#[test]
fn mismatched_kdf_identifier_is_rejected() {
    let suite = HpkeSuiteId {
        kem_id: KemId(0x0041),
        kdf_id: KdfId::HKDF_SHA256,
        aead_id: AeadId::AES_256_GCM,
    };

    let result = key_schedule(
        suite,
        KdfAlgorithm::HkdfSha3_256,
        AeadParameters::for_id(AeadId::AES_256_GCM).unwrap(),
        KeyScheduleInputs {
            mode: HpkeMode::Base,
            shared_secret: &[0x42; 32],
            info: b"context",
            psk: b"",
            psk_id: b"",
        },
    );

    assert!(matches!(result, Err(HpkeError::KdfIdentifierMismatch)));
}

#[test]
fn sha3_psk_mode_requires_consistent_inputs() {
    let suite = HpkeSuiteId {
        kem_id: KemId(0x0041),
        kdf_id: KdfId::EXPERIMENTAL_HKDF_SHA3_256,
        aead_id: AeadId::AES_256_GCM,
    };

    let cases: [(HpkeMode, &[u8], &[u8], HpkeError); 4] = [
        (HpkeMode::Base, b"psk", b"id", HpkeError::UnexpectedPsk),
        (HpkeMode::Psk, b"", b"", HpkeError::MissingPsk),
        (HpkeMode::Psk, b"psk", b"", HpkeError::InconsistentPskInputs),
        (HpkeMode::Psk, b"", b"id", HpkeError::InconsistentPskInputs),
    ];

    for (mode, psk, psk_id, expected) in cases {
        let result = key_schedule(
            suite,
            KdfAlgorithm::HkdfSha3_256,
            AeadParameters::for_id(AeadId::AES_256_GCM).unwrap(),
            KeyScheduleInputs {
                mode,
                shared_secret: &[0x42; 32],
                info: b"context",
                psk,
                psk_id,
            },
        );

        match result {
            Err(actual) => assert_eq!(actual, expected),
            Ok(_) => panic!("invalid PSK inputs accepted"),
        }
    }
}

#[test]
fn sha2_and_sha3_key_schedules_are_distinct() {
    let run = |kdf: KdfAlgorithm| {
        key_schedule(
            HpkeSuiteId {
                kem_id: KemId(0x0041),
                kdf_id: kdf.id(),
                aead_id: AeadId::AES_256_GCM,
            },
            kdf,
            AeadParameters::for_id(AeadId::AES_256_GCM).unwrap(),
            KeyScheduleInputs {
                mode: HpkeMode::Base,
                shared_secret: &[0x42; 32],
                info: b"identical-application-context",
                psk: b"",
                psk_id: b"",
            },
        )
        .unwrap()
    };

    let sha2 = run(KdfAlgorithm::HkdfSha256);
    let sha3 = run(KdfAlgorithm::HkdfSha3_256);

    assert_ne!(sha2.key.as_bytes(), sha3.key.as_bytes());

    assert_ne!(sha2.base_nonce, sha3.base_nonce);

    assert_ne!(
        sha2.exporter_secret.as_bytes(),
        sha3.exporter_secret.as_bytes()
    );
}
