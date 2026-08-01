use std::path::{Path, PathBuf};

use pqc_test_harness::slhdsa_acvp::{
    keygen, load_json, registration::Registration, siggen, sigver, to_json, validation::Validation,
};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root must exist")
}

fn vector_path(family: &str, file: &str) -> PathBuf {
    repository_root()
        .join("vectors/nist-acvp")
        .join(family)
        .join(file)
}

#[test]
fn parses_keygen_corpus() {
    let prompt = keygen::parse_prompt(
        &std::fs::read_to_string(vector_path("slhdsa-keygen", "prompt.json")).unwrap(),
    )
    .unwrap();

    let expected = keygen::parse_expected(
        &std::fs::read_to_string(vector_path("slhdsa-keygen", "expectedResults.json")).unwrap(),
    )
    .unwrap();

    assert_eq!(prompt.test_groups.len(), 12);
    assert_eq!(expected.test_groups.len(), 12);

    assert_eq!(
        prompt
            .test_groups
            .iter()
            .map(|group| group.tests.len())
            .sum::<usize>(),
        120
    );
}

#[test]
fn parses_siggen_corpus() {
    let prompt = siggen::parse_prompt(
        &std::fs::read_to_string(vector_path("slhdsa-siggen", "prompt.json")).unwrap(),
    )
    .unwrap();

    let expected = siggen::parse_expected(
        &std::fs::read_to_string(vector_path("slhdsa-siggen", "expectedResults.json")).unwrap(),
    )
    .unwrap();

    assert_eq!(prompt.test_groups.len(), 72);
    assert_eq!(expected.test_groups.len(), 72);

    assert_eq!(
        prompt
            .test_groups
            .iter()
            .map(|group| group.tests.len())
            .sum::<usize>(),
        624
    );
}

#[test]
fn parses_sigver_corpus() {
    let prompt = sigver::parse_prompt(
        &std::fs::read_to_string(vector_path("slhdsa-sigver", "prompt.json")).unwrap(),
    )
    .unwrap();

    let expected = sigver::parse_expected(
        &std::fs::read_to_string(vector_path("slhdsa-sigver", "expectedResults.json")).unwrap(),
    )
    .unwrap();

    assert_eq!(prompt.test_groups.len(), 36);
    assert_eq!(expected.test_groups.len(), 36);
}

#[test]
fn parses_registration_and_validation_documents() {
    for family in ["slhdsa-keygen", "slhdsa-siggen", "slhdsa-sigver"] {
        let registration: Registration =
            load_json(vector_path(family, "registration.json")).unwrap();

        let validation: Validation = load_json(vector_path(family, "validation.json")).unwrap();

        assert_eq!(registration.algorithm, "SLH-DSA");
        assert_eq!(registration.revision, "FIPS205");
        assert!(validation.vs_id > 0);
    }
}

#[test]
fn typed_prompt_round_trips_without_semantic_loss() {
    let prompt = siggen::parse_prompt(
        &std::fs::read_to_string(vector_path("slhdsa-siggen", "prompt.json")).unwrap(),
    )
    .unwrap();

    let encoded = to_json(&prompt).unwrap();
    let decoded = siggen::parse_prompt(&encoded).unwrap();

    assert_eq!(decoded, prompt);
}

#[test]
fn parses_compact_internal_projection_shapes() {
    let keygen_json = r#"{
        "vsId": 1,
        "algorithm": "SLH-DSA",
        "mode": "keyGen",
        "revision": "FIPS205",
        "isSample": true,
        "testGroups": [{
            "tgId": 1,
            "parameterSet": "SLH-DSA-SHA2-128s",
            "testType": "AFT",
            "tests": [{
                "tcId": 1,
                "deferred": false,
                "skSeed": "00",
                "skPrf": "01",
                "pkSeed": "02",
                "pk": "03",
                "sk": "04"
            }]
        }]
    }"#;

    let siggen_json = r#"{
        "vsId": 2,
        "algorithm": "SLH-DSA",
        "mode": "sigGen",
        "revision": "FIPS205",
        "isSample": true,
        "testGroups": [{
            "tgId": 1,
            "parameterSet": "SLH-DSA-SHAKE-128f",
            "testType": "AFT",
            "deterministic": false,
            "signatureInterface": "internal",
            "preHash": "none",
            "tests": [{
                "tcId": 1,
                "deferred": false,
                "sk": "00",
                "pk": "01",
                "message": "02",
                "hashAlg": "none",
                "additionalRandomness": "03",
                "signature": "04"
            }]
        }]
    }"#;

    let sigver_json = r#"{
        "vsId": 3,
        "algorithm": "SLH-DSA",
        "mode": "sigVer",
        "revision": "FIPS205",
        "isSample": true,
        "testGroups": [{
            "tgId": 1,
            "parameterSet": "SLH-DSA-SHAKE-128f",
            "testType": "AFT",
            "signatureInterface": "internal",
            "preHash": "none",
            "tests": [{
                "tcId": 1,
                "deferred": false,
                "sk": "00",
                "pk": "01",
                "message": "02",
                "signature": "03",
                "hashAlg": "none",
                "additionalRandomness": "04",
                "testPassed": false,
                "reason": "test mutation"
            }]
        }]
    }"#;

    assert_eq!(
        keygen::parse_projection(keygen_json)
            .unwrap()
            .test_groups
            .len(),
        1
    );

    assert_eq!(
        siggen::parse_projection(siggen_json)
            .unwrap()
            .test_groups
            .len(),
        1
    );

    assert_eq!(
        sigver::parse_projection(sigver_json)
            .unwrap()
            .test_groups
            .len(),
        1
    );
}
