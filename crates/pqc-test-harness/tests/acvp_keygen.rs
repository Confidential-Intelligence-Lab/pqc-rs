use pqc_test_harness::acvp::{
    join_keygen_cases, parse_keygen_expected, parse_keygen_prompt, NIST_ACVP_SOURCE,
};

#[test]
fn pinned_source_is_nist_acvp_server() {
    assert_eq!(
        NIST_ACVP_SOURCE.repository,
        "https://github.com/usnistgov/ACVP-Server.git"
    );
    assert_eq!(NIST_ACVP_SOURCE.revision, "RELEASE/v1.1.0.42");
}

#[test]
fn parser_accepts_fips203_keygen_shape() {
    let prompt = r#"{
      "vsId": 7,
      "algorithm": "ML-KEM",
      "mode": "keyGen",
      "revision": "FIPS203",
      "testGroups": [{
        "tgId": 3,
        "testType": "AFT",
        "parameterSet": "ML-KEM-768",
        "tests": [{
          "tcId": 9,
          "z": "0000000000000000000000000000000000000000000000000000000000000000",
          "d": "1111111111111111111111111111111111111111111111111111111111111111"
        }]
      }]
    }"#;

    let expected = r#"{
      "vsId": 7,
      "algorithm": "ML-KEM",
      "mode": "keyGen",
      "revision": "FIPS203",
      "testGroups": [{
        "tgId": 3,
        "tests": [{
          "tcId": 9,
          "ek": "AA",
          "dk": "BB"
        }]
      }]
    }"#;

    let cases = join_keygen_cases(
        &parse_keygen_prompt(prompt).unwrap(),
        &parse_keygen_expected(expected).unwrap(),
    )
    .unwrap();

    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].parameter_set, "ML-KEM-768");
}
