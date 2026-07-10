use pqc_test_harness::acvp_encap_decap::{
    inventory, join_encap_decap_cases, parse_encap_decap_expected, parse_encap_decap_prompt,
    EncapDecapFunction,
};
use serde_json::json;

#[test]
fn joins_all_four_function_shapes() {
    let ek = "00".repeat(800);
    let dk = "00".repeat(1632);
    let c = "00".repeat(768);
    let m = "11".repeat(32);
    let k = "22".repeat(32);

    let prompt = json!({
        "vsId": 12,
        "algorithm": "ML-KEM",
        "mode": "encapDecap",
        "revision": "FIPS203",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-KEM-512",
                "function": "encapsulation",
                "tests": [{ "tcId": 1, "ek": ek, "m": m }]
            },
            {
                "tgId": 2,
                "testType": "VAL",
                "parameterSet": "ML-KEM-512",
                "function": "decapsulation",
                "tests": [{ "tcId": 2, "dk": dk, "c": c }]
            },
            {
                "tgId": 3,
                "testType": "VAL",
                "parameterSet": "ML-KEM-512",
                "function": "encapsulationKeyCheck",
                "tests": [{ "tcId": 3, "ek": "00".repeat(800) }]
            },
            {
                "tgId": 4,
                "testType": "VAL",
                "parameterSet": "ML-KEM-512",
                "function": "decapsulationKeyCheck",
                "tests": [{ "tcId": 4, "dk": "00".repeat(1632) }]
            }
        ]
    });

    let expected = json!({
        "vsId": 12,
        "algorithm": "ML-KEM",
        "mode": "encapDecap",
        "revision": "FIPS203",
        "testGroups": [
            {
                "tgId": 1,
                "tests": [{ "tcId": 1, "c": "00".repeat(768), "k": k }]
            },
            {
                "tgId": 2,
                "tests": [{ "tcId": 2, "k": "22".repeat(32) }]
            },
            {
                "tgId": 3,
                "tests": [{ "tcId": 3, "testPassed": false }]
            },
            {
                "tgId": 4,
                "tests": [{ "tcId": 4, "testPassed": true }]
            }
        ]
    });

    let cases = join_encap_decap_cases(
        &parse_encap_decap_prompt(&prompt.to_string()).unwrap(),
        &parse_encap_decap_expected(&expected.to_string()).unwrap(),
    )
    .unwrap();

    let summary = inventory(&cases);
    assert_eq!(summary.total_cases, 4);
    assert_eq!(
        summary.by_function.get(&EncapDecapFunction::Encapsulation),
        Some(&1)
    );
    assert_eq!(
        summary.by_function.get(&EncapDecapFunction::Decapsulation),
        Some(&1)
    );
}
