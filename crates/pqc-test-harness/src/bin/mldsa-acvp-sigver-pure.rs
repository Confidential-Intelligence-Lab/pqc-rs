use std::{collections::BTreeMap, env, fs, path::Path};

use pqc_ml_dsa::params::MlDsaParameterSet;
use pqc_ml_dsa::verification::verify_internal;
use serde_json::{json, Map, Value};

type CaseMap<'a> = BTreeMap<(u64, u64), &'a Map<String, Value>>;
type AcvpEnvelope<'a> = (Option<Value>, &'a Map<String, Value>, bool);

fn main() {
    if let Err(error) = run() {
        eprintln!("ML-DSA ACVP sigVer failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        return Err(format!(
            "usage: {} <prompt.json> <response.json> <expectedResults.json>",
            args.first()
                .map(String::as_str)
                .unwrap_or("mldsa-acvp-sigver-pure"),
        ));
    }

    let prompt = read_json(Path::new(&args[1]))?;
    let expected = read_json(Path::new(&args[3]))?;
    let result = process_prompt(&prompt)?;

    write_json(Path::new(&args[2]), &result.response)?;
    let comparison = compare_supported(&result.response, &expected)?;

    println!("NIST ACVP ML-DSA sigVer external-pure response");
    println!("  groups examined: {}", result.groups_examined);
    println!("  groups supported: {}", result.groups_supported);
    println!("  groups skipped: {}", result.groups_skipped);
    println!("  tests executed: {}", result.tests_executed);
    println!("  verifier true: {}", result.verifier_true);
    println!("  verifier false: {}", result.verifier_false);
    println!("  matched expected results: {}", comparison.matched);
    println!("  mismatches: {}", comparison.mismatches);

    if comparison.mismatches != 0 {
        return Err(format!(
            "{} supported sigVer vectors did not match",
            comparison.mismatches,
        ));
    }

    Ok(())
}

struct ProcessResult {
    response: Value,
    groups_examined: usize,
    groups_supported: usize,
    groups_skipped: usize,
    tests_executed: usize,
    verifier_true: usize,
    verifier_false: usize,
}

fn process_prompt(prompt: &Value) -> Result<ProcessResult, String> {
    let (version, set, wrapped) = split_envelope(prompt)?;
    require_string(set.get("algorithm"), "algorithm", "ML-DSA")?;
    require_string(set.get("mode"), "mode", "sigVer")?;
    require_string(set.get("revision"), "revision", "FIPS204")?;

    let vs_id = required_u64(set, "vsId")?;
    let groups = set
        .get("testGroups")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing testGroups".to_owned())?;

    let mut response_groups = Vec::new();
    let mut groups_supported = 0_usize;
    let mut tests_executed = 0_usize;
    let mut verifier_true = 0_usize;
    let mut verifier_false = 0_usize;

    for group_value in groups {
        let group = group_value
            .as_object()
            .ok_or_else(|| "test group is not an object".to_owned())?;

        if !is_supported_group(group) {
            continue;
        }

        groups_supported += 1;
        let tg_id = required_u64(group, "tgId")?;
        let parameter_set = parse_parameter_set(required_str(group, "parameterSet")?)?;
        let tests = group
            .get("tests")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("tgId {tg_id}: missing tests"))?;
        let mut response_tests = Vec::with_capacity(tests.len());

        for test_value in tests {
            let test = test_value
                .as_object()
                .ok_or_else(|| format!("tgId {tg_id}: test is not an object"))?;
            let tc_id = required_u64(test, "tcId")?;
            let public_key = decode_hex(required_str(test, "pk")?)?;
            let message = decode_hex(required_str(test, "message")?)?;
            let signature = decode_hex(required_str(test, "signature")?)?;
            let context = decode_optional_hex(test, "context")?;

            let test_passed =
                verify_internal(parameter_set, &public_key, &message, &context, &signature)
                    .unwrap_or(false);

            tests_executed += 1;
            if test_passed {
                verifier_true += 1;
            } else {
                verifier_false += 1;
            }

            response_tests.push(json!({
                "tcId": tc_id,
                "testPassed": test_passed,
            }));
        }

        response_groups.push(json!({
            "tgId": tg_id,
            "tests": response_tests,
        }));
    }

    let response_set = json!({
        "vsId": vs_id,
        "testGroups": response_groups,
    });

    let response = if wrapped {
        json!([
            version.ok_or_else(|| "missing ACVP version envelope".to_owned())?,
            response_set
        ])
    } else {
        response_set
    };

    Ok(ProcessResult {
        response,
        groups_examined: groups.len(),
        groups_supported,
        groups_skipped: groups.len() - groups_supported,
        tests_executed,
        verifier_true,
        verifier_false,
    })
}

fn is_supported_group(group: &Map<String, Value>) -> bool {
    group.get("testType").and_then(Value::as_str) == Some("AFT")
        && group.get("signatureInterface").and_then(Value::as_str) == Some("external")
        && group.get("preHash").and_then(Value::as_str) == Some("pure")
}

struct Comparison {
    matched: usize,
    mismatches: usize,
}

fn compare_supported(actual: &Value, expected: &Value) -> Result<Comparison, String> {
    let actual_cases = indexed_cases(actual)?;
    let expected_cases = indexed_cases(expected)?;
    let mut matched = 0_usize;
    let mut mismatches = 0_usize;

    for (key, actual_case) in actual_cases {
        let expected_case = expected_cases
            .get(&key)
            .ok_or_else(|| format!("missing expected tgId={} tcId={}", key.0, key.1))?;

        let actual_passed = required_bool(actual_case, "testPassed")?;
        let expected_passed = required_bool(expected_case, "testPassed")?;

        if actual_passed == expected_passed {
            matched += 1;
        } else {
            mismatches += 1;
            if mismatches <= 10 {
                eprintln!(
                    "mismatch tgId={} tcId={}: actual={} expected={}",
                    key.0, key.1, actual_passed, expected_passed,
                );
            }
        }
    }

    Ok(Comparison {
        matched,
        mismatches,
    })
}

fn indexed_cases(value: &Value) -> Result<CaseMap<'_>, String> {
    let (_, set, _) = split_envelope(value)?;
    let groups = set
        .get("testGroups")
        .and_then(Value::as_array)
        .ok_or_else(|| "response missing testGroups".to_owned())?;
    let mut output = BTreeMap::new();

    for group_value in groups {
        let group = group_value
            .as_object()
            .ok_or_else(|| "response group is not an object".to_owned())?;
        let tg_id = required_u64(group, "tgId")?;
        let tests = group
            .get("tests")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("tgId {tg_id}: response tests missing"))?;

        for test_value in tests {
            let test = test_value
                .as_object()
                .ok_or_else(|| format!("tgId {tg_id}: response test is not an object"))?;
            let tc_id = required_u64(test, "tcId")?;
            output.insert((tg_id, tc_id), test);
        }
    }

    Ok(output)
}

fn split_envelope(value: &Value) -> Result<AcvpEnvelope<'_>, String> {
    if let Some(envelope) = value.as_array() {
        if envelope.len() != 2 {
            return Err(format!(
                "expected two ACVP envelope objects, found {}",
                envelope.len(),
            ));
        }

        Ok((
            Some(envelope[0].clone()),
            envelope[1]
                .as_object()
                .ok_or_else(|| "missing ACVP vector-set object".to_owned())?,
            true,
        ))
    } else {
        Ok((
            None,
            value
                .as_object()
                .ok_or_else(|| "ACVP JSON must be an object or two-element array".to_owned())?,
            false,
        ))
    }
}

fn parse_parameter_set(value: &str) -> Result<MlDsaParameterSet, String> {
    match value {
        "ML-DSA-44" => Ok(MlDsaParameterSet::MlDsa44),
        "ML-DSA-65" => Ok(MlDsaParameterSet::MlDsa65),
        "ML-DSA-87" => Ok(MlDsaParameterSet::MlDsa87),
        _ => Err(format!("unsupported parameterSet {value}")),
    }
}

fn required_str<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {field}"))
}

fn required_u64(object: &Map<String, Value>, field: &str) -> Result<u64, String> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing numeric field {field}"))
}

fn required_bool(object: &Map<String, Value>, field: &str) -> Result<bool, String> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing boolean field {field}"))
}

fn require_string(value: Option<&Value>, field: &str, expected: &str) -> Result<(), String> {
    match value.and_then(Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!("{field}={actual}, expected {expected}")),
        None => Err(format!("missing string field {field}")),
    }
}

fn decode_optional_hex(object: &Map<String, Value>, field: &str) -> Result<Vec<u8>, String> {
    match object.get(field) {
        Some(Value::String(value)) => decode_hex(value),
        None => Ok(Vec::new()),
        _ => Err(format!("{field} is not a hex string")),
    }
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("hex string has odd length".to_owned());
    }

    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?))
        .collect()
}

fn decode_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(format!("invalid hex character {:?}", char::from(value))),
    }
}

fn read_json(path: &Path) -> Result<Value, String> {
    let data = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&data).map_err(|error| format!("JSON {}: {error}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(path, data).map_err(|error| format!("write {}: {error}", path.display()))
}
