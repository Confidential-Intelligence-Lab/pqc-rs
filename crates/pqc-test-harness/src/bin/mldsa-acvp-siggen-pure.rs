use std::{env, fs, path::Path};

use pqc_ml_dsa::params::MlDsaParameterSet;
use pqc_ml_dsa::signature::sign_internal;
use serde_json::{json, Map, Value};
type CaseMap<'a> = std::collections::BTreeMap<(u64, u64), &'a Map<String, Value>>;
type AcvpEnvelope<'a> = (Option<Value>, &'a Map<String, Value>, bool);

fn main() {
    if let Err(error) = run() {
        eprintln!("ML-DSA ACVP sigGen failed: {error}");
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
                .unwrap_or("mldsa-acvp-siggen-pure"),
        ));
    }

    let prompt = read_json(Path::new(&args[1]))?;
    let expected = read_json(Path::new(&args[3]))?;
    let result = process_prompt(&prompt)?;

    write_json(Path::new(&args[2]), &result.response)?;
    let comparison = compare_supported(&result.response, &expected)?;

    println!("NIST ACVP ML-DSA sigGen external-pure response");
    println!("  groups examined: {}", result.groups_examined);
    println!("  groups supported: {}", result.groups_supported);
    println!("  groups skipped: {}", result.groups_skipped);
    println!("  tests generated: {}", result.tests_generated);
    println!("  matched expected results: {}", comparison.matched);
    println!("  mismatches: {}", comparison.mismatches);

    if comparison.mismatches != 0 {
        return Err(format!(
            "{} supported sigGen vectors did not match",
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
    tests_generated: usize,
}

fn process_prompt(prompt: &Value) -> Result<ProcessResult, String> {
    let (version, vector_set, wrapped) = split_envelope(prompt)?;
    require_string(vector_set.get("algorithm"), "algorithm", "ML-DSA")?;
    require_string(vector_set.get("mode"), "mode", "sigGen")?;
    require_string(vector_set.get("revision"), "revision", "FIPS204")?;

    let vs_id = vector_set
        .get("vsId")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing numeric vsId".to_owned())?;
    let groups = vector_set
        .get("testGroups")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing testGroups".to_owned())?;

    let mut response_groups = Vec::new();
    let mut groups_supported = 0_usize;
    let mut tests_generated = 0_usize;

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
        let deterministic = required_bool(group, "deterministic")?;
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
            let private_key = decode_hex(required_str(test, "sk")?)?;
            let message = decode_hex(required_str(test, "message")?)?;
            let context = decode_optional_hex(test, "context")?;
            let randomness = if deterministic {
                [0_u8; 32]
            } else {
                decode_fixed_hex::<32>(required_str(test, "rnd")?)?
            };

            let signature =
                sign_internal(parameter_set, &private_key, &message, &context, &randomness)
                    .map_err(|error| {
                        format!("tgId {tg_id} tcId {tc_id}: signing failed: {error:?}")
                    })?;

            response_tests.push(json!({
                "tcId": tc_id,
                "signature": encode_hex(&signature),
            }));
            tests_generated += 1;
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
        tests_generated,
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
            .ok_or_else(|| format!("expected results missing tgId={} tcId={}", key.0, key.1))?;
        let actual_signature = decode_hex(required_str(actual_case, "signature")?)?;
        let expected_signature = decode_hex(required_str(expected_case, "signature")?)?;

        if actual_signature == expected_signature {
            matched += 1;
        } else {
            mismatches += 1;
            if mismatches <= 10 {
                eprintln!("mismatch tgId={} tcId={}", key.0, key.1);
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
    let mut output = std::collections::BTreeMap::new();

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

fn decode_fixed_hex<const LENGTH: usize>(input: &str) -> Result<[u8; LENGTH], String> {
    let decoded = decode_hex(input)?;
    if decoded.len() != LENGTH {
        return Err(format!(
            "hex value has {} bytes, expected {LENGTH}",
            decoded.len(),
        ));
    }
    decoded
        .try_into()
        .map_err(|_| "fixed-size conversion failed".to_owned())
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

fn encode_hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);

    for byte in input {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }

    output
}

fn read_json(path: &Path) -> Result<Value, String> {
    let data = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&data).map_err(|error| format!("JSON {}: {error}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(path, data).map_err(|error| format!("write {}: {error}", path.display()))
}
