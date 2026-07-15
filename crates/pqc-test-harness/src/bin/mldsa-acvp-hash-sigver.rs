use std::{collections::BTreeMap, env, fs, path::Path};

use pqc_ml_dsa::{
    hash_mldsa::{hash_verify, PreHashAlgorithm},
    params::MlDsaParameterSet,
};
use serde_json::{json, Map, Value};
type AcvpEnvelope<'a> = (Option<Value>, &'a Map<String, Value>, bool);
type CaseMap<'a> = BTreeMap<(u64, u64), &'a Map<String, Value>>;

fn main() {
    if let Err(error) = run() {
        eprintln!("HashML-DSA sigVer failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        return Err("usage: prompt response expected".to_owned());
    }

    let prompt = read_json(Path::new(&args[1]))?;
    let expected = read_json(Path::new(&args[3]))?;
    let (response, groups_examined, groups_supported, tests_executed) = process_prompt(&prompt)?;
    write_json(Path::new(&args[2]), &response)?;

    let actual_cases = indexed_cases(&response)?;
    let expected_cases = indexed_cases(&expected)?;
    let mut matched = 0_usize;
    let mut mismatches = 0_usize;

    for (key, actual) in actual_cases {
        let expected = expected_cases.get(&key).ok_or("missing expected")?;
        if required_bool(actual, "testPassed")? == required_bool(expected, "testPassed")? {
            matched += 1;
        } else {
            mismatches += 1;
        }
    }

    println!("NIST ACVP HashML-DSA sigVer");
    println!("  groups examined: {groups_examined}");
    println!("  groups supported: {groups_supported}");
    println!("  groups skipped: {}", groups_examined - groups_supported);
    println!("  tests executed: {tests_executed}");
    println!("  matched expected results: {matched}");
    println!("  mismatches: {mismatches}");

    if mismatches != 0 {
        return Err(format!("{mismatches} mismatches"));
    }

    Ok(())
}

fn process_prompt(prompt: &Value) -> Result<(Value, usize, usize, usize), String> {
    let (version, set, wrapped) = split(prompt)?;
    let groups = set
        .get("testGroups")
        .and_then(Value::as_array)
        .ok_or("missing groups")?;

    let mut output_groups = Vec::new();
    let mut groups_supported = 0_usize;
    let mut tests_executed = 0_usize;

    for group_value in groups {
        let group = group_value.as_object().ok_or("group is not an object")?;

        if group.get("testType").and_then(Value::as_str) != Some("AFT")
            || group.get("signatureInterface").and_then(Value::as_str) != Some("external")
            || group.get("preHash").and_then(Value::as_str) != Some("preHash")
        {
            continue;
        }

        groups_supported += 1;
        let tg_id = required_u64(group, "tgId")?;
        let set_id = parameter_set(required_str(group, "parameterSet")?)?;
        let mut output_tests = Vec::new();

        for test_value in group
            .get("tests")
            .and_then(Value::as_array)
            .ok_or("missing tests")?
        {
            let test = test_value.as_object().ok_or("test is not an object")?;
            let tc_id = required_u64(test, "tcId")?;
            let public_key = decode_hex(required_str(test, "pk")?)?;
            let message = decode_hex(required_str(test, "message")?)?;
            let context = decode_hex(required_str(test, "context")?)?;
            let signature = decode_hex(required_str(test, "signature")?)?;
            let algorithm = PreHashAlgorithm::from_acvp_name(required_str(test, "hashAlg")?)
                .map_err(|error| format!("{error:?}"))?;

            let test_passed = hash_verify(
                set_id,
                &public_key,
                &message,
                &context,
                algorithm,
                &signature,
            )
            .unwrap_or(false);

            output_tests.push(json!({
                "tcId": tc_id,
                "testPassed": test_passed,
            }));
            tests_executed += 1;
        }

        output_groups.push(json!({
            "tgId": tg_id,
            "tests": output_tests,
        }));
    }

    let response_set = json!({
        "vsId": required_u64(set, "vsId")?,
        "testGroups": output_groups,
    });

    Ok((
        if wrapped {
            json!([version.ok_or("missing version")?, response_set])
        } else {
            response_set
        },
        groups.len(),
        groups_supported,
        tests_executed,
    ))
}

fn split(value: &Value) -> Result<AcvpEnvelope<'_>, String> {
    if let Some(envelope) = value.as_array() {
        if envelope.len() != 2 {
            return Err("invalid ACVP envelope".to_owned());
        }
        Ok((
            Some(envelope[0].clone()),
            envelope[1].as_object().ok_or("missing vector set")?,
            true,
        ))
    } else {
        Ok((
            None,
            value.as_object().ok_or("ACVP JSON is not an object")?,
            false,
        ))
    }
}

fn indexed_cases(value: &Value) -> Result<CaseMap<'_>, String> {
    let (_, set, _) = split(value)?;
    let groups = set
        .get("testGroups")
        .and_then(Value::as_array)
        .ok_or("missing groups")?;
    let mut output = BTreeMap::new();

    for group_value in groups {
        let group = group_value.as_object().ok_or("group is not an object")?;
        let tg_id = required_u64(group, "tgId")?;

        for test_value in group
            .get("tests")
            .and_then(Value::as_array)
            .ok_or("missing tests")?
        {
            let test = test_value.as_object().ok_or("test is not an object")?;
            output.insert((tg_id, required_u64(test, "tcId")?), test);
        }
    }

    Ok(output)
}

fn parameter_set(value: &str) -> Result<MlDsaParameterSet, String> {
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
        .ok_or_else(|| format!("missing {field}"))
}

fn required_u64(object: &Map<String, Value>, field: &str) -> Result<u64, String> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing {field}"))
}

fn required_bool(object: &Map<String, Value>, field: &str) -> Result<bool, String> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing {field}"))
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("odd hex length".to_owned());
    }

    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("invalid hex".to_owned()),
    }
}

fn read_json(path: &Path) -> Result<Value, String> {
    let data = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&data).map_err(|error| error.to_string())
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(path, data).map_err(|error| error.to_string())
}
