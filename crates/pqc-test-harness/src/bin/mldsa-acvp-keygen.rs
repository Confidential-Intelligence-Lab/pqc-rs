use pqc_ml_dsa::keygen::keygen_internal;
use pqc_ml_dsa::params::MlDsaParameterSet;
use serde_json::{json, Value};
use std::{env, fs, path::Path};

fn main() {
    if let Err(error) = run() {
        eprintln!("ML-DSA ACVP keyGen failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 || args.len() > 4 {
        return Err(format!(
            "usage: {} <prompt.json> <response.json> [expectedResults.json]",
            args.first()
                .map(String::as_str)
                .unwrap_or("mldsa-acvp-keygen")
        ));
    }
    let prompt = read_json(Path::new(&args[1]))?;
    let response = process_prompt(&prompt)?;
    write_json(Path::new(&args[2]), &response)?;
    let total = response_cases(&response)?.len();
    println!("NIST ACVP ML-DSA keyGen response");
    println!("  total: {total}");
    println!("  generated: {total}");
    if let Some(expected) = args.get(3) {
        compare_responses(&response, &read_json(Path::new(expected))?)?;
        println!("  matched expected results: {total}");
        println!("  mismatches: 0");
    }
    Ok(())
}

fn process_prompt(prompt: &Value) -> Result<Value, String> {
    let (version, set, wrapped) = if let Some(envelope) = prompt.as_array() {
        if envelope.len() != 2 {
            return Err(format!(
                "expected two envelope objects, found {}",
                envelope.len()
            ));
        }

        (
            Some(envelope[0].clone()),
            envelope[1].as_object().ok_or("missing vector-set object")?,
            true,
        )
    } else {
        (
            None,
            prompt
                .as_object()
                .ok_or("ACVP prompt must be an object or two-element array")?,
            false,
        )
    };
    require(set.get("algorithm"), "algorithm", "ML-DSA")?;
    require(set.get("mode"), "mode", "keyGen")?;
    require(set.get("revision"), "revision", "FIPS204")?;
    let vs_id = set
        .get("vsId")
        .and_then(Value::as_u64)
        .ok_or("missing vsId")?;
    let groups = set
        .get("testGroups")
        .and_then(Value::as_array)
        .ok_or("missing testGroups")?;
    let mut out_groups = Vec::with_capacity(groups.len());
    for group in groups {
        let group = group.as_object().ok_or("group is not an object")?;
        let tg_id = group
            .get("tgId")
            .and_then(Value::as_u64)
            .ok_or("missing tgId")?;
        require(group.get("testType"), "testType", "AFT")?;
        let parameter_set = parse_parameter_set(
            group
                .get("parameterSet")
                .and_then(Value::as_str)
                .ok_or("missing parameterSet")?,
        )?;
        let tests = group
            .get("tests")
            .and_then(Value::as_array)
            .ok_or("missing tests")?;
        let mut out_tests = Vec::with_capacity(tests.len());
        for test in tests {
            let test = test.as_object().ok_or("test is not an object")?;
            let tc_id = test
                .get("tcId")
                .and_then(Value::as_u64)
                .ok_or("missing tcId")?;
            let seed = decode_fixed_hex::<32>(
                test.get("seed")
                    .and_then(Value::as_str)
                    .ok_or("missing seed")?,
            )?;
            let kp = keygen_internal(parameter_set, &seed)
                .map_err(|e| format!("tcId {tc_id}: {e:?}"))?;
            out_tests.push(json!({"tcId": tc_id, "pk": encode_hex(kp.public_key()), "sk": encode_hex(kp.private_key())}));
        }
        out_groups.push(json!({"tgId": tg_id, "tests": out_tests}));
    }
    let response_set = json!({
        "vsId": vs_id,
        "testGroups": out_groups
    });

    if wrapped {
        Ok(json!([
            version.ok_or("missing ACVP version envelope")?,
            response_set
        ]))
    } else {
        Ok(response_set)
    }
}

fn compare_responses(actual: &Value, expected: &Value) -> Result<(), String> {
    let a = response_cases(actual)?;
    let e = response_cases(expected)?;
    if a.len() != e.len() {
        return Err(format!("count mismatch: {} vs {}", a.len(), e.len()));
    }
    let mut mismatches = Vec::new();
    for (aa, ee) in a.iter().zip(e.iter()) {
        let actual_pk = aa
            .get("pk")
            .and_then(Value::as_str)
            .ok_or("actual response missing pk")?;
        let expected_pk = ee
            .get("pk")
            .and_then(Value::as_str)
            .ok_or("expected response missing pk")?;
        let actual_sk = aa
            .get("sk")
            .and_then(Value::as_str)
            .ok_or("actual response missing sk")?;
        let expected_sk = ee
            .get("sk")
            .and_then(Value::as_str)
            .ok_or("expected response missing sk")?;

        if aa.get("tcId") != ee.get("tcId")
            || decode_hex(actual_pk)? != decode_hex(expected_pk)?
            || decode_hex(actual_sk)? != decode_hex(expected_sk)?
        {
            mismatches.push(aa.get("tcId").and_then(Value::as_u64).unwrap_or(0));
        }
    }
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} mismatches, first tcIds: {:?}",
            mismatches.len(),
            &mismatches[..mismatches.len().min(10)]
        ))
    }
}

fn response_cases(response: &Value) -> Result<Vec<&serde_json::Map<String, Value>>, String> {
    let set = if let Some(envelope) = response.as_array() {
        envelope
            .get(1)
            .and_then(Value::as_object)
            .ok_or("missing response set")?
    } else {
        response
            .as_object()
            .ok_or("response must be an object or two-element array")?
    };
    let groups = set
        .get("testGroups")
        .and_then(Value::as_array)
        .ok_or("missing response groups")?;
    let mut cases = Vec::new();
    for group in groups {
        let tests = group
            .as_object()
            .and_then(|g| g.get("tests"))
            .and_then(Value::as_array)
            .ok_or("missing response tests")?;
        for test in tests {
            cases.push(test.as_object().ok_or("response test not object")?);
        }
    }
    Ok(cases)
}

fn parse_parameter_set(name: &str) -> Result<MlDsaParameterSet, String> {
    match name {
        "ML-DSA-44" => Ok(MlDsaParameterSet::MlDsa44),
        "ML-DSA-65" => Ok(MlDsaParameterSet::MlDsa65),
        "ML-DSA-87" => Ok(MlDsaParameterSet::MlDsa87),
        _ => Err(format!("unsupported parameterSet {name}")),
    }
}
fn require(value: Option<&Value>, field: &str, expected: &str) -> Result<(), String> {
    match value.and_then(Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!("{field}={actual}, expected {expected}")),
        None => Err(format!("missing {field}")),
    }
}
fn decode_fixed_hex<const N: usize>(input: &str) -> Result<[u8; N], String> {
    let bytes = decode_hex(input)?;
    if bytes.len() != N {
        return Err(format!("hex has {} bytes, expected {N}", bytes.len()));
    }
    bytes
        .try_into()
        .map_err(|_| "fixed-size conversion failed".to_owned())
}
fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("odd hex length".to_owned());
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|p| Ok((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}
fn nibble(v: u8) -> Result<u8, String> {
    match v {
        b'0'..=b'9' => Ok(v - b'0'),
        b'a'..=b'f' => Ok(v - b'a' + 10),
        b'A'..=b'F' => Ok(v - b'A' + 10),
        _ => Err("invalid hex".to_owned()),
    }
}
fn encode_hex(input: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(input.len() * 2);
    for b in input {
        s.push(char::from(H[usize::from(b >> 4)]));
        s.push(char::from(H[usize::from(b & 15)]));
    }
    s
}
fn read_json(path: &Path) -> Result<Value, String> {
    let data = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_slice(&data).map_err(|e| format!("json {}: {e}", path.display()))
}
fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("write {}: {e}", path.display()))
}
