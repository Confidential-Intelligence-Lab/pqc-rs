//! Trace the first failing NIST ACVP ML-KEM KeyGen case.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pqc_ml_kem::ml_kem_trace::{
    trace_ml_kem_1024_keygen, trace_ml_kem_512_keygen, trace_ml_kem_768_keygen, MlKemKeygenTrace,
};
use pqc_test_harness::acvp::{load_keygen_cases, MlKemKeygenCase};
use serde_json::{json, Value};

const PROMPT_RELATIVE: &str = "gen-val/json-files/ML-KEM-keyGen-FIPS203/prompt.json";
const EXPECTED_RELATIVE: &str = "gen-val/json-files/ML-KEM-keyGen-FIPS203/expectedResults.json";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ACVP KeyGen trace error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let vector_root = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tests/kat/acvp/upstream"));
    let output_root = env::args_os()
        .nth(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/acvp-traces/ml-kem-keygen"));

    let cases = load_keygen_cases(
        vector_root.join(PROMPT_RELATIVE),
        vector_root.join(EXPECTED_RELATIVE),
    )
    .map_err(|error| error.to_string())?;

    for case in &cases {
        if let Some(report) = trace_if_mismatched(case, &output_root)? {
            println!("First failing KeyGen trace written to {}", report.display());
            return Ok(());
        }
    }

    Err("all KeyGen cases passed; no failing trace was produced".to_owned())
}

fn trace_if_mismatched(
    case: &MlKemKeygenCase,
    output_root: &Path,
) -> Result<Option<PathBuf>, String> {
    let d: [u8; 32] = case
        .d
        .as_slice()
        .try_into()
        .map_err(|_| case_error(case, "d is not 32 bytes"))?;
    let z: [u8; 32] = case
        .z
        .as_slice()
        .try_into()
        .map_err(|_| case_error(case, "z is not 32 bytes"))?;

    match case.parameter_set.as_str() {
        "ML-KEM-512" => {
            let trace = trace_ml_kem_512_keygen(&d, &z)
                .map_err(|error| case_error(case, &format!("{error:?}")))?;
            write_if_mismatched(case, &trace, output_root)
        }
        "ML-KEM-768" => {
            let trace = trace_ml_kem_768_keygen(&d, &z)
                .map_err(|error| case_error(case, &format!("{error:?}")))?;
            write_if_mismatched(case, &trace, output_root)
        }
        "ML-KEM-1024" => {
            let trace = trace_ml_kem_1024_keygen(&d, &z)
                .map_err(|error| case_error(case, &format!("{error:?}")))?;
            write_if_mismatched(case, &trace, output_root)
        }
        other => Err(case_error(
            case,
            &format!("unsupported parameter set {other}"),
        )),
    }
}

fn write_if_mismatched<const EK_BYTES: usize, const DK_PKE_BYTES: usize>(
    case: &MlKemKeygenCase,
    trace: &MlKemKeygenTrace<EK_BYTES, DK_PKE_BYTES>,
    output_root: &Path,
) -> Result<Option<PathBuf>, String> {
    if trace.encapsulation_key.as_slice() == case.ek.as_slice() {
        return Ok(None);
    }

    let case_dir = output_root
        .join(&case.parameter_set)
        .join(format!("tg{}-tc{}", case.tg_id, case.tc_id));
    fs::create_dir_all(&case_dir).map_err(|error| error.to_string())?;

    write_bytes(&case_dir, "d.bin", &trace.d)?;
    write_bytes(&case_dir, "z.bin", &trace.z)?;
    write_bytes(&case_dir, "rho.bin", &trace.rho)?;
    write_bytes(&case_dir, "sigma.bin", &trace.sigma)?;
    write_bytes(&case_dir, "actual-ek.bin", &trace.encapsulation_key)?;
    write_bytes(&case_dir, "expected-ek.bin", &case.ek)?;
    write_bytes(&case_dir, "actual-dk-pke.bin", &trace.cpa_secret_key)?;

    let mismatch = first_mismatch(&trace.encapsulation_key, &case.ek);
    let report = json!({
        "status": "failing-internal-trace-not-conformance",
        "parameterSet": case.parameter_set,
        "tgId": case.tg_id,
        "tcId": case.tc_id,
        "firstEkMismatch": mismatch,
        "d": hex::encode_upper(trace.d),
        "z": hex::encode_upper(trace.z),
        "rho": hex::encode_upper(trace.rho),
        "sigma": hex::encode_upper(trace.sigma),
        "matrix00Digest": hex::encode_upper(trace.matrix_00_digest),
        "secret0Digest": hex::encode_upper(trace.secret_0_digest),
        "error0Digest": hex::encode_upper(trace.error_0_digest),
        "secretHat0Digest": hex::encode_upper(trace.secret_hat_0_digest),
        "errorHat0Digest": hex::encode_upper(trace.error_hat_0_digest),
        "public0Digest": hex::encode_upper(trace.public_0_digest),
        "publicHat0Digest": hex::encode_upper(trace.public_hat_0_digest),
        "actualEkSha3_256": hex::encode_upper(pqc_ml_kem::symmetric::h(&trace.encapsulation_key)),
        "expectedEkSha3_256": hex::encode_upper(pqc_ml_kem::symmetric::h(&case.ek)),
    });

    let report_path = case_dir.join("trace.json");
    let serialized = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    fs::write(&report_path, serialized).map_err(|error| error.to_string())?;

    Ok(Some(report_path))
}

fn first_mismatch(actual: &[u8], expected: &[u8]) -> Value {
    if actual.len() != expected.len() {
        return json!({
            "kind": "length",
            "actual": actual.len(),
            "expected": expected.len(),
        });
    }

    match actual
        .iter()
        .zip(expected.iter())
        .position(|(actual_byte, expected_byte)| actual_byte != expected_byte)
    {
        Some(index) => json!({
            "kind": "byte",
            "index": index,
            "actual": format!("{:02X}", actual[index]),
            "expected": format!("{:02X}", expected[index]),
        }),
        None => json!({ "kind": "none" }),
    }
}

fn write_bytes(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    fs::write(directory.join(name), bytes).map_err(|error| error.to_string())
}

fn case_error(case: &MlKemKeygenCase, detail: &str) -> String {
    format!(
        "parameterSet={}, tgId={}, tcId={}: {}",
        case.parameter_set, case.tg_id, case.tc_id, detail,
    )
}
