//! Execute NIST ACVP ML-KEM key-generation vectors.

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pqc_ml_kem::ml_kem_keygen::{
    ml_kem_1024_keygen_internal, ml_kem_512_keygen_internal, ml_kem_768_keygen_internal,
};
use pqc_test_harness::acvp::{load_keygen_cases, MlKemKeygenCase};

const PROMPT_RELATIVE: &str = "gen-val/json-files/ML-KEM-keyGen-FIPS203/prompt.json";
const EXPECTED_RELATIVE: &str = "gen-val/json-files/ML-KEM-keyGen-FIPS203/expectedResults.json";

#[derive(Default)]
struct Statistics {
    total: usize,
    passed: usize,
    failed: usize,
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("ACVP KeyGen runner error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<bool, String> {
    let root = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tests/kat/acvp/upstream"));

    let prompt = root.join(PROMPT_RELATIVE);
    let expected = root.join(EXPECTED_RELATIVE);

    require_file(&prompt)?;
    require_file(&expected)?;

    let cases = load_keygen_cases(&prompt, &expected).map_err(|error| error.to_string())?;

    let mut statistics = Statistics::default();
    let mut first_failure = None;

    for case in &cases {
        statistics.total += 1;

        match execute_case(case) {
            Ok(()) => statistics.passed += 1,
            Err(detail) => {
                statistics.failed += 1;
                if first_failure.is_none() {
                    first_failure = Some(detail);
                }
            }
        }
    }

    println!("NIST ACVP ML-KEM KeyGen results");
    println!("  total:  {}", statistics.total);
    println!("  passed: {}", statistics.passed);
    println!("  failed: {}", statistics.failed);

    if let Some(failure) = first_failure {
        println!("\nFirst mismatch:\n{failure}");
    }

    Ok(statistics.failed == 0 && statistics.total > 0)
}

fn require_file(path: &Path) -> Result<(), String> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!(
            "missing vector file {}; run ./scripts/fetch-nist-acvp-ml-kem.sh first",
            path.display()
        ))
    }
}

fn execute_case(case: &MlKemKeygenCase) -> Result<(), String> {
    let d: [u8; 32] = case
        .d
        .as_slice()
        .try_into()
        .map_err(|_| format_case_error(case, "d is not 32 bytes"))?;
    let z: [u8; 32] = case
        .z
        .as_slice()
        .try_into()
        .map_err(|_| format_case_error(case, "z is not 32 bytes"))?;

    match case.parameter_set.as_str() {
        "ML-KEM-512" => {
            let output = ml_kem_512_keygen_internal(&d, &z)
                .map_err(|error| format_case_error(case, &format!("{error:?}")))?;
            compare_case(case, &output.encapsulation_key, &output.decapsulation_key)
        }
        "ML-KEM-768" => {
            let output = ml_kem_768_keygen_internal(&d, &z)
                .map_err(|error| format_case_error(case, &format!("{error:?}")))?;
            compare_case(case, &output.encapsulation_key, &output.decapsulation_key)
        }
        "ML-KEM-1024" => {
            let output = ml_kem_1024_keygen_internal(&d, &z)
                .map_err(|error| format_case_error(case, &format!("{error:?}")))?;
            compare_case(case, &output.encapsulation_key, &output.decapsulation_key)
        }
        other => Err(format_case_error(
            case,
            &format!("unsupported parameter set {other}"),
        )),
    }
}

fn compare_case(case: &MlKemKeygenCase, actual_ek: &[u8], actual_dk: &[u8]) -> Result<(), String> {
    compare_bytes(case, "ek", actual_ek, &case.ek)?;
    compare_bytes(case, "dk", actual_dk, &case.dk)
}

fn compare_bytes(
    case: &MlKemKeygenCase,
    field: &str,
    actual: &[u8],
    expected: &[u8],
) -> Result<(), String> {
    if actual.len() != expected.len() {
        return Err(format_case_error(
            case,
            &format!(
                "{field} length mismatch: actual {}, expected {}",
                actual.len(),
                expected.len()
            ),
        ));
    }

    if let Some(index) = actual
        .iter()
        .zip(expected.iter())
        .position(|(actual_byte, expected_byte)| actual_byte != expected_byte)
    {
        let start = index.saturating_sub(8);
        let end = core::cmp::min(index + 9, actual.len());
        return Err(format_case_error(
            case,
            &format!(
                "{field} mismatch at byte {index}: actual {:02X}, expected {:02X}\n  actual[{start}..{end}]   = {}\n  expected[{start}..{end}] = {}",
                actual[index],
                expected[index],
                hex::encode_upper(&actual[start..end]),
                hex::encode_upper(&expected[start..end]),
            ),
        ));
    }

    Ok(())
}

fn format_case_error(case: &MlKemKeygenCase, detail: &str) -> String {
    format!(
        "parameterSet={}, tgId={}, tcId={}\n  {}",
        case.parameter_set, case.tg_id, case.tc_id, detail
    )
}
