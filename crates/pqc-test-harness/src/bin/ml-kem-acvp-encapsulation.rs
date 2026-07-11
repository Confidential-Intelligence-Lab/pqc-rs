use pqc_ml_kem::ml_kem_encaps::encaps_internal;
use pqc_ml_kem::MlKemParameterSet;
use pqc_test_harness::acvp::NIST_ACVP_SOURCE;
use pqc_test_harness::acvp_encap_decap::{
    load_encap_decap_cases, EncapDecapCase, EncapDecapFunction,
};
use std::path::PathBuf;

#[derive(Clone, Copy, Default)]
struct ParameterResults {
    total: usize,
    passed: usize,
    failed: usize,
}

#[derive(Default)]
struct Results {
    total: usize,
    passed: usize,
    failed: usize,
    first_failure: Option<String>,
    ml_kem_512: ParameterResults,
    ml_kem_768: ParameterResults,
    ml_kem_1024: ParameterResults,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ACVP encapsulation execution failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;

    let prompt =
        pqc_test_harness::acvp::local_vector_path(&root, NIST_ACVP_SOURCE.encap_decap_prompt_path);
    let expected = pqc_test_harness::acvp::local_vector_path(
        &root,
        NIST_ACVP_SOURCE.encap_decap_expected_path,
    );

    let cases = load_encap_decap_cases(prompt, expected)?;
    let mut results = Results::default();

    for case in cases
        .iter()
        .filter(|case| case.function == EncapDecapFunction::Encapsulation)
    {
        results.total += 1;
        parameter_results_mut(&mut results, &case.parameter_set).total += 1;

        match execute_case(case) {
            Ok(()) => {
                results.passed += 1;
                parameter_results_mut(&mut results, &case.parameter_set).passed += 1;
            }
            Err(detail) => {
                results.failed += 1;
                parameter_results_mut(&mut results, &case.parameter_set).failed += 1;
                if results.first_failure.is_none() {
                    results.first_failure = Some(detail);
                }
            }
        }
    }

    println!("NIST ACVP ML-KEM encapsulation results");
    println!("  total:  {}", results.total);
    println!("  passed: {}", results.passed);
    println!("  failed: {}", results.failed);
    println!();
    println!("By parameter set:");
    print_parameter_results("ML-KEM-512", results.ml_kem_512);
    print_parameter_results("ML-KEM-768", results.ml_kem_768);
    print_parameter_results("ML-KEM-1024", results.ml_kem_1024);

    if let Some(failure) = &results.first_failure {
        println!();
        println!("First mismatch:");
        println!("{failure}");
    }

    if results.failed != 0 {
        std::process::exit(2);
    }

    Ok(())
}

fn parameter_results_mut<'a>(
    results: &'a mut Results,
    parameter_set: &str,
) -> &'a mut ParameterResults {
    match parameter_set {
        "ML-KEM-512" => &mut results.ml_kem_512,
        "ML-KEM-768" => &mut results.ml_kem_768,
        "ML-KEM-1024" => &mut results.ml_kem_1024,
        other => panic!("unsupported parameter set in parsed ACVP case: {other}"),
    }
}

fn print_parameter_results(name: &str, results: ParameterResults) {
    println!(
        "  {name:12} total={:2} passed={:2} failed={:2}",
        results.total, results.passed, results.failed
    );
}

fn execute_case(case: &EncapDecapCase) -> Result<(), String> {
    let parameter_set = parse_parameter_set(&case.parameter_set)?;
    let ek = case
        .ek
        .as_deref()
        .ok_or_else(|| format_case_error(case, "missing ek"))?;
    let m_bytes = case
        .m
        .as_deref()
        .ok_or_else(|| format_case_error(case, "missing m"))?;
    let expected_ciphertext = case
        .expected_ciphertext
        .as_deref()
        .ok_or_else(|| format_case_error(case, "missing expected ciphertext"))?;
    let expected_shared_secret = case
        .expected_shared_secret
        .as_deref()
        .ok_or_else(|| format_case_error(case, "missing expected shared secret"))?;

    let m: [u8; 32] = m_bytes
        .try_into()
        .map_err(|_| format_case_error(case, "m is not 32 bytes"))?;

    let actual = encaps_internal(parameter_set, ek, &m)
        .map_err(|error| format_case_error(case, &format!("{error:?}")))?;

    let ciphertext_matches = actual.ciphertext == expected_ciphertext;
    let shared_secret_matches = actual.shared_secret.as_bytes() == expected_shared_secret;

    if ciphertext_matches && shared_secret_matches {
        return Ok(());
    }

    let mut details = Vec::new();

    if !ciphertext_matches {
        details.push(mismatch_report(
            case,
            "ciphertext",
            &actual.ciphertext,
            expected_ciphertext,
        ));
    } else {
        details.push(format!(
            "parameterSet={}, tgId={}, tcId={}\n  ciphertext: match",
            case.parameter_set, case.tg_id, case.tc_id
        ));
    }

    if !shared_secret_matches {
        details.push(mismatch_report(
            case,
            "shared secret",
            actual.shared_secret.as_bytes(),
            expected_shared_secret,
        ));
    } else {
        details.push(format!(
            "parameterSet={}, tgId={}, tcId={}\n  shared secret: match",
            case.parameter_set, case.tg_id, case.tc_id
        ));
    }

    Err(details.join("\n"))
}

fn parse_parameter_set(value: &str) -> Result<MlKemParameterSet, String> {
    match value {
        "ML-KEM-512" => Ok(MlKemParameterSet::MlKem512),
        "ML-KEM-768" => Ok(MlKemParameterSet::MlKem768),
        "ML-KEM-1024" => Ok(MlKemParameterSet::MlKem1024),
        other => Err(format!("unsupported parameter set: {other}")),
    }
}

fn mismatch_report(case: &EncapDecapCase, field: &str, actual: &[u8], expected: &[u8]) -> String {
    let index = first_mismatch(actual, expected);
    let start = index.saturating_sub(4);
    let end = usize::min(index + 9, usize::min(actual.len(), expected.len()));

    format!(
        "parameterSet={}, tgId={}, tcId={}\n  {} mismatch at byte {}: actual {:02X}, expected {:02X}\n  actual[{}..{}]   = {}\n  expected[{}..{}] = {}",
        case.parameter_set,
        case.tg_id,
        case.tc_id,
        field,
        index,
        actual.get(index).copied().unwrap_or_default(),
        expected.get(index).copied().unwrap_or_default(),
        start,
        end,
        hex::encode_upper(&actual[start..end]),
        start,
        end,
        hex::encode_upper(&expected[start..end]),
    )
}

fn first_mismatch(actual: &[u8], expected: &[u8]) -> usize {
    actual
        .iter()
        .zip(expected)
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| usize::min(actual.len(), expected.len()))
}

fn format_case_error(case: &EncapDecapCase, detail: &str) -> String {
    format!(
        "parameterSet={}, tgId={}, tcId={}: {}",
        case.parameter_set, case.tg_id, case.tc_id, detail
    )
}
