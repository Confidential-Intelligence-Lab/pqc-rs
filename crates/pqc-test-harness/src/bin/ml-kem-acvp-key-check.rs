use pqc_ml_kem::ml_kem_key_check::{decapsulation_key_is_valid, encapsulation_key_is_valid};
use pqc_ml_kem::MlKemParameterSet;
use pqc_test_harness::acvp::NIST_ACVP_SOURCE;
use pqc_test_harness::acvp_encap_decap::{
    load_encap_decap_cases, EncapDecapCase, EncapDecapFunction,
};
use std::path::PathBuf;

#[derive(Clone, Copy, Default)]
struct Counts {
    total: usize,
    passed: usize,
    failed: usize,
}

#[derive(Default)]
struct Results {
    total: Counts,
    encapsulation: Counts,
    decapsulation: Counts,
    ml_kem_512: Counts,
    ml_kem_768: Counts,
    ml_kem_1024: Counts,
    first_failure: Option<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ACVP key-check execution failed: {error}");
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

    for case in cases.iter().filter(|case| {
        matches!(
            case.function,
            EncapDecapFunction::EncapsulationKeyCheck | EncapDecapFunction::DecapsulationKeyCheck
        )
    }) {
        results.total.total += 1;
        function_counts_mut(&mut results, case.function).total += 1;
        parameter_counts_mut(&mut results, &case.parameter_set).total += 1;

        match execute_case(case) {
            Ok(()) => {
                results.total.passed += 1;
                function_counts_mut(&mut results, case.function).passed += 1;
                parameter_counts_mut(&mut results, &case.parameter_set).passed += 1;
            }
            Err(detail) => {
                results.total.failed += 1;
                function_counts_mut(&mut results, case.function).failed += 1;
                parameter_counts_mut(&mut results, &case.parameter_set).failed += 1;
                if results.first_failure.is_none() {
                    results.first_failure = Some(detail);
                }
            }
        }
    }

    println!("NIST ACVP ML-KEM key-check results");
    print_counts("total", results.total);
    println!();
    println!("By function:");
    print_counts("encapsulationKeyCheck", results.encapsulation);
    print_counts("decapsulationKeyCheck", results.decapsulation);
    println!();
    println!("By parameter set:");
    print_counts("ML-KEM-512", results.ml_kem_512);
    print_counts("ML-KEM-768", results.ml_kem_768);
    print_counts("ML-KEM-1024", results.ml_kem_1024);

    if let Some(failure) = &results.first_failure {
        println!();
        println!("First mismatch:");
        println!("{failure}");
    }

    if results.total.failed != 0 {
        std::process::exit(2);
    }

    Ok(())
}

fn execute_case(case: &EncapDecapCase) -> Result<(), String> {
    let parameter_set = parse_parameter_set(&case.parameter_set)?;
    let expected = case
        .expected_test_passed
        .ok_or_else(|| format_case_error(case, "missing testPassed"))?;

    let actual = match case.function {
        EncapDecapFunction::EncapsulationKeyCheck => {
            let ek = case
                .ek
                .as_deref()
                .ok_or_else(|| format_case_error(case, "missing ek"))?;
            encapsulation_key_is_valid(parameter_set, ek)
        }
        EncapDecapFunction::DecapsulationKeyCheck => {
            let dk = case
                .dk
                .as_deref()
                .ok_or_else(|| format_case_error(case, "missing dk"))?;
            decapsulation_key_is_valid(parameter_set, dk)
        }
        _ => return Err(format_case_error(case, "unexpected function")),
    };

    if actual != expected {
        return Err(format!(
            "parameterSet={}, tgId={}, tcId={}, function={}\n  actual testPassed={}\n  expected testPassed={}",
            case.parameter_set,
            case.tg_id,
            case.tc_id,
            case.function.as_str(),
            actual,
            expected,
        ));
    }

    Ok(())
}

fn parse_parameter_set(value: &str) -> Result<MlKemParameterSet, String> {
    match value {
        "ML-KEM-512" => Ok(MlKemParameterSet::MlKem512),
        "ML-KEM-768" => Ok(MlKemParameterSet::MlKem768),
        "ML-KEM-1024" => Ok(MlKemParameterSet::MlKem1024),
        other => Err(format!("unsupported parameter set: {other}")),
    }
}

fn function_counts_mut(results: &mut Results, function: EncapDecapFunction) -> &mut Counts {
    match function {
        EncapDecapFunction::EncapsulationKeyCheck => &mut results.encapsulation,
        EncapDecapFunction::DecapsulationKeyCheck => &mut results.decapsulation,
        _ => panic!("unexpected function in key-check runner"),
    }
}

fn parameter_counts_mut<'a>(results: &'a mut Results, parameter_set: &str) -> &'a mut Counts {
    match parameter_set {
        "ML-KEM-512" => &mut results.ml_kem_512,
        "ML-KEM-768" => &mut results.ml_kem_768,
        "ML-KEM-1024" => &mut results.ml_kem_1024,
        other => panic!("unsupported parameter set: {other}"),
    }
}

fn print_counts(name: &str, counts: Counts) {
    println!(
        "  {name:24} total={:2} passed={:2} failed={:2}",
        counts.total, counts.passed, counts.failed
    );
}

fn format_case_error(case: &EncapDecapCase, detail: &str) -> String {
    format!(
        "parameterSet={}, tgId={}, tcId={}: {}",
        case.parameter_set, case.tg_id, case.tc_id, detail
    )
}
