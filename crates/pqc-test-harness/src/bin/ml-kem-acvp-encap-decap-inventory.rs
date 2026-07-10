use pqc_test_harness::acvp::NIST_ACVP_SOURCE;
use pqc_test_harness::acvp_encap_decap::{inventory, load_encap_decap_cases, EncapDecapFunction};
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("ACVP encapDecap inventory failed: {error}");
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
    let summary = inventory(&cases);

    println!("NIST ACVP ML-KEM encapDecap inventory");
    println!("  total cases: {}", summary.total_cases);
    println!();
    println!("By function:");

    for function in [
        EncapDecapFunction::Encapsulation,
        EncapDecapFunction::Decapsulation,
        EncapDecapFunction::EncapsulationKeyCheck,
        EncapDecapFunction::DecapsulationKeyCheck,
    ] {
        let count = summary.by_function.get(&function).copied().unwrap_or(0);
        println!("  {:28} {}", function.as_str(), count);
    }

    println!();
    println!("By parameter set:");
    for (parameter_set, count) in &summary.by_parameter_set {
        println!("  {parameter_set:12} {count}");
    }

    println!();
    println!("Execution status:");
    println!("  parsed and schema-validated: {}", summary.total_cases);
    println!("  cryptographically executed: 0");
    println!("  officially passed:           0");
    println!();
    println!(
        "Stage 6.5A is inventory-only; no encapsulation or decapsulation \
         conformance claim is made."
    );

    Ok(())
}
