#!/usr/bin/env python3
from pathlib import Path

sampling_path = Path("crates/pqc-ml-kem/src/sampling.rs")
runner_path = Path(
    "crates/pqc-test-harness/src/bin/ml-kem-acvp-encapsulation.rs"
)

if not sampling_path.exists():
    raise SystemExit(f"{sampling_path} not found; run from repository root")
if not runner_path.exists():
    raise SystemExit(f"{runner_path} not found; run from repository root")


def replace_function(text: str, signature: str, replacement: str) -> str:
    start = text.find(signature)
    if start < 0:
        raise SystemExit(f"Could not locate function: {signature}")

    brace = text.find("{", start)
    if brace < 0:
        raise SystemExit(f"Could not locate opening brace for: {signature}")

    depth = 0
    end = None
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                break

    if end is None:
        raise SystemExit(f"Could not locate closing brace for: {signature}")

    return text[:start] + replacement + text[end:]


sampling = sampling_path.read_text(encoding="utf-8")

eta3_replacement = '''pub fn cbd_eta3(input: &[u8; 192]) -> Poly {
    let mut coefficients = [0i16; 256];
    let mut block = 0usize;

    while block < 64 {
        let offset = 3 * block;
        let word = u32::from(input[offset])
            | (u32::from(input[offset + 1]) << 8)
            | (u32::from(input[offset + 2]) << 16);

        let mut sums = word & 0x0024_9249;
        sums += (word >> 1) & 0x0024_9249;
        sums += (word >> 2) & 0x0024_9249;

        let mut lane = 0usize;
        while lane < 4 {
            let shift = 6 * lane;
            let a = ((sums >> shift) & 0x7) as i16;
            let b = ((sums >> (shift + 3)) & 0x7) as i16;
            coefficients[4 * block + lane] = a - b;
            lane += 1;
        }

        block += 1;
    }

    Poly::from_coefficients(coefficients)
}'''

sampling = replace_function(
    sampling,
    "pub fn cbd_eta3(input: &[u8; 192]) -> Poly",
    eta3_replacement,
)

test_marker = "#[cfg(test)]\nmod tests {"
if test_marker not in sampling:
    raise SystemExit("Could not locate sampling test module")

if "cbd_eta3_known_bit_groups" not in sampling:
    insertion = '''#[cfg(test)]
mod stage6_5b2_tests {
    use super::*;

    #[test]
    fn cbd_eta3_all_zero_input_is_zero() {
        assert_eq!(cbd_eta3(&[0u8; 192]), Poly::zero());
    }

    #[test]
    fn cbd_eta3_known_bit_groups() {
        let mut input = [0u8; 192];

        input[0] = 0b0000_0111;
        let positive = cbd_eta3(&input);
        assert_eq!(positive.coefficients()[0], 3);

        input[0] = 0b0011_1000;
        let negative = cbd_eta3(&input);
        assert_eq!(negative.coefficients()[0], -3);
    }

    #[test]
    fn cbd_eta3_coefficients_stay_in_range() {
        let input = [0xffu8; 192];
        let polynomial = cbd_eta3(&input);

        assert!(polynomial
            .coefficients()
            .iter()
            .all(|coefficient| (-3..=3).contains(coefficient)));
    }
}

'''
    sampling = sampling.replace(test_marker, insertion + test_marker, 1)

sampling_path.write_text(sampling, encoding="utf-8")
print(f"Updated {sampling_path}")

runner = runner_path.read_text(encoding="utf-8")

if "struct ParameterResults" not in runner:
    runner = runner.replace(
        "#[derive(Default)]\nstruct Results {",
        '''#[derive(Clone, Copy, Default)]
struct ParameterResults {
    total: usize,
    passed: usize,
    failed: usize,
}

#[derive(Default)]
struct Results {''',
        1,
    )

    runner = runner.replace(
        "    first_failure: Option<String>,\n}",
        '''    first_failure: Option<String>,
    ml_kem_512: ParameterResults,
    ml_kem_768: ParameterResults,
    ml_kem_1024: ParameterResults,
}''',
        1,
    )

    runner = runner.replace(
        "        results.total += 1;\n\n        match execute_case(case) {",
        '''        results.total += 1;
        parameter_results_mut(&mut results, &case.parameter_set).total += 1;

        match execute_case(case) {''',
        1,
    )

    runner = runner.replace(
        "            Ok(()) => results.passed += 1,",
        '''            Ok(()) => {
                results.passed += 1;
                parameter_results_mut(&mut results, &case.parameter_set).passed += 1;
            }''',
        1,
    )

    runner = runner.replace(
        "                results.failed += 1;\n",
        '''                results.failed += 1;
                parameter_results_mut(&mut results, &case.parameter_set).failed += 1;
''',
        1,
    )

    print_marker = '    println!("  failed: {}", results.failed);\n'
    print_block = '''    println!("  failed: {}", results.failed);
    println!();
    println!("By parameter set:");
    print_parameter_results("ML-KEM-512", results.ml_kem_512);
    print_parameter_results("ML-KEM-768", results.ml_kem_768);
    print_parameter_results("ML-KEM-1024", results.ml_kem_1024);
'''
    if print_marker not in runner:
        raise SystemExit("Could not locate runner summary output")
    runner = runner.replace(print_marker, print_block, 1)

    helper_marker = "fn execute_case(case: &EncapDecapCase) -> Result<(), String> {"
    helpers = '''fn parameter_results_mut<'a>(
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

'''
    if helper_marker not in runner:
        raise SystemExit("Could not locate runner helper insertion point")
    runner = runner.replace(helper_marker, helpers + helper_marker, 1)

runner_path.write_text(runner, encoding="utf-8")
print(f"Updated {runner_path}")
