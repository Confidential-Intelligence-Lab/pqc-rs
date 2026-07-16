use std::{
    env,
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

use pqc_ml_dsa::{
    audit::multiply_challenge_counted, challenge::sample_in_ball_bytes, constants::N, poly::Poly,
};

const TAU: usize = 39;
const CASES: usize = 1_000;

fn main() {
    if let Err(error) = run() {
        eprintln!("challenge work-equivalence report failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = env::args().collect();

    if arguments.len() != 2 {
        return Err(format!(
            "usage: {} <output.csv>",
            arguments
                .first()
                .map(String::as_str)
                .unwrap_or("mldsa-challenge-work-report"),
        ));
    }

    let output = Path::new(&arguments[1]);
    let file =
        File::create(output).map_err(|error| format!("create {}: {error}", output.display()))?;
    let mut writer = BufWriter::new(file);

    writeln!(
        writer,
        "case,nonzero,multiplications,direct,wrapped,total_accumulations,reductions"
    )
    .map_err(|error| error.to_string())?;

    let polynomial = audit_polynomial();
    let mut invariant_failures = 0_usize;
    let mut minimum_direct = usize::MAX;
    let mut maximum_direct = 0_usize;
    let mut minimum_wrapped = usize::MAX;
    let mut maximum_wrapped = 0_usize;

    for case in 0..CASES {
        let challenge = sample_in_ball_bytes(&seed_for_case(case), TAU)
            .map_err(|error| format!("case {case}: {error:?}"))?;
        let (_, counts) = multiply_challenge_counted(&challenge, &polynomial);

        if !counts.obeys_weight_invariants(TAU) {
            invariant_failures += 1;
        }

        minimum_direct = minimum_direct.min(counts.direct_accumulations);
        maximum_direct = maximum_direct.max(counts.direct_accumulations);
        minimum_wrapped = minimum_wrapped.min(counts.wrapped_accumulations);
        maximum_wrapped = maximum_wrapped.max(counts.wrapped_accumulations);

        writeln!(
            writer,
            "{case},{},{},{},{},{},{}",
            counts.nonzero_challenge_coefficients,
            counts.coefficient_multiplications,
            counts.direct_accumulations,
            counts.wrapped_accumulations,
            counts.total_accumulations(),
            counts.modular_reductions,
        )
        .map_err(|error| error.to_string())?;
    }

    writer.flush().map_err(|error| error.to_string())?;

    println!("ML-DSA challenge multiplication work-equivalence");
    println!("  cases: {CASES}");
    println!("  tau: {TAU}");
    println!("  polynomial degree: {N}");
    println!("  expected multiplications per case: {}", TAU * N);
    println!("  expected accumulations per case: {}", TAU * N);
    println!("  expected reductions per case: {N}");
    println!("  invariant failures: {invariant_failures}");
    println!("  direct accumulation range: {minimum_direct}..={maximum_direct}");
    println!("  wrapped accumulation range: {minimum_wrapped}..={maximum_wrapped}");

    if invariant_failures != 0 {
        return Err(format!("{invariant_failures} invariant failures"));
    }

    Ok(())
}

fn audit_polynomial() -> Poly {
    let mut coefficients = [0_i32; N];

    for (index, coefficient) in coefficients.iter_mut().enumerate() {
        *coefficient = ((index as i32 * 257) + 19).rem_euclid(8_380_417);
    }

    Poly::from_coeffs(coefficients)
}

fn seed_for_case(case: usize) -> [u8; 32] {
    let mut seed = [0_u8; 32];
    seed[..8].copy_from_slice(&(case as u64).to_le_bytes());

    for (index, byte) in seed[8..].iter_mut().enumerate() {
        *byte = (case as u8).wrapping_mul(17).wrapping_add(index as u8);
    }

    seed
}
