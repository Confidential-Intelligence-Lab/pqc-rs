//! ML-DSA-65 signing rejection/performance profiler.
//!
//! Generates a deterministic 5,000-case CSV campaign for longitudinal
//! analysis of signing latency and FIPS 204 rejection-loop behavior.
//! Case 0 preserves the fixed-randomness PQQS benchmark instance; the
//! remaining cases use deterministically derived signing randomness.
//!
//! This is performance/diagnostic infrastructure, not a constant-time
//! test. ML-DSA signing performs algorithmically variable work because
//! of its standardized rejection-sampling procedure.

use std::{
    fs::File,
    hint::black_box,
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};

use pqc_ml_dsa::{
    keygen::keygen_internal,
    params::MlDsaParameterSet,
    signature::{clear_signing_trace, sign_internal, signing_trace},
};

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const CASES: usize = 5_000;

const MESSAGE: &[u8] = b"pqc-rfc9958-rs B1.3.5 performance baseline";
const CONTEXT: &[u8] = b"benchmark";
const DSA_XI: [u8; 32] = [0x65; 32];

fn main() {
    let output = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: mldsa65-pqqs-rejection-profile <output.csv>");
        std::process::exit(64);
    });

    run(Path::new(&output)).expect("profile failed");
}

fn run(output: &Path) -> Result<(), String> {
    let parameter_set = MlDsaParameterSet::MlDsa65;

    let key_pair =
        keygen_internal(parameter_set, &DSA_XI).map_err(|e| format!("keygen failed: {e:?}"))?;

    let file = File::create(output).map_err(|e| format!("create {}: {e}", output.display()))?;

    let mut writer = BufWriter::new(file);

    writeln!(
        writer,
        "case,nanoseconds,attempts,reject_z,reject_r0,reject_ct0,reject_hint,total_rejections"
    )
    .map_err(|e| e.to_string())?;

    for case in 0..CASES {
        let randomness = if case == 0 {
            [0_u8; 32]
        } else {
            deterministic_randomness(case as u64)
        };

        clear_signing_trace();

        let start = Instant::now();

        let signature = sign_internal(
            parameter_set,
            black_box(key_pair.private_key()),
            black_box(MESSAGE),
            black_box(CONTEXT),
            black_box(&randomness),
        )
        .map_err(|e| format!("case {case}: {e:?}"))?;

        black_box(signature);

        let ns = start.elapsed().as_nanos();
        let trace = signing_trace();

        if trace.attempts != trace.total_rejections() + 1 {
            return Err(format!(
                "case {case}: attempts={} rejections={}",
                trace.attempts,
                trace.total_rejections()
            ));
        }

        writeln!(
            writer,
            "{case},{ns},{},{},{},{},{},{}",
            trace.attempts,
            trace.reject_z,
            trace.reject_r0,
            trace.reject_ct0,
            trace.reject_hint,
            trace.total_rejections(),
        )
        .map_err(|e| e.to_string())?;
    }

    writer.flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn deterministic_randomness(index: u64) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"pqc-rs-pqqs-mldsa65-performance");
    hasher.update(&index.to_le_bytes());

    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 32];
    reader.read(&mut output);
    output
}
