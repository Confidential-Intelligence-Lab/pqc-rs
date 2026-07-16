//! Fixed-key versus varying-key ML-DSA signing trace campaign.

use std::{
    env,
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

const CASES: usize = 10_000;

fn main() {
    if let Err(error) = run() {
        eprintln!("key-class signing trace failed: {error}");
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
                .unwrap_or("mldsa-key-class-trace"),
        ));
    }

    let output = Path::new(&arguments[1]);
    let parameter_set = MlDsaParameterSet::MlDsa44;
    let fixed_key_pair = keygen_internal(parameter_set, &[0x42_u8; 32])
        .map_err(|error| format!("fixed keyGen failed: {error:?}"))?;
    let message = b"pqc-rs Stage 9F-3A key-class trace";
    let context = b"stage9f3a";

    let file =
        File::create(output).map_err(|error| format!("create {}: {error}", output.display()))?;
    let mut writer = BufWriter::new(file);

    writeln!(
        writer,
        "case,class,nanoseconds,attempts,reject_z,reject_r0,reject_ct0,reject_hint,total_rejections"
    )
    .map_err(|error| error.to_string())?;

    for case in 0..CASES {
        let class = class_for_case(case);
        let private_key = if class == 0 {
            fixed_key_pair.private_key().to_vec()
        } else {
            let key_seed = deterministic_bytes::<32>(0x61, case as u64);
            keygen_internal(parameter_set, &key_seed)
                .map_err(|error| format!("case {case}: varying keyGen failed: {error:?}"))?
                .private_key()
                .to_vec()
        };

        // The randomness distribution is identical in both classes.
        let randomness = deterministic_bytes::<32>(0x73, case as u64);

        clear_signing_trace();
        let start = Instant::now();
        let signature = sign_internal(
            parameter_set,
            black_box(&private_key),
            black_box(message),
            black_box(context),
            black_box(&randomness),
        )
        .map_err(|error| format!("case {case}: sign failed: {error:?}"))?;
        black_box(signature);
        let nanoseconds = start.elapsed().as_nanos();
        let trace = signing_trace();

        if trace.attempts != trace.total_rejections() + 1 {
            return Err(format!(
                "case {case}: attempts={} rejections={}",
                trace.attempts,
                trace.total_rejections(),
            ));
        }

        writeln!(
            writer,
            "{case},{class},{nanoseconds},{},{},{},{},{},{}",
            trace.attempts,
            trace.reject_z,
            trace.reject_r0,
            trace.reject_ct0,
            trace.reject_hint,
            trace.total_rejections(),
        )
        .map_err(|error| error.to_string())?;
    }

    writer.flush().map_err(|error| error.to_string())?;
    println!("Recorded {CASES} ML-DSA-44 fixed/varying-key traces.");
    Ok(())
}

fn class_for_case(case: usize) -> usize {
    usize::from(deterministic_bytes::<1>(0x90, case as u64)[0] & 1)
}

fn deterministic_bytes<const LENGTH: usize>(domain: u8, index: u64) -> [u8; LENGTH] {
    let mut hasher = Shake256::default();
    hasher.update(b"pqc-rs-stage9f3a");
    hasher.update(&[domain]);
    hasher.update(&index.to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; LENGTH];
    reader.read(&mut output);
    output
}
