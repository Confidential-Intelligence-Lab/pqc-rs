use pqc_core::ct::ct_eq_bytes;
use std::{
    env,
    fs::File,
    hint::black_box,
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};
const SAMPLES: usize = 20_000;
const REPETITIONS: usize = 1_024;
const LENGTH: usize = 256;
fn main() {
    if let Err(e) = run() {
        eprintln!("Stage 10B-2 timing screen failed: {e}");
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
                .unwrap_or("ct-stage10b2-timing"),
        ));
    }

    let output = Path::new(&arguments[1]);
    let file =
        File::create(output).map_err(|error| format!("create {}: {error}", output.display()))?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "sample,class,nanoseconds").map_err(|error| error.to_string())?;

    let reference = [0xA5_u8; LENGTH];

    for sample in 0..SAMPLES {
        let class = class_for_sample(sample);
        let mut candidate = reference;

        match class {
            0 => candidate[0] ^= 1,
            1 => candidate[LENGTH / 2] ^= 1,
            2 => candidate[LENGTH - 1] ^= 1,
            _ => {}
        }

        let start = Instant::now();
        let mut accumulator = 0_u8;

        for repetition in 0..REPETITIONS {
            let mask = ct_eq_bytes(black_box(&reference), black_box(&candidate));

            accumulator ^= mask.raw().wrapping_add(repetition as u8);
        }

        black_box(accumulator);

        let elapsed = start.elapsed().as_nanos();
        let nanoseconds = elapsed as f64 / REPETITIONS as f64;

        writeln!(writer, "{sample},{class},{nanoseconds:.6}").map_err(|error| error.to_string())?;
    }

    writer.flush().map_err(|error| error.to_string())?;

    println!("Recorded {SAMPLES} batched mismatch-position timing samples.");
    println!("comparisons per sample: {REPETITIONS}");

    Ok(())
}

fn class_for_sample(sample: usize) -> usize {
    sample.wrapping_mul(17).wrapping_add(5) % 4
}
