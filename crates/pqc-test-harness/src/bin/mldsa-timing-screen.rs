//! ML-DSA timing-leakage screening harness.

use std::{
    env,
    fs::File,
    hint::black_box,
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};

use pqc_ml_dsa::{keygen::keygen_internal, params::MlDsaParameterSet, signature::sign_internal};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const DEFAULT_SAMPLES: usize = 20_000;
const DEFAULT_WARMUP: usize = 200;

fn main() {
    if let Err(error) = run() {
        eprintln!("ML-DSA timing screen failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = env::args().collect();

    if arguments.len() < 3 || arguments.len() > 5 {
        return Err(format!(
            "usage: {} <keygen|sign> <output.csv> [samples] [warmup]",
            arguments
                .first()
                .map(String::as_str)
                .unwrap_or("mldsa-timing-screen"),
        ));
    }

    let output = Path::new(&arguments[2]);
    let samples = parse_optional_usize(arguments.get(3), DEFAULT_SAMPLES)?;
    let warmup = parse_optional_usize(arguments.get(4), DEFAULT_WARMUP)?;

    match arguments[1].as_str() {
        "keygen" => screen_keygen(output, samples, warmup),
        "sign" => screen_sign(output, samples, warmup),
        operation => Err(format!("unsupported operation {operation}")),
    }
}

fn screen_keygen(output: &Path, samples: usize, warmup: usize) -> Result<(), String> {
    let parameter_set = MlDsaParameterSet::MlDsa44;

    for index in 0..warmup {
        let seed = class_seed(index, index & 1);
        let key_pair = keygen_internal(parameter_set, black_box(&seed))
            .map_err(|error| format!("keyGen warmup failed: {error:?}"))?;
        black_box(key_pair.public_key());
        black_box(key_pair.private_key());
    }

    let mut writer = csv_writer(output)?;

    for sample in 0..samples {
        let class = interleaved_class(sample);
        let seed = class_seed(sample, class);

        let start = Instant::now();
        let key_pair = keygen_internal(parameter_set, black_box(&seed))
            .map_err(|error| format!("keyGen failed: {error:?}"))?;
        black_box(key_pair.public_key());
        black_box(key_pair.private_key());
        let elapsed = start.elapsed().as_nanos();

        writeln!(writer, "{sample},{class},{elapsed}").map_err(|error| error.to_string())?;
    }

    writer.flush().map_err(|error| error.to_string())
}

fn screen_sign(output: &Path, samples: usize, warmup: usize) -> Result<(), String> {
    let parameter_set = MlDsaParameterSet::MlDsa44;
    let fixed_key_pair = keygen_internal(parameter_set, &[0x42_u8; 32])
        .map_err(|error| format!("fixed keyGen failed: {error:?}"))?;
    let message = b"pqc-rs Stage 9F timing-screen message";
    let context = b"stage9f";
    let randomness = [0x24_u8; 32];

    for index in 0..warmup {
        let private_key = private_key_for_class(parameter_set, &fixed_key_pair, index, index & 1)?;

        let signature = sign_internal(
            parameter_set,
            black_box(&private_key),
            black_box(message),
            black_box(context),
            black_box(&randomness),
        )
        .map_err(|error| format!("sign warmup failed: {error:?}"))?;
        black_box(signature);
    }

    let mut writer = csv_writer(output)?;

    for sample in 0..samples {
        let class = interleaved_class(sample);
        let private_key = private_key_for_class(parameter_set, &fixed_key_pair, sample, class)?;

        let start = Instant::now();
        let signature = sign_internal(
            parameter_set,
            black_box(&private_key),
            black_box(message),
            black_box(context),
            black_box(&randomness),
        )
        .map_err(|error| format!("sign failed: {error:?}"))?;
        black_box(signature);
        let elapsed = start.elapsed().as_nanos();

        writeln!(writer, "{sample},{class},{elapsed}").map_err(|error| error.to_string())?;
    }

    writer.flush().map_err(|error| error.to_string())
}

fn private_key_for_class(
    parameter_set: MlDsaParameterSet,
    fixed_key_pair: &pqc_ml_dsa::keygen::MlDsaKeyPair,
    sample: usize,
    class: usize,
) -> Result<Vec<u8>, String> {
    if class == 0 {
        Ok(fixed_key_pair.private_key().to_vec())
    } else {
        let seed = class_seed(sample, 1);
        Ok(keygen_internal(parameter_set, &seed)
            .map_err(|error| format!("sample keyGen failed: {error:?}"))?
            .private_key()
            .to_vec())
    }
}

fn csv_writer(output: &Path) -> Result<BufWriter<File>, String> {
    let file =
        File::create(output).map_err(|error| format!("create {}: {error}", output.display()))?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "sample,class,nanoseconds").map_err(|error| error.to_string())?;
    Ok(writer)
}

fn interleaved_class(sample: usize) -> usize {
    usize::from(deterministic_bytes::<1>(0x90, sample as u64)[0] & 1)
}

fn class_seed(sample: usize, class: usize) -> [u8; 32] {
    if class == 0 {
        [0_u8; 32]
    } else {
        deterministic_bytes(0xa0, sample as u64)
    }
}

fn deterministic_bytes<const LENGTH: usize>(domain: u8, index: u64) -> [u8; LENGTH] {
    let mut hasher = Shake256::default();
    hasher.update(b"pqc-rs-stage9f1");
    hasher.update(&[domain]);
    hasher.update(&index.to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; LENGTH];
    reader.read(&mut output);
    output
}

fn parse_optional_usize(value: Option<&String>, default: usize) -> Result<usize, String> {
    match value {
        Some(value) => value
            .parse()
            .map_err(|error| format!("invalid integer {value}: {error}")),
        None => Ok(default),
    }
}
