//! SLH-DSA S6 fixed-vs-varying secret timing screen.

use std::{
    env,
    fs::File,
    hint::black_box,
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};

use pqc_slh_dsa::{
    address::{Address, AddressType},
    hash::{Sha2TweakableHash, ShakeTweakableHash},
};

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const DEFAULT_SAMPLES: usize = 20_000;
const DEFAULT_WARMUP: usize = 500;
const DEFAULT_REPETITIONS: usize = 128;

fn main() {
    if let Err(error) = run() {
        eprintln!("SLH-DSA S6 timing screen failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = env::args().collect();

    if arguments.len() < 3 || arguments.len() > 6 {
        return Err(format!(
            "usage: {} <shake-prf|shake-prf-msg|sha2-prf|sha2-prf-msg-32|sha2-prf-msg-16> \
             <output.csv> [samples] [warmup] [repetitions]",
            arguments
                .first()
                .map(String::as_str)
                .unwrap_or("slhdsa-s6-timing-screen"),
        ));
    }

    let output = Path::new(&arguments[2]);
    let samples = parse_optional_usize(arguments.get(3), DEFAULT_SAMPLES)?;
    let warmup = parse_optional_usize(arguments.get(4), DEFAULT_WARMUP)?;
    let repetitions = parse_optional_usize(arguments.get(5), DEFAULT_REPETITIONS)?;

    match arguments[1].as_str() {
        "shake-prf" => screen_prf(output, samples, warmup, repetitions, Primitive::ShakePrf),
        "shake-prf-msg" => {
            screen_prf_msg(output, samples, warmup, repetitions, Primitive::ShakePrfMsg)
        }
        "sha2-prf" => screen_prf(output, samples, warmup, repetitions, Primitive::Sha2Prf),
        "sha2-prf-msg-32" => screen_prf_msg(
            output,
            samples,
            warmup,
            repetitions,
            Primitive::Sha2PrfMsg32,
        ),
        "sha2-prf-msg-16" => screen_prf_msg(
            output,
            samples,
            warmup,
            repetitions,
            Primitive::Sha2PrfMsg16,
        ),
        operation => Err(format!("unsupported operation {operation}")),
    }
}

#[derive(Clone, Copy)]
enum Primitive {
    ShakePrf,
    ShakePrfMsg,
    Sha2Prf,
    Sha2PrfMsg32,
    Sha2PrfMsg16,
}

impl Primitive {
    fn n(self) -> usize {
        match self {
            Self::Sha2PrfMsg16 => 16,
            _ => 32,
        }
    }
}

fn screen_prf(
    output_path: &Path,
    samples: usize,
    warmup: usize,
    repetitions: usize,
    primitive: Primitive,
) -> Result<(), String> {
    let n = primitive.n();

    let public_seed = vec![0x11_u8; n];
    let address = audit_address();

    for sample in 0..warmup {
        let class = interleaved_class(sample);
        let secret_seed = secret_for_class(n, sample, class, 0xa1);

        execute_prf(primitive, &public_seed, &secret_seed, &address, repetitions)?;
    }

    let mut writer = csv_writer(output_path)?;

    for sample in 0..samples {
        let class = interleaved_class(sample);
        let secret_seed = secret_for_class(n, sample, class, 0xa1);

        let start = Instant::now();

        execute_prf(
            primitive,
            black_box(&public_seed),
            black_box(&secret_seed),
            black_box(&address),
            repetitions,
        )?;

        let elapsed = start.elapsed().as_nanos() as f64 / repetitions as f64;

        writeln!(writer, "{sample},{class},{elapsed:.6}").map_err(|error| error.to_string())?;
    }

    writer.flush().map_err(|error| error.to_string())?;

    println!("samples={samples}");
    println!("warmup={warmup}");
    println!("repetitions={repetitions}");

    Ok(())
}

fn screen_prf_msg(
    output_path: &Path,
    samples: usize,
    warmup: usize,
    repetitions: usize,
    primitive: Primitive,
) -> Result<(), String> {
    let n = primitive.n();
    let message = b"pqc-rs-slh-dsa-s6-fixed-public-message";

    for sample in 0..warmup {
        let class = interleaved_class(sample);

        let secret_prf = secret_for_class(n, sample, class, 0xb1);
        let optional_randomness = secret_for_class(n, sample, class, 0xb2);

        execute_prf_msg(
            primitive,
            &secret_prf,
            &optional_randomness,
            message,
            repetitions,
        )?;
    }

    let mut writer = csv_writer(output_path)?;

    for sample in 0..samples {
        let class = interleaved_class(sample);

        let secret_prf = secret_for_class(n, sample, class, 0xb1);
        let optional_randomness = secret_for_class(n, sample, class, 0xb2);

        let start = Instant::now();

        execute_prf_msg(
            primitive,
            black_box(&secret_prf),
            black_box(&optional_randomness),
            black_box(message),
            repetitions,
        )?;

        let elapsed = start.elapsed().as_nanos() as f64 / repetitions as f64;

        writeln!(writer, "{sample},{class},{elapsed:.6}").map_err(|error| error.to_string())?;
    }

    writer.flush().map_err(|error| error.to_string())?;

    println!("samples={samples}");
    println!("warmup={warmup}");
    println!("repetitions={repetitions}");

    Ok(())
}

fn execute_prf(
    primitive: Primitive,
    public_seed: &[u8],
    secret_seed: &[u8],
    address: &Address,
    repetitions: usize,
) -> Result<(), String> {
    let n = primitive.n();
    let mut output = vec![0_u8; n];

    match primitive {
        Primitive::ShakePrf => {
            let hash = ShakeTweakableHash::new(n);

            for _ in 0..repetitions {
                hash.prf(
                    black_box(public_seed),
                    black_box(secret_seed),
                    black_box(address),
                    black_box(&mut output),
                )
                .map_err(|error| format!("SHAKE PRF failed: {error:?}"))?;

                black_box(&output);
            }
        }

        Primitive::Sha2Prf => {
            let hash = Sha2TweakableHash::new(n);

            for _ in 0..repetitions {
                hash.prf(
                    black_box(public_seed),
                    black_box(secret_seed),
                    black_box(address),
                    black_box(&mut output),
                )
                .map_err(|error| format!("SHA2 PRF failed: {error:?}"))?;

                black_box(&output);
            }
        }

        _ => return Err("PRF timing called with PRF_msg primitive".to_owned()),
    }

    Ok(())
}

fn execute_prf_msg(
    primitive: Primitive,
    secret_prf: &[u8],
    optional_randomness: &[u8],
    message: &[u8],
    repetitions: usize,
) -> Result<(), String> {
    let n = primitive.n();
    let mut output = vec![0_u8; n];

    match primitive {
        Primitive::ShakePrfMsg => {
            let hash = ShakeTweakableHash::new(n);

            for _ in 0..repetitions {
                hash.prf_msg(
                    black_box(secret_prf),
                    black_box(optional_randomness),
                    black_box(message),
                    black_box(&mut output),
                )
                .map_err(|error| format!("SHAKE PRF_msg failed: {error:?}"))?;

                black_box(&output);
            }
        }

        Primitive::Sha2PrfMsg32 | Primitive::Sha2PrfMsg16 => {
            let hash = Sha2TweakableHash::new(n);

            for _ in 0..repetitions {
                hash.prf_msg(
                    black_box(secret_prf),
                    black_box(optional_randomness),
                    black_box(message),
                    black_box(&mut output),
                )
                .map_err(|error| format!("SHA2 PRF_msg failed: {error:?}"))?;

                black_box(&output);
            }
        }

        _ => return Err("PRF_msg timing called with PRF primitive".to_owned()),
    }

    Ok(())
}

fn audit_address() -> Address {
    let mut address = Address::new();

    address.set_layer_address(3);
    address.set_tree_address(0x0102_0304_0506_0708);
    address.set_type_and_clear(AddressType::WotsPrf);
    address.set_key_pair_address(7);
    address.set_chain_address(11);
    address.set_hash_address(13);

    address
}

fn secret_for_class(length: usize, sample: usize, class: usize, domain: u8) -> Vec<u8> {
    if class == 0 {
        vec![0x5a_u8; length]
    } else {
        deterministic_bytes(length, domain, sample as u64)
    }
}

fn deterministic_bytes(length: usize, domain: u8, index: u64) -> Vec<u8> {
    let mut hasher = Shake256::default();

    hasher.update(b"pqc-rs-slh-dsa-s6-timing");
    hasher.update(&[domain]);
    hasher.update(&index.to_le_bytes());

    let mut reader = hasher.finalize_xof();
    let mut output = vec![0_u8; length];

    reader.read(&mut output);

    output
}

fn interleaved_class(sample: usize) -> usize {
    usize::from(deterministic_bytes(1, 0x90, sample as u64)[0] & 1)
}

fn csv_writer(output: &Path) -> Result<BufWriter<File>, String> {
    let file =
        File::create(output).map_err(|error| format!("create {}: {error}", output.display()))?;

    let mut writer = BufWriter::new(file);

    writeln!(writer, "sample,class,nanoseconds").map_err(|error| error.to_string())?;

    Ok(writer)
}

fn parse_optional_usize(value: Option<&String>, default: usize) -> Result<usize, String> {
    match value {
        Some(value) => value
            .parse()
            .map_err(|error| format!("invalid integer {value}: {error}")),
        None => Ok(default),
    }
}
