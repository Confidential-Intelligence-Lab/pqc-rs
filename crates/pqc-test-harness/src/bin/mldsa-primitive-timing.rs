use std::{
    env,
    fs::File,
    hint::black_box,
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};

use pqc_ml_dsa::{
    challenge::sample_in_ball_bytes,
    constants::N,
    encoding::{decode_t1, encode_t1},
    poly::Poly,
    rounding::{high_bits, low_bits, Gamma2},
    sample::sample_eta_poly,
    signing_core::multiply_challenge,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const SAMPLES: usize = 20_000;
const WARMUP: usize = 200;

fn main() {
    if let Err(error) = run() {
        eprintln!("primitive timing screen failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: mldsa-primitive-timing <primitive> <output.csv>".into());
    }

    match args[1].as_str() {
        "ntt" => screen_poly(&args[2], |poly| poly.ntt()),
        "intt" => screen_poly(&args[2], |poly| poly.inv_ntt_to_mont()),
        "sample-eta" => screen_eta(&args[2]),
        "sample-ball" => screen_ball(&args[2]),
        "rounding" => screen_rounding(&args[2]),
        "encoding" => screen_encoding(&args[2]),
        "challenge-mul" => screen_challenge_mul(&args[2]),
        other => Err(format!("unsupported primitive {other}")),
    }
}

fn screen_poly<F>(path: &str, mut operation: F) -> Result<(), String>
where
    F: FnMut(&mut Poly),
{
    for index in 0..WARMUP {
        let class = class(index);
        let mut poly = polynomial(index, class);
        operation(black_box(&mut poly));
        black_box(poly);
    }

    let mut writer = writer(path)?;
    for sample in 0..SAMPLES {
        let class = class(sample);
        let mut poly = polynomial(sample, class);
        let start = Instant::now();
        operation(black_box(&mut poly));
        black_box(poly);
        record(&mut writer, sample, class, start.elapsed().as_nanos())?;
    }
    writer.flush().map_err(|error| error.to_string())
}

fn screen_eta(path: &str) -> Result<(), String> {
    for index in 0..WARMUP {
        let class = class(index);
        let input = seed64(index, class);
        let polynomial =
            sample_eta_poly(&input, index as u16, 2).map_err(|error| format!("{error:?}"))?;
        black_box(polynomial);
    }

    let mut writer = writer(path)?;

    for sample in 0..SAMPLES {
        let class = class(sample);
        let input = seed64(sample, class);

        let start = Instant::now();
        let output =
            sample_eta_poly(&input, sample as u16, 2).map_err(|error| format!("{error:?}"))?;
        black_box(output);

        record(&mut writer, sample, class, start.elapsed().as_nanos())?;
    }

    writer.flush().map_err(|error| error.to_string())
}

fn screen_ball(path: &str) -> Result<(), String> {
    for index in 0..WARMUP {
        let input = seed(index, class(index), 32);
        let polynomial = sample_in_ball_bytes(&input, 39).map_err(|error| format!("{error:?}"))?;
        black_box(polynomial);
    }

    let mut writer = writer(path)?;
    for sample in 0..SAMPLES {
        let class = class(sample);
        let input = seed(sample, class, 32);
        let start = Instant::now();
        let output = sample_in_ball_bytes(&input, 39).map_err(|error| format!("{error:?}"))?;
        black_box(output);
        record(&mut writer, sample, class, start.elapsed().as_nanos())?;
    }
    writer.flush().map_err(|error| error.to_string())
}

fn screen_rounding(path: &str) -> Result<(), String> {
    let gamma2 = Gamma2::QMinusOneOver88;
    let mut writer = writer(path)?;

    for sample in 0..SAMPLES {
        let class = class(sample);
        let poly = polynomial(sample, class);
        let start = Instant::now();
        let mut output = [(0_i32, 0_i32); N];
        for (slot, coefficient) in output.iter_mut().zip(poly.coeffs()) {
            *slot = (
                high_bits(*coefficient, gamma2),
                low_bits(*coefficient, gamma2),
            );
        }
        black_box(output);
        record(&mut writer, sample, class, start.elapsed().as_nanos())?;
    }
    writer.flush().map_err(|error| error.to_string())
}

fn screen_encoding(path: &str) -> Result<(), String> {
    let mut writer = writer(path)?;

    for sample in 0..SAMPLES {
        let class = class(sample);
        let poly = t1_polynomial(sample, class);
        let start = Instant::now();
        let encoded = encode_t1(&poly).map_err(|error| format!("{error:?}"))?;
        let decoded = decode_t1(&encoded).map_err(|error| format!("{error:?}"))?;
        black_box(decoded);
        record(&mut writer, sample, class, start.elapsed().as_nanos())?;
    }
    writer.flush().map_err(|error| error.to_string())
}

fn screen_challenge_mul(path: &str) -> Result<(), String> {
    let mut writer = writer(path)?;

    for sample in 0..SAMPLES {
        let class = class(sample);
        let poly = polynomial(sample, class);
        let challenge = sample_in_ball_bytes(&seed(sample, class, 32), 39)
            .map_err(|error| format!("{error:?}"))?;
        let start = Instant::now();
        let output = multiply_challenge(&challenge, &poly);
        black_box(output);
        record(&mut writer, sample, class, start.elapsed().as_nanos())?;
    }
    writer.flush().map_err(|error| error.to_string())
}

fn polynomial(sample: usize, class: usize) -> Poly {
    let mut coefficients = [0_i32; N];
    if class == 1 {
        let bytes = deterministic::<{ N * 4 }>(0x31, sample as u64);
        for (index, coefficient) in coefficients.iter_mut().enumerate() {
            let offset = index * 4;
            let value = u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            *coefficient = (value % 8_380_417) as i32;
        }
    }
    Poly::from_coeffs(coefficients)
}

fn t1_polynomial(sample: usize, class: usize) -> Poly {
    let mut coefficients = [0_i32; N];
    if class == 1 {
        let bytes = deterministic::<{ N * 2 }>(0x55, sample as u64);
        for (index, coefficient) in coefficients.iter_mut().enumerate() {
            *coefficient =
                i32::from(u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]) & 1023);
        }
    }
    Poly::from_coeffs(coefficients)
}

fn seed64(sample: usize, class: usize) -> [u8; 64] {
    if class == 0 {
        [0_u8; 64]
    } else {
        deterministic::<64>(0x70, sample as u64)
    }
}

fn seed(sample: usize, class: usize, length: usize) -> Vec<u8> {
    if class == 0 {
        vec![0_u8; length]
    } else {
        deterministic::<64>(0x70, sample as u64)[..length].to_vec()
    }
}

fn class(sample: usize) -> usize {
    usize::from(deterministic::<1>(0x90, sample as u64)[0] & 1)
}

fn deterministic<const LENGTH: usize>(domain: u8, index: u64) -> [u8; LENGTH] {
    let mut hasher = Shake256::default();
    hasher.update(b"pqc-rs-stage9f2");
    hasher.update(&[domain]);
    hasher.update(&index.to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; LENGTH];
    reader.read(&mut output);
    output
}

fn writer(path: &str) -> Result<BufWriter<File>, String> {
    let file = File::create(Path::new(path)).map_err(|error| error.to_string())?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "sample,class,nanoseconds").map_err(|error| error.to_string())?;
    Ok(writer)
}

fn record(
    writer: &mut BufWriter<File>,
    sample: usize,
    class: usize,
    elapsed: u128,
) -> Result<(), String> {
    writeln!(writer, "{sample},{class},{elapsed}").map_err(|error| error.to_string())
}
