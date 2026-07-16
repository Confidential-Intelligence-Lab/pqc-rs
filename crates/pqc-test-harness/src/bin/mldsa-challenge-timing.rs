use pqc_ml_dsa::{
    challenge::sample_in_ball_bytes, constants::N, poly::Poly, signing_core::multiply_challenge,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::{
    env,
    fs::File,
    hint::black_box,
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};
const SAMPLES: usize = 30_000;
const WARMUP: usize = 500;
const TAU: usize = 39;
fn main() {
    if let Err(e) = run() {
        eprintln!("challenge timing failed: {e}");
        std::process::exit(1)
    }
}
fn run() -> Result<(), String> {
    let a: Vec<String> = env::args().collect();
    if a.len() != 3 {
        return Err("usage: <experiment> <output.csv>".into());
    }
    match a[1].as_str() {
        "fixed-challenge" => fixed_challenge(Path::new(&a[2])),
        "varying-challenge" => varying_challenge(Path::new(&a[2])),
        "matched-distribution" => matched_distribution(Path::new(&a[2])),
        x => Err(format!("unsupported experiment {x}")),
    }
}
fn fixed_challenge(p: &Path) -> Result<(), String> {
    let c = challenge(&[0x42; 32])?;
    for i in 0..WARMUP {
        let k = class(i);
        black_box(multiply_challenge(&c, &poly_for_class(i, k)));
    }
    let mut w = writer(p)?;
    for i in 0..SAMPLES {
        let k = class(i);
        let poly = poly_for_class(i, k);
        let s = Instant::now();
        black_box(multiply_challenge(black_box(&c), black_box(&poly)));
        record(&mut w, i, k, s.elapsed().as_nanos())?;
    }
    w.flush().map_err(|e| e.to_string())
}
fn varying_challenge(p: &Path) -> Result<(), String> {
    let poly = varying_poly(0x61, 0);
    for i in 0..WARMUP {
        let k = class(i);
        let c = challenge_for_class(i, k)?;
        black_box(multiply_challenge(&c, &poly));
    }
    let mut w = writer(p)?;
    for i in 0..SAMPLES {
        let k = class(i);
        let c = challenge_for_class(i, k)?;
        let s = Instant::now();
        black_box(multiply_challenge(black_box(&c), black_box(&poly)));
        record(&mut w, i, k, s.elapsed().as_nanos())?;
    }
    w.flush().map_err(|e| e.to_string())
}
fn matched_distribution(p: &Path) -> Result<(), String> {
    for i in 0..WARMUP {
        let k = class(i);
        let c = matched_challenge(i, k)?;
        let poly = matched_poly(i, k);
        black_box(multiply_challenge(&c, &poly));
    }
    let mut w = writer(p)?;
    for i in 0..SAMPLES {
        let k = class(i);
        let c = matched_challenge(i, k)?;
        let poly = matched_poly(i, k);
        let s = Instant::now();
        black_box(multiply_challenge(black_box(&c), black_box(&poly)));
        record(&mut w, i, k, s.elapsed().as_nanos())?;
    }
    w.flush().map_err(|e| e.to_string())
}
fn poly_for_class(i: usize, k: usize) -> Poly {
    if k == 0 {
        let mut a = [0i32; N];
        for (j, x) in a.iter_mut().enumerate() {
            *x = ((j as i32 * 17) + 3) % 8_380_417;
        }
        Poly::from_coeffs(a)
    } else {
        varying_poly(0x73, i as u64)
    }
}
fn matched_poly(i: usize, k: usize) -> Poly {
    varying_poly(if k == 0 { 0x81 } else { 0x82 }, i as u64)
}
fn varying_poly(d: u8, i: u64) -> Poly {
    let b = bytes::<{ N * 4 }>(d, i);
    let mut a = [0i32; N];
    for (j, x) in a.iter_mut().enumerate() {
        let o = j * 4;
        *x = (u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) % 8_380_417) as i32;
    }
    Poly::from_coeffs(a)
}
fn challenge(seed: &[u8; 32]) -> Result<Poly, String> {
    sample_in_ball_bytes(seed, TAU).map_err(|e| format!("{e:?}"))
}
fn challenge_for_class(i: usize, k: usize) -> Result<Poly, String> {
    let s = if k == 0 {
        [0x11; 32]
    } else {
        bytes::<32>(0x91, i as u64)
    };
    challenge(&s)
}
fn matched_challenge(i: usize, k: usize) -> Result<Poly, String> {
    challenge(&bytes::<32>(if k == 0 { 0xa1 } else { 0xa2 }, i as u64))
}
fn class(i: usize) -> usize {
    usize::from(bytes::<1>(0xb0, i as u64)[0] & 1)
}
fn bytes<const L: usize>(d: u8, i: u64) -> [u8; L] {
    let mut h = Shake256::default();
    h.update(b"pqc-rs-stage9f2a");
    h.update(&[d]);
    h.update(&i.to_le_bytes());
    let mut r = h.finalize_xof();
    let mut o = [0u8; L];
    r.read(&mut o);
    o
}
fn writer(p: &Path) -> Result<BufWriter<File>, String> {
    let mut w = BufWriter::new(File::create(p).map_err(|e| e.to_string())?);
    writeln!(w, "sample,class,nanoseconds").map_err(|e| e.to_string())?;
    Ok(w)
}
fn record(w: &mut BufWriter<File>, i: usize, k: usize, n: u128) -> Result<(), String> {
    writeln!(w, "{i},{k},{n}").map_err(|e| e.to_string())
}
