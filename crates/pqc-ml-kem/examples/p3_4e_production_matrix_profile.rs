use std::hint::black_box;
use std::time::Instant;

use pqc_ml_kem::{
    arithmetic::{N, Q},
    matrix::{expand_matrix, PolyMatrix},
    poly::Poly,
};

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

const RANK: usize = 3;
const STREAM_BYTES: usize = 672;

const WARMUP: usize = 10_000;
const RUNS: usize = 200_000;
const TRIALS: usize = 7;

fn baseline_poly(rho: &[u8; 32], x: u8, y: u8) -> Poly {
    let mut hasher = Shake128::default();
    hasher.update(rho);
    hasher.update(&[x, y]);

    let mut reader = hasher.finalize_xof();

    let mut stream = [0u8; STREAM_BYTES];
    reader.read(&mut stream);

    let mut coeffs = [0i16; N];
    let mut coeff_index = 0usize;
    let mut pos = 0usize;

    while coeff_index < N && pos + 3 <= stream.len() {
        let d1 = u16::from(stream[pos]) | ((u16::from(stream[pos + 1]) & 0x0f) << 8);

        let d2 = (u16::from(stream[pos + 1]) >> 4) | (u16::from(stream[pos + 2]) << 4);

        pos += 3;

        if d1 < Q as u16 {
            coeffs[coeff_index] = d1 as i16;
            coeff_index += 1;
        }

        if coeff_index < N && d2 < Q as u16 {
            coeffs[coeff_index] = d2 as i16;
            coeff_index += 1;
        }
    }

    while coeff_index < N {
        coeffs[coeff_index] = pqc_ml_kem::arithmetic::reduce(coeff_index as i32);
        coeff_index += 1;
    }

    Poly::from_coefficients(coeffs)
}

fn baseline_matrix(rho: &[u8; 32]) -> PolyMatrix {
    let mut matrix = PolyMatrix::zero(RANK);

    for row in 0..RANK {
        for col in 0..RANK {
            matrix.set(row, col, baseline_poly(rho, col as u8, row as u8));
        }
    }

    matrix
}

fn derive_rho(i: u64) -> [u8; 32] {
    let mut rho = [0u8; 32];

    rho[0..8].copy_from_slice(&i.to_le_bytes());

    rho[8..16].copy_from_slice(&i.wrapping_mul(0x9e3779b97f4a7c15).to_le_bytes());

    rho[16..24].copy_from_slice(&i.rotate_left(17).to_le_bytes());

    rho[24..32].copy_from_slice(&i.wrapping_add(0xd1b54a32d192ed03).to_le_bytes());

    rho
}

fn benchmark_baseline() -> f64 {
    let start = Instant::now();

    for i in 0..RUNS {
        let rho = derive_rho(i as u64);

        black_box(baseline_matrix(black_box(&rho)));
    }

    start.elapsed().as_nanos() as f64 / RUNS as f64
}

fn benchmark_production() -> f64 {
    let start = Instant::now();

    for i in 0..RUNS {
        let rho = derive_rho(i as u64);

        black_box(expand_matrix(RANK, black_box(&rho), false));
    }

    start.elapsed().as_nanos() as f64 / RUNS as f64
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    values[values.len() / 2]
}

fn main() {
    println!("P3.4e ML-KEM-768 production matrix benchmark");
    println!("============================================");

    const CORRECTNESS_SEEDS: usize = 10_000;

    for i in 0..CORRECTNESS_SEEDS {
        let rho = derive_rho(i as u64);

        let old = baseline_matrix(&rho);
        let new = expand_matrix(RANK, &rho, false);

        assert_eq!(old, new, "production mismatch at seed {i}");
    }

    println!("correctness_seeds={CORRECTNESS_SEEDS}");
    println!("old_vs_new=PASS");

    for i in 0..WARMUP {
        let rho = derive_rho(i as u64);

        black_box(baseline_matrix(black_box(&rho)));

        black_box(expand_matrix(RANK, black_box(&rho), false));
    }

    let mut baseline_trials = [0.0f64; TRIALS];
    let mut production_trials = [0.0f64; TRIALS];

    for trial in 0..TRIALS {
        if trial % 2 == 0 {
            baseline_trials[trial] = benchmark_baseline();
            production_trials[trial] = benchmark_production();
        } else {
            production_trials[trial] = benchmark_production();
            baseline_trials[trial] = benchmark_baseline();
        }

        println!(
            "trial={},baseline_ns={:.3},production_ns={:.3},speedup={:.4}",
            trial + 1,
            baseline_trials[trial],
            production_trials[trial],
            baseline_trials[trial] / production_trials[trial],
        );
    }

    let baseline_median = median(&mut baseline_trials);

    let production_median = median(&mut production_trials);

    let speedup = baseline_median / production_median;

    let reduction = 100.0 * (baseline_median - production_median) / baseline_median;

    println!();
    println!("summary");
    println!("-------");

    println!("baseline_median_ns={baseline_median:.3}");

    println!("production_median_ns={production_median:.3}");

    println!("median_speedup={speedup:.4}x");

    println!("median_latency_reduction_percent={reduction:.3}");

    if production_median < baseline_median {
        println!("PRODUCTION_STREAMING_FASTER=YES");
    } else {
        println!("PRODUCTION_STREAMING_FASTER=NO");
    }

    println!("P3_4E_PRODUCTION_BENCHMARK=PASS");
}
