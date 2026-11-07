// SPDX-License-Identifier: MIT
//! HAETAE 1.2.0 polynomial sampling.
//!
//! These routines reproduce the reference's SHAKE stream and rejection
//! sampling behavior. They are not yet integrated into key generation.

use crate::poly::Poly;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake256,
};

const N: usize = 256;
const Q: u16 = 64513;
const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

fn reject_uniform(output: &mut [i32; N], count: &mut usize, bytes: &[u8]) {
    for pair in bytes.chunks_exact(2) {
        if *count == N {
            break;
        }

        let candidate = u16::from_le_bytes([pair[0], pair[1]]);

        if candidate < Q {
            output[*count] = i32::from(candidate);
            *count += 1;
        }
    }
}

fn mod3(mut value: u32) -> i32 {
    value = (value >> 4) + (value & 15);
    value = (value >> 2) + (value & 3);
    value = (value >> 2) + (value & 3);
    value = (value >> 2) + (value & 3);
    (value as i32) - 3 * ((value >> 1) as i32)
}

fn mod3_leq26(mut value: u32) -> i32 {
    value = (value >> 4) + (value & 15);
    value = (value >> 2) + (value & 3);
    value = (value >> 2) + (value & 3);
    (value as i32) - 3 * ((value >> 1) as i32)
}

fn mod3_leq8(mut value: u32) -> i32 {
    value = (value >> 2) + (value & 3);
    value = (value >> 2) + (value & 3);
    (value as i32) - 3 * ((value >> 1) as i32)
}

fn reject_eta(output: &mut [i32; N], count: &mut usize, bytes: &[u8]) {
    for &byte in bytes {
        if *count == N {
            break;
        }

        let mut value = u32::from(byte);

        if value >= 243 {
            continue;
        }

        output[*count] = mod3(value);
        *count += 1;

        if *count == N {
            break;
        }

        value = (value * 171) >> 9;
        output[*count] = mod3(value);
        *count += 1;

        if *count == N {
            break;
        }

        value = (value * 171) >> 9;
        output[*count] = mod3_leq26(value);
        *count += 1;

        if *count == N {
            break;
        }

        value = (value * 171) >> 9;
        output[*count] = mod3_leq8(value);
        *count += 1;

        if *count == N {
            break;
        }

        value = (value * 171) >> 9;
        output[*count] = (value as i32) - 3 * ((value >> 1) as i32);
        *count += 1;
    }
}

/// Sample a polynomial uniformly in `[0, Q)` using SHAKE128.
///
/// Input: `seed || nonce.to_le_bytes()`.
pub fn uniform(seed: &[u8; 32], nonce: u16) -> Poly {
    let mut shake = Shake128::default();
    shake.update(seed);
    shake.update(&nonce.to_le_bytes());

    let mut reader = shake.finalize_xof();
    let mut output = [0_i32; N];
    let mut count = 0;

    // Reference initial squeeze: four SHAKE128 blocks.
    let mut buffer = [0_u8; 4 * SHAKE128_RATE];
    reader.read(&mut buffer);
    reject_uniform(&mut output, &mut count, &buffer);

    while count < N {
        let mut block = [0_u8; SHAKE128_RATE];
        reader.read(&mut block);
        reject_uniform(&mut output, &mut count, &block);
    }

    Poly::new(output)
}

/// Sample a polynomial in `[-1, 1]` using SHAKE256.
///
/// Input: `seed || nonce.to_le_bytes()`.
pub fn uniform_eta(seed: &[u8; 64], nonce: u16) -> Poly {
    let mut shake = Shake256::default();
    shake.update(seed);
    shake.update(&nonce.to_le_bytes());

    let mut reader = shake.finalize_xof();
    let mut output = [0_i32; N];
    let mut count = 0;

    // Reference initial squeeze: one SHAKE256 block.
    let mut block = [0_u8; SHAKE256_RATE];

    reader.read(&mut block);
    reject_eta(&mut output, &mut count, &block);

    while count < N {
        reader.read(&mut block);
        reject_eta(&mut output, &mut count, &block);
    }

    Poly::new(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_is_deterministic_and_bounded() {
        let seed = [7_u8; 32];

        let a = uniform(&seed, 0);
        let b = uniform(&seed, 0);
        let c = uniform(&seed, 1);

        assert_eq!(a, b);
        assert_ne!(a, c);

        assert!(a.coeffs.iter().all(|&x| (0..i32::from(Q)).contains(&x)));
    }

    #[test]
    fn eta_is_deterministic_and_bounded() {
        let seed = [11_u8; 64];

        let a = uniform_eta(&seed, 0);
        let b = uniform_eta(&seed, 0);
        let c = uniform_eta(&seed, 1);

        assert_eq!(a, b);
        assert_ne!(a, c);

        assert!(a.coeffs.iter().all(|&x| (-1..=1).contains(&x)));
    }

    #[test]
    fn uniform_rejection_boundaries() {
        let mut output = [0_i32; N];
        let mut count = 0;

        reject_uniform(&mut output, &mut count, &[0, 0, 0, 252, 1, 252, 255, 255]);

        assert_eq!(count, 2);
        assert_eq!(&output[..2], &[0, 64512]);
    }

    #[test]
    fn eta_rejection_boundaries() {
        let mut output = [0_i32; N];
        let mut count = 0;

        reject_eta(&mut output, &mut count, &[243, 255]);

        assert_eq!(count, 0);

        reject_eta(&mut output, &mut count, &[0]);

        assert_eq!(count, 5);
        assert_eq!(&output[..5], &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn nonce_encoding_changes_stream() {
        let seed = [0_u8; 32];

        assert_ne!(uniform(&seed, 1), uniform(&seed, 256));
        assert_ne!(uniform(&seed, 0), uniform(&seed, u16::MAX));
    }
}
