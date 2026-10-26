//! SMAUG-T deterministic ephemeral-secret sampling.
//!
//! Experimental, reference-oriented implementation.
//! No production security or side-channel assurance is claimed.

use crate::{Parameters, N};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EphemeralError {
    InvalidParameters,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sampler {
    SparseCbd1,
    Cbd,
    SparseCbd2,
}

fn sampler_for(parameters: &Parameters) -> Result<(Sampler, usize), EphemeralError> {
    match (parameters.k, parameters.q, parameters.p, parameters.p_prime) {
        (2, 1024, 256, 32) | (2, 1024, 256, 8) => Ok((Sampler::SparseCbd1, 96)),
        (3, 2048, 512, 16) => Ok((Sampler::Cbd, 64)),
        (4, 2048, 512, 128) => Ok((Sampler::SparseCbd2, 128)),
        _ => Err(EphemeralError::InvalidParameters),
    }
}

/// Decode a SHAKE256 byte stream into a ternary ephemeral polynomial.
///
/// The returned coefficients are signed integers in {-1, 0, 1}.
fn sample_poly(bytes: &[u8], sampler: Sampler) -> [i16; N] {
    let mut result = [0i16; N];

    match sampler {
        Sampler::SparseCbd1 => {
            assert_eq!(bytes.len(), 96);

            for (block, chunk) in bytes.chunks_exact(3).enumerate() {
                let t =
                    u32::from(chunk[0]) | (u32::from(chunk[1]) << 8) | (u32::from(chunk[2]) << 16);

                let d = (t & (t >> 1)) & 0x0024_9249;
                let s = (t >> 2) & 0x0024_9249;

                for j in 0..8 {
                    let enabled = ((d >> (3 * j)) & 1) as i16;
                    let sign = ((s >> (3 * j)) & 1) as i16;
                    result[8 * block + j] = enabled * (1 - 2 * sign);
                }
            }
        }

        Sampler::Cbd => {
            assert_eq!(bytes.len(), 64);

            for (block, chunk) in bytes.chunks_exact(4).enumerate() {
                let t = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

                for j in 0..16 {
                    let a = ((t >> (2 * j)) & 1) as i16;
                    let b = ((t >> (2 * j + 1)) & 1) as i16;
                    result[16 * block + j] = a - b;
                }
            }
        }

        Sampler::SparseCbd2 => {
            assert_eq!(bytes.len(), 128);

            for (block, chunk) in bytes.chunks_exact(4).enumerate() {
                let t = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

                let d = ((t | (t >> 1)) & (t >> 2)) & 0x1111_1111;
                let s = (t >> 3) & 0x1111_1111;

                for j in 0..8 {
                    let enabled = ((d >> (4 * j)) & 1) as i16;
                    let sign = ((s >> (4 * j)) & 1) as i16;
                    result[8 * block + j] = enabled * (1 - 2 * sign);
                }
            }
        }
    }

    result
}

/// Expand a 32-byte seed into K ephemeral ternary polynomials.
///
/// Each polynomial is sampled from SHAKE256(seed || polynomial_index),
/// matching the reference domain separation.
pub fn expand_r(seed: &[u8; 32], parameters: &Parameters) -> Result<Vec<[i16; N]>, EphemeralError> {
    let (sampler, byte_count) = sampler_for(parameters)?;
    let mut result = Vec::with_capacity(parameters.k);

    for index in 0..parameters.k {
        let mut input = [0u8; 33];
        input[..32].copy_from_slice(seed);
        input[32] = index as u8;

        let mut shake = Shake256::default();
        shake.update(&input);

        let mut reader = shake.finalize_xof();
        let mut bytes = vec![0u8; byte_count];
        reader.read(&mut bytes);

        result.push(sample_poly(&bytes, sampler));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER};

    #[test]
    fn all_modes_have_correct_shapes_and_ternary_coefficients() {
        for parameters in [SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER] {
            let polynomials = expand_r(&[0u8; 32], &parameters).unwrap();
            assert_eq!(polynomials.len(), parameters.k);

            for poly in polynomials {
                assert!(poly.iter().all(|&x| (-1..=1).contains(&x)));
            }
        }
    }

    #[test]
    fn deterministic_and_seed_sensitive() {
        for parameters in [SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER] {
            let first = expand_r(&[0u8; 32], &parameters).unwrap();
            let repeated = expand_r(&[0u8; 32], &parameters).unwrap();
            let changed = expand_r(&[1u8; 32], &parameters).unwrap();

            assert_eq!(first, repeated);
            assert_ne!(first, changed);
        }
    }

    #[test]
    fn mode1_and_timer_have_identical_ephemeral_sampling() {
        let seed = [0xA5u8; 32];
        assert_eq!(
            expand_r(&seed, &SMAUG_T128).unwrap(),
            expand_r(&seed, &TIMER).unwrap()
        );
    }

    #[test]
    fn rejects_invalid_parameters() {
        let invalid = Parameters {
            k: 5,
            q: 1024,
            p: 256,
            p_prime: 32,
        };

        assert_eq!(
            expand_r(&[0u8; 32], &invalid),
            Err(EphemeralError::InvalidParameters)
        );
    }

    #[test]
    fn sampler_bit_patterns() {
        let zero96 = [0u8; 96];
        let zero64 = [0u8; 64];
        let zero128 = [0u8; 128];

        assert_eq!(sample_poly(&zero96, Sampler::SparseCbd1), [0; N]);
        assert_eq!(sample_poly(&zero64, Sampler::Cbd), [0; N]);
        assert_eq!(sample_poly(&zero128, Sampler::SparseCbd2), [0; N]);

        let ones96 = [0xffu8; 96];
        let ones64 = [0xffu8; 64];
        let ones128 = [0xffu8; 128];

        assert!(sample_poly(&ones96, Sampler::SparseCbd1)
            .iter()
            .all(|&x| x == -1));
        assert!(sample_poly(&ones64, Sampler::Cbd).iter().all(|&x| x == 0));
        assert!(sample_poly(&ones128, Sampler::SparseCbd2)
            .iter()
            .all(|&x| x == -1));
    }
}
