//! Reference-compatible SMAUG-T bounded-index sampling.
//!
//! Experimental implementation. Not yet constant-time audited.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::N;

pub const HWT_RANDOM_BYTES: usize = 616;
pub const HWT_RANDOM_WORDS: usize = HWT_RANDOM_BYTES / 2;
pub const HWT_SIGN_BYTES: usize = N / 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SamplingError {
    RandomnessExhausted,
}

/// Generate the exact SHAKE256 stream consumed by the reference HWT sampler.
///
/// `extended_seed` is the 32-byte secret seed followed by two domain bytes.
/// The reader must remain continuous across the randomness and sign buffers.
pub fn hwt_randomness(extended_seed: &[u8; 34]) -> ([u16; HWT_RANDOM_WORDS], [u8; HWT_SIGN_BYTES]) {
    let mut shake = Shake256::default();
    shake.update(extended_seed);

    let mut reader = shake.finalize_xof();

    let mut bytes = [0u8; HWT_RANDOM_BYTES];
    reader.read(&mut bytes);

    let mut words = [0u16; HWT_RANDOM_WORDS];
    for (word, pair) in words.iter_mut().zip(bytes.chunks_exact(2)) {
        *word = u16::from_le_bytes([pair[0], pair[1]]);
    }

    let mut signs = [0u8; HWT_SIGN_BYTES];
    reader.read(&mut signs);

    (words, signs)
}

/// Reproduce SMAUG-T RejSampleMod, returning 256 bounded indices.
///
/// The reference starts with 256 primary words and consumes additional
/// words only when a multiply-high candidate falls in its rejection range.
pub fn rejection_sample_indices(
    randomness: &[u16; HWT_RANDOM_WORDS],
) -> Result<[u16; N], SamplingError> {
    let mut indices = [0u16; N];
    let mut next = N;

    for (i, index) in indices.iter_mut().enumerate() {
        let modulus = (N - i) as u32;
        let threshold = (1u32 << 16) % modulus;

        let mut product = u32::from(randomness[i]) * modulus;

        while (product & 0xffff) < threshold {
            if next >= HWT_RANDOM_WORDS {
                return Err(SamplingError::RandomnessExhausted);
            }

            product = u32::from(randomness[next]) * modulus;
            next += 1;
        }

        *index = (product >> 16) as u16;
    }

    Ok(indices)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_shake_expansion() {
        let seed = [0u8; 34];
        assert_eq!(hwt_randomness(&seed), hwt_randomness(&seed));
    }

    #[test]
    fn domain_separation_changes_randomness() {
        let seed_a = [0u8; 34];
        let mut seed_b = seed_a;
        seed_b[32] = 1;

        assert_ne!(hwt_randomness(&seed_a), hwt_randomness(&seed_b));
    }

    #[test]
    fn indices_respect_decreasing_bounds() {
        for pattern in 0..3 {
            let mut seed = [0u8; 34];
            for (i, byte) in seed[..32].iter_mut().enumerate() {
                *byte = match pattern {
                    0 => 0,
                    1 => 255,
                    _ => i as u8,
                };
            }

            let (randomness, _) = hwt_randomness(&seed);
            let indices = rejection_sample_indices(&randomness)
                .expect("deterministic seed must have enough randomness");

            for (i, &index) in indices.iter().enumerate() {
                assert!(usize::from(index) < N - i);
            }
        }
    }

    #[test]
    fn zero_words_exhaust_rejection_budget() {
        // Zero is rejected whenever 65536 % (N - i) != 0.
        // With only 52 spare words, an all-zero stream exhausts
        // the reference sampler's fixed randomness budget.
        let randomness = [0u16; HWT_RANDOM_WORDS];

        assert_eq!(
            rejection_sample_indices(&randomness),
            Err(SamplingError::RandomnessExhausted)
        );
    }

    #[test]
    fn exhaustion_is_reported() {
        // At modulus 255, 65536 % 255 = 1.
        // A zero word is rejected, exhausting the 52 spare words.
        let mut randomness = [u16::MAX; HWT_RANDOM_WORDS];
        randomness[1] = 0;
        randomness[N..].fill(0);

        assert_eq!(
            rejection_sample_indices(&randomness),
            Err(SamplingError::RandomnessExhausted)
        );
    }
}
