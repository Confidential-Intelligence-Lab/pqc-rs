//! HAETAE 1.2.0 challenge transcript and polynomial generation.
//!
//! Preserves the authenticated C reference's fixed 288-byte
//! highbits stride across all parameter sets.

use crate::params::N;
use crate::poly::Poly;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const HIGHBITS_STRIDE: usize = 288;
const LSB_BYTES: usize = N / 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeError {
    UnsupportedMode,
    IncorrectDimensions,
    InvalidHighbits,
}

fn dimensions(mode: u8) -> Result<(usize, usize), ChallengeError> {
    match mode {
        2 => Ok((2, 58)),
        3 => Ok((3, 80)),
        5 => Ok((4, 128)),
        _ => Err(ChallengeError::UnsupportedMode),
    }
}

/// Serialize the highbits and LSB polynomial exactly as the C reference.
///
/// For HAETAE-2/3, each polynomial occupies a 288-byte slot,
/// although only its first 256 bytes contain highbits.
pub fn pack_challenge_transcript(
    mode: u8,
    highbits: &[Poly],
    lsb: &Poly,
) -> Result<Vec<u8>, ChallengeError> {
    let (k, _) = dimensions(mode)?;
    if highbits.len() != k {
        return Err(ChallengeError::IncorrectDimensions);
    }

    let mut transcript = vec![0_u8; k * HIGHBITS_STRIDE + LSB_BYTES];

    for (poly_index, polynomial) in highbits.iter().enumerate() {
        let offset = poly_index * HIGHBITS_STRIDE;

        if mode != 5 {
            for (index, &coefficient) in polynomial.coeffs.iter().enumerate() {
                // The C reference casts to uint8_t.
                transcript[offset + index] = coefficient as u8;
            }
        } else {
            for block in 0..(N / 8) {
                let mut packed = 0_u128;
                for bit in 0..8 {
                    let coefficient = polynomial.coeffs[block * 8 + bit];
                    if !(0..512).contains(&coefficient) {
                        return Err(ChallengeError::InvalidHighbits);
                    }
                    packed |= (coefficient as u128) << (9 * bit);
                }
                for byte in 0..9 {
                    transcript[offset + block * 9 + byte] = ((packed >> (8 * byte)) & 0xff) as u8;
                }
            }
        }
    }

    let lsb_offset = k * HIGHBITS_STRIDE;
    for (index, &coefficient) in lsb.coeffs.iter().enumerate() {
        transcript[lsb_offset + index / 8] |= ((coefficient & 1) as u8) << (index % 8);
    }

    Ok(transcript)
}

/// Derive the HAETAE challenge polynomial from the serialized
/// transcript and the first 32 bytes of the message digest.
pub fn sample_challenge(
    mode: u8,
    transcript: &[u8],
    mu: &[u8; 32],
) -> Result<Poly, ChallengeError> {
    let (k, tau) = dimensions(mode)?;
    if transcript.len() != k * HIGHBITS_STRIDE + LSB_BYTES {
        return Err(ChallengeError::IncorrectDimensions);
    }

    let mut shake = Shake256::default();
    shake.update(transcript);
    shake.update(mu);
    let mut reader = shake.finalize_xof();

    let mut challenge = Poly::default();

    if mode != 5 {
        // The C reference consumes successive SHAKE256 blocks,
        // rejecting bytes larger than the current shuffle index.
        for i in (N - tau)..N {
            let b = loop {
                let mut byte = [0_u8; 1];
                reader.read(&mut byte);
                if usize::from(byte[0]) <= i {
                    break usize::from(byte[0]);
                }
            };
            challenge.coeffs[i] = challenge.coeffs[b];
            challenge.coeffs[b] = 1;
        }
    } else {
        let mut bytes = [0_u8; 32];
        reader.read(&mut bytes);

        let weight: u32 = bytes.iter().map(|b| b.count_ones()).sum();

        // Reproduce C's unsigned 32-bit arithmetic.
        let cond = 128_u32.wrapping_sub(weight);
        let initial_mask = (cond >> 8) as u8;
        let w0 = 0_u8.wrapping_sub(bytes[0] & 1);
        let conditional_mask = 0_u8.wrapping_sub((cond != 0) as u8);
        let mask = w0 ^ (conditional_mask & (initial_mask ^ w0));

        for (index, byte) in bytes.iter().enumerate() {
            let transformed = *byte ^ mask;
            for bit in 0..8 {
                challenge.coeffs[index * 8 + bit] = i32::from((transformed >> bit) & 1);
            }
        }
    }

    Ok(challenge)
}

#[cfg(test)]
mod authenticated_challenge_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn fixture(mode: u8) -> &'static str {
        match mode {
            2 => include_str!("challenge_fixtures/mode2.txt"),
            3 => include_str!("challenge_fixtures/mode3.txt"),
            5 => include_str!("challenge_fixtures/mode5.txt"),
            _ => panic!("unsupported mode"),
        }
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                    .expect("hex byte")
            })
            .collect()
    }

    fn parse_poly(encoded: &str) -> Poly {
        let coefficients: Vec<i32> = encoded
            .split(',')
            .map(|item| item.parse::<i32>().expect("coefficient"))
            .collect();
        let array: [i32; N] = coefficients
            .try_into()
            .expect("256 polynomial coefficients");
        Poly::new(array)
    }

    fn cases(contents: &str) -> Vec<BTreeMap<String, String>> {
        let mut result = Vec::new();
        let mut current: Option<BTreeMap<String, String>> = None;

        for line in contents.lines() {
            if line == "BEGIN_CASE" {
                assert!(current.is_none());
                current = Some(BTreeMap::new());
            } else if line == "END_CASE" {
                result.push(current.take().expect("case"));
            } else if let Some(ref mut record) = current {
                let (key, value) = line.split_once('=').expect("fixture field");
                assert!(record.insert(key.into(), value.into()).is_none());
            }
        }

        assert!(current.is_none());
        assert_eq!(result.len(), 5);
        result
    }

    #[test]
    fn authenticated_c_transcripts_and_challenges() {
        for mode in [2_u8, 3, 5] {
            let (k, _) = dimensions(mode).expect("mode");
            for record in cases(fixture(mode)) {
                let highbits: Vec<Poly> = (0..k)
                    .map(|index| parse_poly(&record[&format!("HIGHBITS_{index}")]))
                    .collect();
                let lsb = parse_poly(&record["LSB"]);

                let transcript =
                    pack_challenge_transcript(mode, &highbits, &lsb).expect("transcript");

                assert_eq!(
                    transcript,
                    decode_hex(&record["TRANSCRIPT"]),
                    "transcript mismatch mode={mode} case={}",
                    record["CASE"]
                );

                let mu: [u8; 32] = decode_hex(&record["MU"]).try_into().expect("32-byte mu");

                let challenge = sample_challenge(mode, &transcript, &mu).expect("challenge");

                assert_eq!(
                    challenge,
                    parse_poly(&record["CHALLENGE"]),
                    "challenge mismatch mode={mode} case={}",
                    record["CASE"]
                );
            }
        }
    }

    #[test]
    fn diagnose_sparse_challenge_mismatch() {
        for mode in [2_u8, 3] {
            let records = cases(fixture(mode));
            let (k, _) = dimensions(mode).expect("mode");

            for record in records {
                let highbits: Vec<Poly> = (0..k)
                    .map(|index| parse_poly(&record[&format!("HIGHBITS_{index}")]))
                    .collect();

                let lsb = parse_poly(&record["LSB"]);
                let transcript =
                    pack_challenge_transcript(mode, &highbits, &lsb).expect("transcript");

                let mu: [u8; 32] = decode_hex(&record["MU"]).try_into().expect("mu");

                let actual = sample_challenge(mode, &transcript, &mu).expect("challenge");

                let expected = parse_poly(&record["CHALLENGE"]);

                let mismatches: Vec<usize> = (0..N)
                    .filter(|&i| actual.coeffs[i] != expected.coeffs[i])
                    .collect();

                let actual_weight: i32 = actual.coeffs.iter().sum();
                let expected_weight: i32 = expected.coeffs.iter().sum();

                println!(
                    "MODE={mode} CASE={} ACTUAL_WEIGHT={} \
                     EXPECTED_WEIGHT={} MISMATCH_COUNT={} \
                     MISMATCH_POSITIONS={mismatches:?}",
                    record["CASE"],
                    actual_weight,
                    expected_weight,
                    mismatches.len()
                );

                assert_eq!(actual_weight, expected_weight, "challenge weight mismatch");
            }
        }
    }

    #[test]
    fn rejects_invalid_dimensions_and_modes() {
        let empty = Poly::default();
        assert_eq!(
            pack_challenge_transcript(9, &[], &empty),
            Err(ChallengeError::UnsupportedMode)
        );
        assert_eq!(
            pack_challenge_transcript(2, &[], &empty),
            Err(ChallengeError::IncorrectDimensions)
        );
        assert_eq!(
            sample_challenge(2, &[], &[0; 32]),
            Err(ChallengeError::IncorrectDimensions)
        );
    }
}
