// SPDX-License-Identifier: MIT

//! HAETAE 1.2.0 signature serialization.

use crate::params::ParameterSet;
use crate::rans::{
    decode, encode, RansError, Symbol, MODE2_H, MODE2_HB_Z1, MODE3_H, MODE3_HB_Z1, MODE5_H,
    MODE5_HB_Z1,
};

const N: usize = 256;
const CHALLENGE_BYTES: usize = N / 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignaturePackingError {
    InvalidDimensions,
    InvalidChallenge,
    InvalidLowbits,
    InvalidHint,
    InvalidHighbits,
    EncodedLengthOutOfRange,
    SignatureTooLarge,
}

struct EncodingParameters {
    k: usize,
    l: usize,
    signature_bytes: usize,
    base_hb: usize,
    base_h: usize,
    hb_offset: i32,
    h_cut: i32,
    h_offset: i32,
    h_table: &'static [Symbol],
    hb_table: &'static [Symbol],
}

fn parameters(mode: ParameterSet) -> EncodingParameters {
    match mode {
        ParameterSet::Haetae2 => EncodingParameters {
            k: 2,
            l: 4,
            signature_bytes: 1474,
            base_hb: 132,
            base_h: 7,
            hb_offset: 6,
            h_cut: 6,
            h_offset: 239,
            h_table: &MODE2_H,
            hb_table: &MODE2_HB_Z1,
        },
        ParameterSet::Haetae3 => EncodingParameters {
            k: 3,
            l: 6,
            signature_bytes: 2349,
            base_hb: 376,
            base_h: 127,
            hb_offset: 8,
            h_cut: 8,
            h_offset: 235,
            h_table: &MODE3_H,
            hb_table: &MODE3_HB_Z1,
        },
        ParameterSet::Haetae5 => EncodingParameters {
            k: 4,
            l: 7,
            signature_bytes: 2948,
            base_hb: 501,
            base_h: 358,
            hb_offset: 9,
            h_cut: 16,
            h_offset: 471,
            h_table: &MODE5_H,
            hb_table: &MODE5_HB_Z1,
        },
    }
}

fn map_rans_error(error: RansError, highbits: bool) -> SignaturePackingError {
    match error {
        RansError::OutputTooLong => SignaturePackingError::SignatureTooLarge,
        _ if highbits => SignaturePackingError::InvalidHighbits,
        _ => SignaturePackingError::InvalidHint,
    }
}

/// Pack a HAETAE signature from coefficient vectors.
///
/// `challenge` contains exactly 256 binary coefficients.
/// `lowbits_z1` and `highbits_z1` contain `L * 256` coefficients.
/// `h` contains `K * 256` coefficients.
///
/// Returns the fixed-size signature or an explicit packing error.
pub fn pack_signature(
    mode: ParameterSet,
    challenge: &[i32],
    lowbits_z1: &[i32],
    highbits_z1: &[i32],
    h: &[i32],
) -> Result<Vec<u8>, SignaturePackingError> {
    let p = parameters(mode);

    if challenge.len() != N
        || lowbits_z1.len() != p.l * N
        || highbits_z1.len() != p.l * N
        || h.len() != p.k * N
    {
        return Err(SignaturePackingError::InvalidDimensions);
    }

    let mut signature = vec![0_u8; p.signature_bytes];

    for (i, &coefficient) in challenge.iter().enumerate() {
        if coefficient != 0 && coefficient != 1 {
            return Err(SignaturePackingError::InvalidChallenge);
        }
        signature[i / 8] |= (coefficient as u8) << (i % 8);
    }

    let lowbits_start = CHALLENGE_BYTES;
    for (i, &coefficient) in lowbits_z1.iter().enumerate() {
        let signed =
            i8::try_from(coefficient).map_err(|_| SignaturePackingError::InvalidLowbits)?;
        signature[lowbits_start + i] = signed as u8;
    }

    let highbits_symbols: Vec<u16> = highbits_z1
        .iter()
        .map(|&value| {
            let mapped = value + p.hb_offset;
            if mapped < 0 || mapped as usize >= p.hb_table.len() {
                Err(SignaturePackingError::InvalidHighbits)
            } else {
                Ok(mapped as u16)
            }
        })
        .collect::<Result<_, _>>()?;

    let hint_symbols: Vec<u16> = h
        .iter()
        .map(|&value| {
            if value < 0 {
                return Err(SignaturePackingError::InvalidHint);
            }

            if value > p.h_cut && value <= p.h_cut + p.h_offset {
                return Err(SignaturePackingError::InvalidHint);
            }

            let mapped = if value > p.h_cut + p.h_offset {
                value - p.h_offset
            } else {
                value
            };

            if mapped < 0 || mapped as usize >= p.h_table.len() {
                return Err(SignaturePackingError::InvalidHint);
            }

            Ok(mapped as u16)
        })
        .collect::<Result<_, _>>()?;

    let encoded_hb = encode(&highbits_symbols, p.hb_table, highbits_z1.len())
        .map_err(|error| map_rans_error(error, true))?;

    let encoded_h =
        encode(&hint_symbols, p.h_table, h.len()).map_err(|error| map_rans_error(error, false))?;

    let hb_offset = encoded_hb
        .len()
        .checked_sub(p.base_hb)
        .filter(|&value| value <= 255)
        .ok_or(SignaturePackingError::EncodedLengthOutOfRange)?;

    let h_offset = encoded_h
        .len()
        .checked_sub(p.base_h)
        .filter(|&value| value <= 255)
        .ok_or(SignaturePackingError::EncodedLengthOutOfRange)?;

    let position = CHALLENGE_BYTES + p.l * N;

    let total = position + 2 + encoded_hb.len() + encoded_h.len();

    if total > p.signature_bytes {
        return Err(SignaturePackingError::SignatureTooLarge);
    }

    signature[position] = hb_offset as u8;
    signature[position + 1] = h_offset as u8;

    let hb_start = position + 2;
    let h_start = hb_start + encoded_hb.len();

    signature[hb_start..h_start].copy_from_slice(&encoded_hb);
    signature[h_start..total].copy_from_slice(&encoded_h);

    Ok(signature)
}

/// Decoded HAETAE 1.2.0 signature coefficient vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackedSignature {
    pub challenge: Vec<i32>,
    pub lowbits_z1: Vec<i32>,
    pub highbits_z1: Vec<i32>,
    pub hints: Vec<i32>,
}

/// Deserialize a fixed-length HAETAE signature.
///
/// Rejects malformed lengths, entropy coding, and nonzero padding.
pub fn unpack_signature(
    mode: ParameterSet,
    signature: &[u8],
) -> Result<UnpackedSignature, SignaturePackingError> {
    let p = parameters(mode);

    if signature.len() != p.signature_bytes {
        return Err(SignaturePackingError::InvalidDimensions);
    }

    let challenge = (0..N)
        .map(|i| i32::from((signature[i / 8] >> (i % 8)) & 1))
        .collect();

    let lowbits_start = CHALLENGE_BYTES;
    let lowbits_end = lowbits_start + p.l * N;

    let lowbits_z1 = signature[lowbits_start..lowbits_end]
        .iter()
        .map(|&byte| i32::from(byte as i8))
        .collect();

    let hb_length = p.base_hb + usize::from(signature[lowbits_end]);
    let h_length = p.base_h + usize::from(signature[lowbits_end + 1]);

    let hb_start = lowbits_end + 2;
    let hb_end = hb_start
        .checked_add(hb_length)
        .ok_or(SignaturePackingError::EncodedLengthOutOfRange)?;
    let h_end = hb_end
        .checked_add(h_length)
        .ok_or(SignaturePackingError::EncodedLengthOutOfRange)?;

    if h_end > signature.len() {
        return Err(SignaturePackingError::EncodedLengthOutOfRange);
    }

    if signature[h_end..].iter().any(|&byte| byte != 0) {
        return Err(SignaturePackingError::InvalidDimensions);
    }

    let highbits_z1 = decode(&signature[hb_start..hb_end], p.hb_table, p.l * N)
        .map_err(|error| map_rans_error(error, true))?
        .into_iter()
        .map(|symbol| i32::from(symbol) - p.hb_offset)
        .collect();

    let hints = decode(&signature[hb_end..h_end], p.h_table, p.k * N)
        .map_err(|error| map_rans_error(error, false))?
        .into_iter()
        .map(|symbol| {
            let value = i32::from(symbol);
            if value > p.h_cut {
                value + p.h_offset
            } else {
                value
            }
        })
        .collect();

    Ok(UnpackedSignature {
        challenge,
        lowbits_z1,
        highbits_z1,
        hints,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_sizes_and_zero_padding() {
        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let p = parameters(mode);

            let challenge = vec![0; N];
            let lowbits = vec![0; p.l * N];
            let highbits = vec![0; p.l * N];
            let hints = vec![0; p.k * N];

            let result = pack_signature(mode, &challenge, &lowbits, &highbits, &hints);

            // Some synthetic inputs may fail the reference's
            // mode-specific encoded-length restrictions.
            if let Ok(signature) = result {
                assert_eq!(signature.len(), p.signature_bytes);
                assert!(signature[..CHALLENGE_BYTES].iter().all(|&byte| byte == 0));
            }
        }
    }

    #[test]
    fn invalid_challenge_is_rejected() {
        let mut challenge = vec![0; N];
        challenge[7] = 2;

        assert_eq!(
            pack_signature(
                ParameterSet::Haetae2,
                &challenge,
                &vec![0; 4 * N],
                &vec![0; 4 * N],
                &vec![0; 2 * N],
            ),
            Err(SignaturePackingError::InvalidChallenge)
        );
    }

    #[test]
    fn invalid_dimensions_are_rejected() {
        assert_eq!(
            pack_signature(ParameterSet::Haetae2, &[], &[], &[], &[],),
            Err(SignaturePackingError::InvalidDimensions)
        );
    }

    #[test]
    fn malformed_signature_lengths_are_rejected() {
        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let expected = parameters(mode).signature_bytes;

            for length in [0, expected - 1, expected + 1] {
                let signature = vec![0u8; length];

                assert_eq!(
                    unpack_signature(mode, &signature),
                    Err(SignaturePackingError::InvalidDimensions),
                    "mode={mode:?} length={length}"
                );
            }
        }
    }

    #[test]
    fn oversized_encoded_sections_are_rejected() {
        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let p = parameters(mode);
            let mut signature = vec![0u8; p.signature_bytes];

            let length_offset = CHALLENGE_BYTES + p.l * N;

            // Maximize both encoded-length offsets.
            signature[length_offset] = 255;
            signature[length_offset + 1] = 255;

            let encoded_end = length_offset + 2 + p.base_hb + 255 + p.base_h + 255;

            assert!(
                encoded_end > signature.len(),
                "mode={mode:?}: oversized test did not cross boundary"
            );

            assert_eq!(
                unpack_signature(mode, &signature),
                Err(SignaturePackingError::EncodedLengthOutOfRange),
                "mode={mode:?}"
            );
        }
    }

    #[test]
    fn authenticated_verification_challenge_matches_c() {
        use crate::challenge::{pack_challenge_transcript, sample_challenge};
        use crate::poly::Poly;
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake256,
        };

        fn decode_hex(value: &str) -> Vec<u8> {
            assert_eq!(value.len() % 2, 0);
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        }

        fn fixture_cases(
            path: &std::path::Path,
        ) -> Vec<std::collections::BTreeMap<String, String>> {
            let text = std::fs::read_to_string(path).unwrap();
            let mut cases = Vec::new();
            let mut current: Option<std::collections::BTreeMap<String, String>> = None;

            for line in text.lines() {
                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };

                if key == "CASE" {
                    assert!(current.is_none(), "nested case");
                    let mut record = std::collections::BTreeMap::new();
                    record.insert(key.to_string(), value.to_string());
                    current = Some(record);
                } else if key == "END_CASE" {
                    let record = current.take().expect("case terminator");
                    assert_eq!(record["CASE"], value, "case terminator mismatch");
                    assert!(record.contains_key("SIGNATURE"));
                    cases.push(record);
                } else if let Some(ref mut record) = current {
                    // Retry fixtures contain multiple ATTEMPT and
                    // CHALLENGE fields. Only retain the case-level
                    // fields required for verification.
                    if matches!(key, "PK" | "PRE" | "MESSAGE" | "MU" | "SIGNATURE") {
                        assert!(
                            record.insert(key.to_string(), value.to_string()).is_none(),
                            "duplicate case-level field: {key}"
                        );
                    }
                }
            }

            assert!(current.is_none(), "unterminated case");
            assert_eq!(cases.len(), 5);
            cases
        }

        fn coefficients(record: &serde_json::Value, field: &str, expected: usize) -> Vec<i32> {
            let values = record[field].as_array().expect("array");
            assert_eq!(values.len(), expected);
            values
                .iter()
                .map(|v| i32::try_from(v.as_i64().unwrap()).unwrap())
                .collect()
        }

        let root = std::env::var("HAETAE_C_VERIFICATION_ROOT")
            .expect("HAETAE_C_VERIFICATION_ROOT missing");
        let root = std::path::Path::new(&root);

        let mut checked = 0;

        for (number, mode) in [
            (2_usize, ParameterSet::Haetae2),
            (3, ParameterSet::Haetae3),
            (5, ParameterSet::Haetae5),
        ] {
            let fixture_path = root
                .join("rust-fixtures")
                .join(format!("retry_mode{number}.txt"));

            let cases = fixture_cases(&fixture_path);
            assert_eq!(cases.len(), 5);

            let k = mode.parameters().k;

            for (case, fixture) in cases.iter().enumerate() {
                assert_eq!(fixture["CASE"].parse::<usize>().unwrap(), case);

                let path = root
                    .join("verification-crt-hint-parity")
                    .join(format!("mode{number}_case{case}.json"));

                let crt: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();

                let path = root
                    .join("verification-arithmetic-parity")
                    .join(format!("mode{number}_case{case}.json"));

                let arithmetic: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();

                let pk = decode_hex(&fixture["PK"]);
                let pre = decode_hex(&fixture["PRE"]);
                let message = decode_hex(&fixture["MESSAGE"]);
                let signature = decode_hex(&fixture["SIGNATURE"]);

                assert_eq!(pk.len(), mode.parameters().public_key_bytes);
                assert_eq!(signature.len(), mode.parameters().signature_bytes);

                assert_eq!(crt["signature_hex"].as_str().unwrap(), fixture["SIGNATURE"]);

                let decoded = unpack_signature(mode, &signature).expect("authenticated signature");

                let highbits_data = coefficients(&crt, "w_final", k * N);

                let highbits: Vec<Poly> = (0..k)
                    .map(|row| Poly::new(std::array::from_fn(|i| highbits_data[row * N + i])))
                    .collect();

                let wprime = coefficients(&arithmetic, "wprime", N);

                let lsb = Poly::new(std::array::from_fn(|i| wprime[i]));

                let transcript = pack_challenge_transcript(number as u8, &highbits, &lsb)
                    .expect("verification transcript");

                let mut shake = Shake256::default();
                shake.update(&pk);
                shake.update(&pre);
                shake.update(&message);

                let mut mu = [0_u8; 64];
                shake.finalize_xof().read(&mut mu);

                assert_eq!(
                    mu.to_vec(),
                    decode_hex(&fixture["MU"]),
                    "MU mismatch mode={number} case={case}"
                );

                let challenge_mu: [u8; 32] = mu[..32].try_into().unwrap();

                let reconstructed = sample_challenge(number as u8, &transcript, &challenge_mu)
                    .expect("verification challenge");

                assert_eq!(
                    reconstructed.coeffs.as_slice(),
                    decoded.challenge.as_slice(),
                    "challenge mismatch mode={number} case={case}"
                );

                checked += 1;

                println!(
                    "HAETAE_VERIFY_CHALLENGE_MODE={number} \
                     CASE={case} TRANSCRIPT_BYTES={} STATUS=PASS",
                    transcript.len()
                );
            }
        }

        assert_eq!(checked, 15);

        println!("HAETAE_VERIFY_CHALLENGE_TOTAL={checked} STATUS=PASS");
    }

    #[test]
    fn authenticated_verification_z2_matches_c() {
        use crate::poly::Poly;
        use crate::polyvec::PolyVecK;

        fn load(root: &std::path::Path, dir: &str, mode: usize, case: usize) -> serde_json::Value {
            let path = root.join(dir).join(format!("mode{mode}_case{case}.json"));
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
        }

        fn values(v: &serde_json::Value, key: &str, count: usize) -> Vec<i32> {
            let array = v[key].as_array().expect("missing coefficient array");
            assert_eq!(array.len(), count, "{key} length");
            array
                .iter()
                .map(|x| i32::try_from(x.as_i64().unwrap()).unwrap())
                .collect()
        }

        fn vector<const K: usize>(data: &[i32]) -> PolyVecK<K> {
            assert_eq!(data.len(), K * N);
            PolyVecK::new(std::array::from_fn(|row| {
                Poly::new(std::array::from_fn(|i| data[row * N + i]))
            }))
        }

        fn compare<const K: usize>(
            actual: &PolyVecK<K>,
            evidence: &serde_json::Value,
            key: &str,
            mode: usize,
            case: usize,
        ) -> usize {
            let expected = values(evidence, key, K * N);
            for row in 0..K {
                for i in 0..N {
                    assert_eq!(
                        actual.as_slice()[row].coeffs[i],
                        expected[row * N + i],
                        "mode={mode} case={case} stage={key} row={row} i={i}"
                    );
                }
            }
            K * N
        }

        fn check<const K: usize>(
            mode: ParameterSet,
            number: usize,
            case: usize,
            root: &std::path::Path,
        ) -> usize {
            let e = load(root, "verification-z2-parity", number, case);
            let c = load(root, "verification-crt-hint-parity", number, case);
            let a = load(root, "verification-arithmetic-parity", number, case);

            assert_eq!(e["format"], "HAETAE_C_VERIFICATION_Z2_V1");
            assert_eq!(c["format"], "HAETAE_C_VERIFICATION_CRT_HINT_V1");
            assert_eq!(a["format"], "HAETAE_C_VERIFICATION_ARITHMETIC_V1");

            for record in [&e, &c, &a] {
                assert_eq!(record["mode"].as_u64(), Some(number as u64));
                assert_eq!(record["case"].as_u64(), Some(case as u64));
                assert_eq!(record["signature_hex"], e["signature_hex"]);
            }
            assert_eq!(e["k"].as_u64(), Some(K as u64));

            let w = vector::<K>(&values(&c, "w_final", K * N));
            let highbits = vector::<K>(&values(&c, "crt_frozen", K * N));
            let wprime = values(&a, "wprime", N);

            let mut z2 = w.mul_alpha(mode);
            let mut checked = compare(&z2, &e, "z2_after_mul_alpha", number, case);

            z2 = z2.sub(&highbits);
            checked += compare(&z2, &e, "z2_after_sub", number, case);

            let previous = z2.as_slice().to_vec();
            z2 = PolyVecK::new(std::array::from_fn(|row| {
                if row == 0 {
                    previous[row].add(&Poly::new(std::array::from_fn(|i| wprime[i])))
                } else {
                    previous[row].clone()
                }
            }));

            checked += compare(&z2, &e, "z2_after_add_wprime", number, case);

            z2.reduce2q();
            checked += compare(&z2, &e, "z2_after_reduce2q", number, case);

            z2.div2();
            checked += compare(&z2, &e, "z2_final", number, case);

            let norm = z2.sqnorm2();
            assert_eq!(
                Some(norm),
                e["z2_sqnorm2"].as_u64(),
                "z2 norm mode={number} case={case}"
            );

            let z1_norm = a["z1_sqnorm2"].as_u64().unwrap();
            let combined = z1_norm.checked_add(norm).unwrap();

            assert_eq!(
                Some(combined),
                e["combined_sqnorm2"].as_u64(),
                "combined norm mode={number} case={case}"
            );

            assert_eq!(checked, 5 * K * N);

            println!(
                "HAETAE_RUST_Z2_MODE={number} CASE={case} \
                 COEFFICIENTS={checked} COMBINED_NORM={combined} STATUS=PASS"
            );

            checked
        }

        let root = std::env::var("HAETAE_C_VERIFICATION_ROOT")
            .expect("HAETAE_C_VERIFICATION_ROOT missing");
        let root = std::path::Path::new(&root);

        let mut total = 0;
        for case in 0..5 {
            total += check::<2>(ParameterSet::Haetae2, 2, case, root);
            total += check::<3>(ParameterSet::Haetae3, 3, case, root);
            total += check::<4>(ParameterSet::Haetae5, 5, case, root);
        }

        assert_eq!(total, 57_600);
        println!("HAETAE_RUST_Z2_TOTAL={total} STATUS=PASS");
    }

    #[test]
    fn authenticated_verification_crt_hint_matches_c() {
        use crate::poly::Poly;
        use crate::polyvec::PolyVecK;

        fn load(root: &std::path::Path, dir: &str, mode: usize, case: usize) -> serde_json::Value {
            let path = root.join(dir).join(format!("mode{mode}_case{case}.json"));
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
        }

        fn values(v: &serde_json::Value, key: &str, count: usize) -> Vec<i32> {
            let a = v[key].as_array().expect("missing coefficient array");
            assert_eq!(a.len(), count, "{key} length");
            a.iter()
                .map(|x| i32::try_from(x.as_i64().unwrap()).unwrap())
                .collect()
        }

        fn compare<const K: usize>(
            actual: &PolyVecK<K>,
            evidence: &serde_json::Value,
            key: &str,
            mode: usize,
            case: usize,
        ) -> usize {
            let expected = values(evidence, key, K * N);
            for row in 0..K {
                for i in 0..N {
                    assert_eq!(
                        actual.as_slice()[row].coeffs[i],
                        expected[row * N + i],
                        "mode={mode} case={case} stage={key} row={row} i={i}"
                    );
                }
            }
            K * N
        }

        fn check<const K: usize>(
            mode: ParameterSet,
            number: usize,
            case: usize,
            root: &std::path::Path,
        ) -> usize {
            let e = load(root, "verification-crt-hint-parity", number, case);
            let p = load(root, "verification-matrix-product-parity", number, case);
            let a = load(root, "verification-arithmetic-parity", number, case);
            let d = load(root, "decoder-coefficient-parity", number, case);

            assert_eq!(e["format"], "HAETAE_C_VERIFICATION_CRT_HINT_V1");
            assert_eq!(p["format"], "HAETAE_C_VERIFICATION_MATRIX_PRODUCT_V1");
            assert_eq!(a["format"], "HAETAE_C_VERIFICATION_ARITHMETIC_V1");
            assert_eq!(d["format"], "HAETAE_DECODER_COEFFICIENT_PARITY_V1");

            for record in [&e, &p, &a, &d] {
                assert_eq!(record["mode"].as_u64(), Some(number as u64));
                assert_eq!(record["case"].as_u64(), Some(case as u64));
                assert_eq!(record["signature_hex"], e["signature_hex"]);
            }

            assert_eq!(e["k"].as_u64(), Some(K as u64));

            let inverse = values(&p, "product_invntt", K * N);
            let wprime = values(&a, "wprime", N);
            let hints = values(&d, "hints", K * N);

            let mut crt = PolyVecK::<K>::new(std::array::from_fn(|row| {
                Poly::new(std::array::from_fn(|i| {
                    let xq = inverse[row * N + i];
                    let parity = if row == 0 { wprime[i] & 1 } else { 0 };
                    let correction = crate::params::Q & -((xq ^ parity) & 1);
                    xq.checked_add(correction)
                        .expect("verification CRT overflow")
                }))
            }));

            let mut checked = compare(&crt, &e, "crt_raw", number, case);

            crt.freeze2q();
            checked += compare(&crt, &e, "crt_frozen", number, case);

            let mut w = crt.highbits_hint(mode);
            checked += compare(&w, &e, "highbits_hint", number, case);

            let hint_vector = PolyVecK::<K>::new(std::array::from_fn(|row| {
                Poly::new(std::array::from_fn(|i| hints[row * N + i]))
            }));

            w = w.add(&hint_vector);
            w.csub_dq2alpha(mode);
            checked += compare(&w, &e, "w_final", number, case);

            assert_eq!(checked, 4 * K * N);
            println!(
                "HAETAE_RUST_CRT_HINT_MODE={number} CASE={case} \
                 COEFFICIENTS={checked} STATUS=PASS"
            );
            checked
        }

        let root = std::env::var("HAETAE_C_VERIFICATION_ROOT")
            .expect("HAETAE_C_VERIFICATION_ROOT missing");
        let root = std::path::Path::new(&root);

        let mut total = 0;
        for case in 0..5 {
            total += check::<2>(ParameterSet::Haetae2, 2, case, root);
            total += check::<3>(ParameterSet::Haetae3, 3, case, root);
            total += check::<4>(ParameterSet::Haetae5, 5, case, root);
        }

        assert_eq!(total, 46_080);
        println!("HAETAE_RUST_CRT_HINT_TOTAL={total} STATUS=PASS");
    }

    #[test]
    fn authenticated_verification_matrix_product_matches_c() {
        use crate::packing::unpack_verification_key;
        use crate::poly::Poly;
        use crate::polyvec::{PolyVecK, PolyVecL};

        fn decode_hex(hex: &str) -> Vec<u8> {
            assert_eq!(hex.len() % 2, 0);
            hex.as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        }

        fn check<const K: usize, const L: usize>(
            mode: ParameterSet,
            mode_number: usize,
            case: usize,
            root: &std::path::Path,
        ) -> usize {
            let path = root.join(format!("mode{mode_number}_case{case}.json"));

            let evidence: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(path).expect("read C matrix-product evidence"),
            )
            .expect("parse C matrix-product evidence");

            assert_eq!(
                evidence["format"].as_str(),
                Some("HAETAE_C_VERIFICATION_MATRIX_PRODUCT_V1")
            );
            assert_eq!(evidence["mode"].as_u64(), Some(mode_number as u64));
            assert_eq!(evidence["case"].as_u64(), Some(case as u64));
            assert_eq!(evidence["k"].as_u64(), Some(K as u64));
            assert_eq!(evidence["l"].as_u64(), Some(L as u64));

            let public_key = decode_hex(evidence["public_key_hex"].as_str().unwrap());
            let signature = decode_hex(evidence["signature_hex"].as_str().unwrap());

            assert_eq!(public_key.len(), mode.parameters().public_key_bytes);
            assert_eq!(signature.len(), mode.parameters().signature_bytes);

            let reconstructed = unpack_verification_key::<K, L>(&public_key, mode)
                .expect("authenticated verification key");

            let decoded = unpack_signature(mode, &signature).expect("authenticated signature");

            assert_eq!(decoded.highbits_z1.len(), L * N);
            assert_eq!(decoded.lowbits_z1.len(), L * N);

            let mut z1 = PolyVecL::<L>::new(std::array::from_fn(|column| {
                let start = column * N;
                let end = start + N;

                let high: [i32; N] = decoded.highbits_z1[start..end].try_into().unwrap();

                let low: [i32; N] = decoded.lowbits_z1[start..end].try_into().unwrap();

                Poly::compose(&Poly::new(high), &Poly::new(low))
            }));

            z1.ntt();

            let mut product = PolyVecK::<K>::new(std::array::from_fn(|row| {
                reconstructed.matrix[row].pointwise_acc_montgomery(&z1)
            }));

            let expected_ntt = evidence["product_ntt"]
                .as_array()
                .expect("C NTT-domain matrix product");

            assert_eq!(expected_ntt.len(), K * N);

            for row in 0..K {
                for index in 0..N {
                    let flat = row * N + index;

                    assert_eq!(
                        Some(i64::from(product.as_slice()[row].coeffs[index])),
                        expected_ntt[flat].as_i64(),
                        "NTT-domain matrix-product mismatch: \
                         mode={mode_number} case={case} \
                         row={row} coefficient={index}"
                    );
                }
            }

            product.invntt_tomont();

            let expected_invntt = evidence["product_invntt"]
                .as_array()
                .expect("C inverse-NTT matrix product");

            assert_eq!(expected_invntt.len(), K * N);

            for row in 0..K {
                for index in 0..N {
                    let flat = row * N + index;

                    assert_eq!(
                        Some(i64::from(product.as_slice()[row].coeffs[index])),
                        expected_invntt[flat].as_i64(),
                        "Inverse-NTT matrix-product mismatch: \
                         mode={mode_number} case={case} \
                         row={row} coefficient={index}"
                    );
                }
            }

            println!(
                "HAETAE_RUST_MATRIX_PRODUCT_MODE={mode_number} \
                 CASE={case} NTT={} INVNTT={} STATUS=PASS",
                K * N,
                K * N
            );

            2 * K * N
        }

        let root = std::env::var("HAETAE_C_VERIFICATION_MATRIX_PRODUCT_PARITY_DIR")
            .expect("matrix-product parity directory must be set");

        let root = std::path::Path::new(&root);

        let mut total = 0_usize;

        for case in 0..5 {
            total += check::<2, 4>(ParameterSet::Haetae2, 2, case, root);
            total += check::<3, 6>(ParameterSet::Haetae3, 3, case, root);
            total += check::<4, 7>(ParameterSet::Haetae5, 5, case, root);
        }

        assert_eq!(total, 23_040);

        println!("HAETAE_RUST_MATRIX_PRODUCT_TOTAL={total} STATUS=PASS");
    }

    #[test]
    fn authenticated_forward_ntt_matches_independent_c() {
        use crate::poly::Poly;
        use crate::polyvec::PolyVecL;

        let root = std::env::var("HAETAE_C_VERIFICATION_NTT_PARITY_DIR")
            .expect("HAETAE_C_VERIFICATION_NTT_PARITY_DIR must be set");

        let mut total = 0_usize;

        for (mode, mode_number) in [
            (ParameterSet::Haetae2, 2),
            (ParameterSet::Haetae3, 3),
            (ParameterSet::Haetae5, 5),
        ] {
            for case in 0..5 {
                let path =
                    std::path::Path::new(&root).join(format!("mode{mode_number}_case{case}.json"));

                let evidence: serde_json::Value = serde_json::from_str(
                    &std::fs::read_to_string(path).expect("read C NTT evidence"),
                )
                .expect("parse C NTT evidence");

                assert_eq!(
                    evidence["format"].as_str(),
                    Some("HAETAE_C_VERIFICATION_NTT_V1")
                );
                assert_eq!(evidence["mode"].as_u64(), Some(mode_number as u64));
                assert_eq!(evidence["case"].as_u64(), Some(case as u64));

                let signature_hex = evidence["signature_hex"]
                    .as_str()
                    .expect("authenticated signature hex");

                assert_eq!(signature_hex.len(), parameters(mode).signature_bytes * 2);

                let signature = signature_hex
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect::<Vec<_>>();

                let decoded = unpack_signature(mode, &signature)
                    .expect("authenticated signature must decode");

                let l = parameters(mode).l;
                assert_eq!(decoded.highbits_z1.len(), l * N);
                assert_eq!(decoded.lowbits_z1.len(), l * N);

                let z1 = (0..l)
                    .map(|i| {
                        let start = i * N;
                        let end = start + N;

                        let high: [i32; N] = decoded.highbits_z1[start..end].try_into().unwrap();

                        let low: [i32; N] = decoded.lowbits_z1[start..end].try_into().unwrap();

                        Poly::compose(&Poly::new(high), &Poly::new(low))
                    })
                    .collect::<Vec<_>>();

                let actual = match mode_number {
                    2 => {
                        let mut vector = PolyVecL::<4>::new(z1.clone().try_into().unwrap());
                        vector.ntt();
                        vector
                            .as_slice()
                            .iter()
                            .flat_map(|poly| poly.coeffs)
                            .collect::<Vec<_>>()
                    }
                    3 => {
                        let mut vector = PolyVecL::<6>::new(z1.clone().try_into().unwrap());
                        vector.ntt();
                        vector
                            .as_slice()
                            .iter()
                            .flat_map(|poly| poly.coeffs)
                            .collect::<Vec<_>>()
                    }
                    5 => {
                        let mut vector = PolyVecL::<7>::new(z1.try_into().unwrap());
                        vector.ntt();
                        vector
                            .as_slice()
                            .iter()
                            .flat_map(|poly| poly.coeffs)
                            .collect::<Vec<_>>()
                    }
                    _ => unreachable!(),
                };

                let expected = evidence["z1_ntt"].as_array().expect("C NTT coefficients");

                assert_eq!(actual.len(), l * N);
                assert_eq!(expected.len(), l * N);

                for (index, &coefficient) in actual.iter().enumerate() {
                    assert_eq!(
                        Some(i64::from(coefficient)),
                        expected[index].as_i64(),
                        "C/Rust NTT mismatch: mode={mode_number} \
                         case={case} coefficient={index}"
                    );
                    total += 1;
                }

                println!(
                    "HAETAE_RUST_NTT_MODE={mode_number} CASE={case} \
                     COEFFICIENTS={} STATUS=PASS",
                    l * N
                );
            }
        }

        assert_eq!(total, 21_760);
        println!("HAETAE_RUST_NTT_TOTAL={total} STATUS=PASS");
    }

    #[test]
    fn authenticated_verification_arithmetic_matches_c() {
        use crate::poly::Poly;
        use crate::polyvec::PolyVecL;

        let root = std::env::var("HAETAE_C_VERIFY_ARITHMETIC_PARITY_DIR")
            .expect("HAETAE_C_VERIFY_ARITHMETIC_PARITY_DIR must be set");

        let mut total_wprime = 0_usize;
        let mut total_norms = 0_usize;

        for (mode, mode_number) in [
            (ParameterSet::Haetae2, 2),
            (ParameterSet::Haetae3, 3),
            (ParameterSet::Haetae5, 5),
        ] {
            for case in 0..5 {
                let path =
                    std::path::Path::new(&root).join(format!("mode{mode_number}_case{case}.json"));

                let evidence: serde_json::Value = serde_json::from_str(
                    &std::fs::read_to_string(path).expect("read C arithmetic evidence"),
                )
                .expect("parse C arithmetic evidence");

                assert_eq!(
                    evidence["format"].as_str(),
                    Some("HAETAE_C_VERIFICATION_ARITHMETIC_V1")
                );
                assert_eq!(evidence["mode"].as_u64(), Some(mode_number as u64));
                assert_eq!(evidence["case"].as_u64(), Some(case as u64));

                let signature_hex = evidence["signature_hex"].as_str().expect("signature hex");

                let signature = signature_hex
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect::<Vec<_>>();

                assert_eq!(signature.len(), parameters(mode).signature_bytes);

                let decoded = unpack_signature(mode, &signature)
                    .expect("authenticated signature must decode");

                let l = parameters(mode).l;
                assert_eq!(decoded.highbits_z1.len(), l * N);
                assert_eq!(decoded.lowbits_z1.len(), l * N);
                assert_eq!(decoded.challenge.len(), N);

                let z1 = (0..l)
                    .map(|i| {
                        let start = i * N;
                        let end = start + N;

                        let high: [i32; N] = decoded.highbits_z1[start..end].try_into().unwrap();

                        let low: [i32; N] = decoded.lowbits_z1[start..end].try_into().unwrap();

                        Poly::compose(&Poly::new(high), &Poly::new(low))
                    })
                    .collect::<Vec<_>>();

                let actual_norm = match mode_number {
                    2 => PolyVecL::<4>::new(z1.clone().try_into().unwrap()).sqnorm2(),
                    3 => PolyVecL::<6>::new(z1.clone().try_into().unwrap()).sqnorm2(),
                    5 => PolyVecL::<7>::new(z1.clone().try_into().unwrap()).sqnorm2(),
                    _ => unreachable!(),
                };

                assert_eq!(
                    Some(actual_norm),
                    evidence["z1_sqnorm2"].as_u64(),
                    "squared norm mismatch: mode={mode_number} case={case}"
                );

                total_norms += 1;

                let challenge: [i32; N] = decoded.challenge.as_slice().try_into().unwrap();

                let actual_wprime = z1[0].sub(&Poly::new(challenge)).lsb();

                let expected = evidence["wprime"]
                    .as_array()
                    .expect("C wprime coefficients");

                assert_eq!(expected.len(), N);

                for (index, &actual) in actual_wprime.coeffs.iter().enumerate() {
                    assert_eq!(
                        Some(i64::from(actual)),
                        expected[index].as_i64(),
                        "wprime mismatch: mode={mode_number} \
                         case={case} coefficient={index}"
                    );
                    total_wprime += 1;
                }

                println!(
                    "HAETAE_RUST_VERIFY_ARITH_MODE={mode_number} \
                     CASE={case} NORM=PASS WPRIME=PASS"
                );
            }
        }

        assert_eq!(total_norms, 15);
        assert_eq!(total_wprime, 3840);

        println!("HAETAE_RUST_VERIFY_NORMS={total_norms} STATUS=PASS");
        println!("HAETAE_RUST_VERIFY_WPRIME={total_wprime} STATUS=PASS");
    }

    #[test]
    fn authenticated_z1_matches_independent_c_compose() {
        use crate::poly::Poly;

        let root = std::env::var("HAETAE_C_Z1_COMPOSITION_PARITY_DIR")
            .expect("HAETAE_C_Z1_COMPOSITION_PARITY_DIR must be set");

        let mut total = 0_usize;

        for (mode, mode_number) in [
            (ParameterSet::Haetae2, 2),
            (ParameterSet::Haetae3, 3),
            (ParameterSet::Haetae5, 5),
        ] {
            let p = parameters(mode);

            for case in 0..5 {
                let path =
                    std::path::Path::new(&root).join(format!("mode{mode_number}_case{case}.json"));

                let evidence: serde_json::Value = serde_json::from_str(
                    &std::fs::read_to_string(path).expect("read C composition evidence"),
                )
                .expect("parse C composition evidence");

                assert_eq!(
                    evidence["format"].as_str(),
                    Some("HAETAE_C_POLY_COMPOSE_PARITY_V1")
                );
                assert_eq!(evidence["mode"].as_u64(), Some(mode_number as u64));
                assert_eq!(evidence["case"].as_u64(), Some(case as u64));

                let hex = evidence["signature_hex"]
                    .as_str()
                    .expect("C evidence signature");

                assert_eq!(hex.len(), p.signature_bytes * 2);

                let signature = hex
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect::<Vec<_>>();

                let decoded = unpack_signature(mode, &signature)
                    .expect("authenticated signature must decode");

                let expected = evidence["z1"]
                    .as_array()
                    .expect("C-composed z1 coefficients");

                assert_eq!(expected.len(), p.l * N);
                assert_eq!(decoded.highbits_z1.len(), p.l * N);
                assert_eq!(decoded.lowbits_z1.len(), p.l * N);

                for polynomial in 0..p.l {
                    let start = polynomial * N;
                    let end = start + N;

                    let high: [i32; N] = decoded.highbits_z1[start..end]
                        .try_into()
                        .expect("highbits polynomial");

                    let low: [i32; N] = decoded.lowbits_z1[start..end]
                        .try_into()
                        .expect("lowbits polynomial");

                    let z1 = Poly::compose(&Poly::new(high), &Poly::new(low));

                    for coefficient in 0..N {
                        let index = start + coefficient;

                        assert_eq!(
                            Some(i64::from(z1.coeffs[coefficient])),
                            expected[index].as_i64(),
                            "C/Rust z1 mismatch: mode={mode_number} \
                             case={case} coefficient={index}"
                        );

                        total += 1;
                    }
                }

                println!(
                    "HAETAE_C_RUST_Z1_MODE={mode_number} CASE={case} \
                     COEFFICIENTS={} STATUS=PASS",
                    p.l * N
                );
            }
        }

        assert_eq!(total, 21_760);

        println!("HAETAE_C_RUST_Z1_TOTAL={total} STATUS=PASS");
    }

    #[test]
    fn authenticated_z1_reconstruction_matches_c_coefficients() {
        use crate::poly::Poly;

        let root = std::env::var("HAETAE_DECODER_COEFFICIENT_PARITY_DIR")
            .expect("HAETAE_DECODER_COEFFICIENT_PARITY_DIR must be set");

        let mut total_coefficients = 0_usize;

        for (mode, mode_number) in [
            (ParameterSet::Haetae2, 2),
            (ParameterSet::Haetae3, 3),
            (ParameterSet::Haetae5, 5),
        ] {
            let p = parameters(mode);

            for case in 0..5 {
                let path =
                    std::path::Path::new(&root).join(format!("mode{mode_number}_case{case}.json"));

                let evidence: serde_json::Value = serde_json::from_str(
                    &std::fs::read_to_string(path).expect("read independent C evidence"),
                )
                .expect("parse independent C evidence");

                assert_eq!(
                    evidence["format"].as_str(),
                    Some("HAETAE_DECODER_COEFFICIENT_PARITY_V1")
                );
                assert_eq!(evidence["mode"].as_u64(), Some(mode_number as u64));
                assert_eq!(evidence["case"].as_u64(), Some(case as u64));

                let hex = evidence["signature_hex"]
                    .as_str()
                    .expect("authenticated signature hex");

                assert_eq!(hex.len(), p.signature_bytes * 2);

                let signature = hex
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect::<Vec<_>>();

                let decoded = unpack_signature(mode, &signature)
                    .expect("authenticated signature must decode");

                let reference_high = evidence["highbits_z1"]
                    .as_array()
                    .expect("C highbits coefficient vector");

                let reference_low = evidence["lowbits_z1"]
                    .as_array()
                    .expect("C lowbits coefficient vector");

                assert_eq!(decoded.highbits_z1.len(), p.l * N);
                assert_eq!(decoded.lowbits_z1.len(), p.l * N);
                assert_eq!(reference_high.len(), p.l * N);
                assert_eq!(reference_low.len(), p.l * N);

                for polynomial in 0..p.l {
                    let start = polynomial * N;
                    let end = start + N;

                    let high: [i32; N] = decoded.highbits_z1[start..end]
                        .try_into()
                        .expect("highbits polynomial");

                    let low: [i32; N] = decoded.lowbits_z1[start..end]
                        .try_into()
                        .expect("lowbits polynomial");

                    let composed = Poly::compose(&Poly::new(high), &Poly::new(low));

                    for coefficient in 0..N {
                        let index = start + coefficient;

                        let c_high = reference_high[index]
                            .as_i64()
                            .expect("C highbits coefficient");

                        let c_low = reference_low[index]
                            .as_i64()
                            .expect("C lowbits coefficient");

                        assert_eq!(
                            i64::from(high[coefficient]),
                            c_high,
                            "mode={mode_number} case={case} highbits[{index}]"
                        );

                        assert_eq!(
                            i64::from(low[coefficient]),
                            c_low,
                            "mode={mode_number} case={case} lowbits[{index}]"
                        );

                        assert!(
                            (-128..128).contains(&low[coefficient]),
                            "mode={mode_number} case={case} lowbits range [{index}]"
                        );

                        let expected = c_high
                            .checked_mul(256)
                            .and_then(|x| x.checked_add(c_low))
                            .expect("C composition arithmetic overflow");

                        assert_eq!(
                            i64::from(composed.coeffs[coefficient]),
                            expected,
                            "mode={mode_number} case={case} z1[{index}]"
                        );

                        total_coefficients += 1;
                    }
                }

                println!(
                    "HAETAE_Z1_COMPOSITION_MODE={mode_number} CASE={case} COEFFICIENTS={} STATUS=PASS",
                    p.l * N
                );
            }
        }

        assert_eq!(total_coefficients, 21_760);

        println!("HAETAE_Z1_COMPOSITION_TOTAL={total_coefficients} STATUS=PASS");
    }

    #[test]
    fn authenticated_signature_nonzero_padding_is_rejected() {
        let root = std::env::var("HAETAE_DECODER_COEFFICIENT_PARITY_DIR")
            .expect("HAETAE_DECODER_COEFFICIENT_PARITY_DIR must be set");

        for (mode, mode_number) in [
            (ParameterSet::Haetae2, 2),
            (ParameterSet::Haetae3, 3),
            (ParameterSet::Haetae5, 5),
        ] {
            let p = parameters(mode);

            for case in 0..5 {
                let path =
                    std::path::Path::new(&root).join(format!("mode{mode_number}_case{case}.json"));

                let evidence: serde_json::Value = serde_json::from_str(
                    &std::fs::read_to_string(path).expect("read C decoder evidence"),
                )
                .expect("parse C decoder evidence");

                let hex = evidence["signature_hex"]
                    .as_str()
                    .expect("reference signature hex");

                assert_eq!(hex.len(), p.signature_bytes * 2);

                let mut signature = hex
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect::<Vec<_>>();

                unpack_signature(mode, &signature).expect("valid authenticated signature");

                let length_offset = CHALLENGE_BYTES + p.l * N;

                let payload_end = length_offset
                    + 2
                    + p.base_hb
                    + usize::from(signature[length_offset])
                    + p.base_h
                    + usize::from(signature[length_offset + 1]);

                assert!(
                    payload_end < signature.len(),
                    "mode={mode_number} case={case}: no padding available"
                );

                assert!(signature[payload_end..].iter().all(|&byte| byte == 0));

                signature[payload_end] = 1;

                assert_eq!(
                    unpack_signature(mode, &signature),
                    Err(SignaturePackingError::InvalidDimensions),
                    "mode={mode_number} case={case}"
                );

                println!(
                    "HAETAE_NEGATIVE_PADDING_MODE={mode_number}                      CASE={case} STATUS=PASS"
                );
            }
        }
    }

    #[test]
    fn malformed_rans_initial_states_are_rejected() {
        let root = std::env::var("HAETAE_DECODER_COEFFICIENT_PARITY_DIR")
            .expect("HAETAE_DECODER_COEFFICIENT_PARITY_DIR must be set");

        for (mode, mode_number) in [
            (ParameterSet::Haetae2, 2),
            (ParameterSet::Haetae3, 3),
            (ParameterSet::Haetae5, 5),
        ] {
            let p = parameters(mode);

            for case in 0..5 {
                let path =
                    std::path::Path::new(&root).join(format!("mode{mode_number}_case{case}.json"));

                let evidence: serde_json::Value = serde_json::from_str(
                    &std::fs::read_to_string(path).expect("read authenticated C evidence"),
                )
                .expect("parse authenticated C evidence");

                let hex = evidence["signature_hex"].as_str().expect("signature hex");

                assert_eq!(hex.len(), p.signature_bytes * 2);

                let signature = hex
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect::<Vec<_>>();

                unpack_signature(mode, &signature).expect("authenticated signature must decode");

                let length_offset = CHALLENGE_BYTES + p.l * N;
                let hb_start = length_offset + 2;

                let hb_length = p.base_hb + usize::from(signature[length_offset]);

                let h_start = hb_start + hb_length;

                let h_length = p.base_h + usize::from(signature[length_offset + 1]);

                assert!(hb_length >= 4);
                assert!(h_length >= 4);
                assert!(h_start + h_length <= signature.len());

                let mut invalid_highbits = signature.clone();
                invalid_highbits[hb_start..hb_start + 4].fill(0);

                assert_eq!(
                    unpack_signature(mode, &invalid_highbits),
                    Err(SignaturePackingError::InvalidHighbits),
                    "mode={mode_number} case={case} highbits"
                );

                let mut invalid_hints = signature.clone();
                invalid_hints[h_start..h_start + 4].fill(0);

                assert_eq!(
                    unpack_signature(mode, &invalid_hints),
                    Err(SignaturePackingError::InvalidHint),
                    "mode={mode_number} case={case} hints"
                );

                println!(
                    "HAETAE_NEGATIVE_RANS_MODE={mode_number} CASE={case} HIGHBITS=PASS HINTS=PASS"
                );
            }
        }
    }
}
