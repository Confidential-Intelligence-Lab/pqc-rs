//! Experimental native HAETAE 1.2.0 signature verification.
//!
//! This module has not undergone a security audit.

use crate::challenge::{pack_challenge_transcript, sample_challenge};
use crate::packing::unpack_verification_key;
use crate::params::{ParameterSet, N, Q};
use crate::poly::Poly;
use crate::polyvec::{PolyVecK, PolyVecL};
use crate::signature_packing::unpack_signature;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    InvalidPublicKey,
    InvalidSignature,
    InvalidChallenge,
    NormExceeded,
}

fn norm_bound(mode: ParameterSet) -> u64 {
    match mode {
        ParameterSet::Haetae2 => 163_265_017,
        ParameterSet::Haetae3 => 479_901_314,
        ParameterSet::Haetae5 => 597_386_433,
    }
}

fn checked_z1_norm<const L: usize>(
    mode: ParameterSet,
    z1: &PolyVecL<L>,
) -> Result<u64, VerificationError> {
    let mut norm = 0_u64;

    for polynomial in z1.as_slice() {
        for &coefficient in &polynomial.coeffs {
            let value = i64::from(coefficient);
            let square = (value * value) as u64;

            norm = norm
                .checked_add(square)
                .ok_or(VerificationError::NormExceeded)?;

            if norm > norm_bound(mode) {
                return Err(VerificationError::NormExceeded);
            }
        }
    }

    Ok(norm)
}

/// Verify a detached HAETAE signature using an already formatted prefix.
///
/// The authenticated message is SHAKE256(public_key || pre || message).
/// This API is experimental and not security audited.
pub fn verify_preformatted(
    mode: ParameterSet,
    public_key: &[u8],
    pre: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerificationError> {
    let p = mode.parameters();

    if public_key.len() != p.public_key_bytes {
        return Err(VerificationError::InvalidPublicKey);
    }

    if signature.len() != p.signature_bytes {
        return Err(VerificationError::InvalidSignature);
    }

    match mode {
        ParameterSet::Haetae2 => verify_inner::<2, 4>(mode, public_key, pre, message, signature),
        ParameterSet::Haetae3 => verify_inner::<3, 6>(mode, public_key, pre, message, signature),
        ParameterSet::Haetae5 => verify_inner::<4, 7>(mode, public_key, pre, message, signature),
    }
}

fn verify_inner<const K: usize, const L: usize>(
    mode: ParameterSet,
    public_key: &[u8],
    pre: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerificationError> {
    let key = unpack_verification_key::<K, L>(public_key, mode)
        .map_err(|_| VerificationError::InvalidPublicKey)?;

    let decoded =
        unpack_signature(mode, signature).map_err(|_| VerificationError::InvalidSignature)?;

    if decoded.challenge.len() != N
        || decoded.lowbits_z1.len() != L * N
        || decoded.highbits_z1.len() != L * N
        || decoded.hints.len() != K * N
    {
        return Err(VerificationError::InvalidSignature);
    }

    let mut z1 = PolyVecL::<L>::new(std::array::from_fn(|column| {
        let start = column * N;

        let high = Poly::new(std::array::from_fn(|i| decoded.highbits_z1[start + i]));

        let low = Poly::new(std::array::from_fn(|i| decoded.lowbits_z1[start + i]));

        Poly::compose(&high, &low)
    }));

    let challenge = Poly::new(std::array::from_fn(|i| decoded.challenge[i]));

    let wprime = z1.as_slice()[0].sub(&challenge).lsb();

    let z1_norm = checked_z1_norm(mode, &z1)?;

    z1.ntt();

    let mut product = PolyVecK::<K>::new(std::array::from_fn(|row| {
        key.matrix[row].pointwise_acc_montgomery(&z1)
    }));

    product.invntt_tomont();

    // Preserve the authenticated CRT parity correction.
    let mut crt_coefficients = [[0_i32; N]; K];
    for (row, coefficients) in crt_coefficients.iter_mut().enumerate() {
        for (i, coefficient) in coefficients.iter_mut().enumerate() {
            let xq = product.as_slice()[row].coeffs[i];
            let parity = if row == 0 { wprime.coeffs[i] & 1 } else { 0 };
            let correction = Q & -((xq ^ parity) & 1);
            *coefficient = xq
                .checked_add(correction)
                .ok_or(VerificationError::InvalidSignature)?;
        }
    }

    let mut crt = PolyVecK::<K>::new(crt_coefficients.map(Poly::new));

    crt.freeze2q();

    let mut w = crt.highbits_hint(mode);

    let hints = PolyVecK::<K>::new(std::array::from_fn(|row| {
        Poly::new(std::array::from_fn(|i| decoded.hints[row * N + i]))
    }));

    w = w.add(&hints);
    w.csub_dq2alpha(mode);

    let mut z2 = w.mul_alpha(mode);
    z2 = z2.sub(&crt);

    z2 = PolyVecK::<K>::new(std::array::from_fn(|row| {
        if row == 0 {
            z2.as_slice()[row].add(&wprime)
        } else {
            z2.as_slice()[row].clone()
        }
    }));

    z2.reduce2q();
    z2.div2();

    let combined_norm = z1_norm
        .checked_add(z2.sqnorm2())
        .ok_or(VerificationError::NormExceeded)?;

    if combined_norm > norm_bound(mode) {
        return Err(VerificationError::NormExceeded);
    }

    let mode_number = match mode {
        ParameterSet::Haetae2 => 2,
        ParameterSet::Haetae3 => 3,
        ParameterSet::Haetae5 => 5,
    };

    let transcript = pack_challenge_transcript(mode_number, w.as_slice(), &wprime)
        .map_err(|_| VerificationError::InvalidChallenge)?;

    let mut shake = Shake256::default();
    shake.update(public_key);
    shake.update(pre);
    shake.update(message);

    let mut reader = shake.finalize_xof();
    let mut mu = [0_u8; 32];
    reader.read(&mut mu);

    let expected = sample_challenge(mode_number, &transcript, &mu)
        .map_err(|_| VerificationError::InvalidChallenge)?;

    // Accumulate differences without returning early on the first mismatch.
    let mut difference = 0_u32;
    for i in 0..N {
        difference |= (expected.coeffs[i] ^ decoded.challenge[i]) as u32;
    }

    if difference != 0 {
        return Err(VerificationError::InvalidChallenge);
    }

    Ok(())
}

#[cfg(test)]
mod authenticated_verification_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::Path;

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn cases(path: &Path) -> Vec<BTreeMap<String, String>> {
        let text = std::fs::read_to_string(path).unwrap();
        let mut result = Vec::new();
        let mut current: Option<BTreeMap<String, String>> = None;

        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };

            if key == "CASE" {
                assert!(current.is_none());
                let mut record = BTreeMap::new();
                record.insert(key.into(), value.into());
                current = Some(record);
            } else if key == "END_CASE" {
                let record = current.take().expect("case");
                assert_eq!(record["CASE"], value);
                result.push(record);
            } else if let Some(ref mut record) = current {
                if matches!(key, "PK" | "PRE" | "MESSAGE" | "SIGNATURE") {
                    assert!(
                        record.insert(key.into(), value.into()).is_none(),
                        "duplicate field: {key}"
                    );
                }
            }
        }

        assert!(current.is_none());
        assert_eq!(result.len(), 5);
        result
    }

    #[test]
    fn authenticated_native_verification_rejects_mutations() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let root = std::env::var("HAETAE_C_VERIFICATION_ROOT")
            .expect("HAETAE_C_VERIFICATION_ROOT missing");
        let root = Path::new(&root);
        let mut checked = 0_usize;

        for (number, mode) in [
            (2, ParameterSet::Haetae2),
            (3, ParameterSet::Haetae3),
            (5, ParameterSet::Haetae5),
        ] {
            let path = root
                .join("rust-fixtures")
                .join(format!("retry_mode{number}.txt"));

            for (case, record) in cases(&path).iter().enumerate() {
                let pk = decode_hex(&record["PK"]);
                let pre = decode_hex(&record["PRE"]);
                let message = decode_hex(&record["MESSAGE"]);
                let sig = decode_hex(&record["SIGNATURE"]);

                assert!(!pk.is_empty());
                assert!(!pre.is_empty());
                assert!(!message.is_empty());
                assert!(!sig.is_empty());

                let mut modified_message = message.clone();
                modified_message[0] ^= 1;

                let mut modified_pre = pre.clone();
                modified_pre[0] ^= 1;

                let mut modified_pk = pk.clone();
                modified_pk[0] ^= 1;

                let mut modified_sig = sig.clone();
                modified_sig[0] ^= 1;

                let variants = [
                    (
                        "message",
                        pk.as_slice(),
                        pre.as_slice(),
                        modified_message.as_slice(),
                        sig.as_slice(),
                    ),
                    (
                        "prefix",
                        pk.as_slice(),
                        modified_pre.as_slice(),
                        message.as_slice(),
                        sig.as_slice(),
                    ),
                    (
                        "public_key",
                        modified_pk.as_slice(),
                        pre.as_slice(),
                        message.as_slice(),
                        sig.as_slice(),
                    ),
                    (
                        "signature",
                        pk.as_slice(),
                        pre.as_slice(),
                        message.as_slice(),
                        modified_sig.as_slice(),
                    ),
                    (
                        "short_signature",
                        pk.as_slice(),
                        pre.as_slice(),
                        message.as_slice(),
                        &sig[..sig.len() - 1],
                    ),
                    (
                        "short_public_key",
                        &pk[..pk.len() - 1],
                        pre.as_slice(),
                        message.as_slice(),
                        sig.as_slice(),
                    ),
                    (
                        "empty_signature",
                        pk.as_slice(),
                        pre.as_slice(),
                        message.as_slice(),
                        &[],
                    ),
                ];

                for (mutation, key, prefix, msg, signature) in variants {
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        verify_preformatted(mode, key, prefix, msg, signature)
                    }));

                    match result {
                        Ok(Err(error)) => {
                            println!(
                                "HAETAE_NEGATIVE_MODE={number} CASE={case} \
                                 MUTATION={mutation} ERROR={error:?} STATUS=PASS"
                            );
                        }
                        Ok(Ok(())) => panic!(
                            "INVALID_SIGNATURE_ACCEPTED mode={number} \
                             case={case} mutation={mutation}"
                        ),
                        Err(_) => panic!(
                            "VERIFIER_PANIC mode={number} \
                             case={case} mutation={mutation}"
                        ),
                    }

                    checked += 1;
                }
            }
        }

        assert_eq!(checked, 105);
        println!("HAETAE_NATIVE_NEGATIVE_TOTAL={checked} STATUS=PASS");
    }

    #[test]
    fn authenticated_native_verification_stress_and_norm_bounds() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        // Directly exercise the early norm rejection helper.
        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let coefficient = 30_000_i32;

            let z1 = PolyVecL::<4>::new(std::array::from_fn(|_| Poly::new([coefficient; N])));

            assert_eq!(
                checked_z1_norm(mode, &z1),
                Err(VerificationError::NormExceeded)
            );
        }

        let root = std::env::var("HAETAE_C_VERIFICATION_ROOT")
            .expect("HAETAE_C_VERIFICATION_ROOT missing");
        let root = Path::new(&root);

        let mut checked = 0_usize;

        for (number, mode) in [
            (2, ParameterSet::Haetae2),
            (3, ParameterSet::Haetae3),
            (5, ParameterSet::Haetae5),
        ] {
            let path = root
                .join("rust-fixtures")
                .join(format!("retry_mode{number}.txt"));

            for (case, record) in cases(&path).iter().enumerate() {
                let pk = decode_hex(&record["PK"]);
                let pre = decode_hex(&record["PRE"]);
                let message = decode_hex(&record["MESSAGE"]);
                let signature = decode_hex(&record["SIGNATURE"]);

                // Mutate every signature byte with a fixed bit mask.
                for index in 0..signature.len() {
                    let mut mutated = signature.clone();
                    mutated[index] ^= 0x80;

                    let result = catch_unwind(AssertUnwindSafe(|| {
                        verify_preformatted(mode, &pk, &pre, &message, &mutated)
                    }));

                    assert!(
                        matches!(result, Ok(Err(_))),
                        "mode={number} case={case} byte={index} result={result:?}"
                    );

                    checked += 1;
                }
            }
        }

        println!("HAETAE_NATIVE_STRESS_MUTATIONS={checked} STATUS=PASS");
    }

    #[test]
    fn authenticated_native_verification_accepts_c_signatures() {
        let root = std::env::var("HAETAE_C_VERIFICATION_ROOT")
            .expect("HAETAE_C_VERIFICATION_ROOT missing");
        let root = Path::new(&root);

        let mut total = 0;

        for (number, mode) in [
            (2, ParameterSet::Haetae2),
            (3, ParameterSet::Haetae3),
            (5, ParameterSet::Haetae5),
        ] {
            let path = root
                .join("rust-fixtures")
                .join(format!("retry_mode{number}.txt"));

            for (case, record) in cases(&path).iter().enumerate() {
                assert_eq!(record["CASE"].parse::<usize>().unwrap(), case);

                let pk = decode_hex(&record["PK"]);
                let pre = decode_hex(&record["PRE"]);
                let message = decode_hex(&record["MESSAGE"]);
                let signature = decode_hex(&record["SIGNATURE"]);

                let result = verify_preformatted(mode, &pk, &pre, &message, &signature);

                println!(
                    "HAETAE_NATIVE_VERIFY_MODE={number} \
                     CASE={case} RESULT={result:?}"
                );

                assert_eq!(
                    result,
                    Ok(()),
                    "native verification failed: mode={number} case={case}"
                );

                total += 1;
            }
        }

        assert_eq!(total, 15);
        println!("HAETAE_NATIVE_VERIFY_TOTAL={total} STATUS=PASS");
    }
}
