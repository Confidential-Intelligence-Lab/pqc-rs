//! Authenticated signing challenge-preparation parity.

use crate::challenge::{pack_challenge_transcript, sample_challenge};
use crate::packing::unpack_verification_key;
use crate::params::{ParameterSet, N};
use crate::poly::Poly;
use crate::polyvec::{PolyVecK, PolyVecL};
use zeroize::Zeroizing;

fn round_fixed(x: i32) -> i32 {
    x.checked_add(4096)
        .expect("HAETAE fixed-point rounding overflow")
        >> 13
}

#[derive(Debug)]
pub(crate) struct SigningChallengePreparation<const K: usize> {
    pub(crate) challenge: Poly,
    pub(crate) ay: PolyVecK<K>,
    pub(crate) highbits: PolyVecK<K>,
}

// HAETAE_10K_7D_4C_8C_RETAINED_AY_LIFECYCLE
impl<const K: usize> Drop for SigningChallengePreparation<K> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.ay);
    }
}

/// Preserve the established challenge-only interface.
pub(crate) fn prepare_signing_challenge<const K: usize, const L: usize>(
    mode_number: u8,
    mode: ParameterSet,
    pk: &[u8],
    mu: &[u8; 64],
    y1: &[[i32; N]],
    y2: &[[i32; N]],
) -> Poly {
    let prepared = prepare_signing_challenge_complete::<K, L>(mode_number, mode, pk, mu, y1, y2);

    assert_eq!(
        prepared.ay.highbits_hint(mode).as_slice(),
        prepared.highbits.as_slice(),
        "retained HAETAE signing highbits mismatch"
    );

    prepared.challenge.clone()
}

/// Prepare the HAETAE signing challenge from one accepted hyperball sample.
///
/// Internal signing primitive; the public signer is not yet integrated.
pub(crate) fn prepare_signing_challenge_complete<const K: usize, const L: usize>(
    mode_number: u8,
    mode: ParameterSet,
    pk: &[u8],
    mu: &[u8; 64],
    y1: &[[i32; N]],
    y2: &[[i32; N]],
) -> SigningChallengePreparation<K> {
    let vk = unpack_verification_key::<K, L>(pk, mode).expect("verification key");

    prepare_signing_challenge_predecoded::<K, L>(mode_number, mode, &vk, mu, y1, y2)
}

pub(crate) fn prepare_signing_challenge_predecoded<const K: usize, const L: usize>(
    mode_number: u8,
    mode: ParameterSet,
    vk: &crate::packing::ReconstructedVerificationKey<K, L>,
    mu: &[u8; 64],
    y1: &[[i32; N]],
    y2: &[[i32; N]],
) -> SigningChallengePreparation<K> {
    assert_eq!(y1.len(), L);
    assert_eq!(y2.len(), K);

    // HAETAE_10K_7D_4C_8A_CHALLENGE_TEMPORARY_LIFECYCLE
    let mut z1rnd = Zeroizing::new(PolyVecL::<L>::new(std::array::from_fn(|i| {
        Poly::new(std::array::from_fn(|j| round_fixed(y1[i][j])))
    })));

    let mut z2rnd = Zeroizing::new(PolyVecK::<K>::new(std::array::from_fn(|i| {
        Poly::new(std::array::from_fn(|j| round_fixed(y2[i][j])))
    })));

    let z1rnd0 = Zeroizing::new(z1rnd.as_slice()[0].clone());

    z1rnd.ntt();

    let mut ay = PolyVecK::<K>::new(std::array::from_fn(|i| {
        vk.matrix[i].pointwise_acc_montgomery(&z1rnd)
    }));

    ay.invntt_tomont();
    z2rnd.double();
    let replacement = ay.add(&z2rnd);
    let _displaced_ay_add = Zeroizing::new(std::mem::replace(&mut ay, replacement));

    // Signing-specific CRT accepts unreduced inverse-NTT coefficients.
    // The result is subsequently reduced modulo 2q.
    let before_crt = Zeroizing::new(ay.clone());

    let replacement = PolyVecK::<K>::new(std::array::from_fn(|i| {
        Poly::new(std::array::from_fn(|j| {
            let xq = before_crt.as_slice()[i].coeffs[j];
            let parity = if i == 0 { z1rnd0.coeffs[j] & 1 } else { 0 };

            let correction = crate::params::Q & -((xq ^ parity) & 1);

            xq.checked_add(correction)
                .expect("HAETAE signing CRT overflow")
        }))
    }));
    let _displaced_ay_crt = Zeroizing::new(std::mem::replace(&mut ay, replacement));

    ay.freeze2q();

    let highbits = ay.highbits_hint(mode);
    let lsb = z1rnd0.lsb();

    let transcript = pack_challenge_transcript(mode_number, highbits.as_slice(), &lsb)
        .expect("challenge transcript");

    let challenge_mu: [u8; 32] = mu[..32].try_into().expect("32-byte challenge mu");

    let challenge =
        sample_challenge(mode_number, &transcript, &challenge_mu).expect("signing challenge");

    SigningChallengePreparation {
        challenge,
        ay,
        highbits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyperball::sample_hyperball;
    use std::collections::BTreeMap;

    fn parse_poly(encoded: &str) -> Poly {
        let values: Vec<i32> = encoded
            .split(',')
            .map(|x| x.parse::<i32>().expect("coefficient"))
            .collect();
        Poly::new(values.try_into().expect("256 coefficients"))
    }

    fn decode_hex(encoded: &str) -> Vec<u8> {
        assert_eq!(encoded.len() % 2, 0);
        encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                    .expect("hex byte")
            })
            .collect()
    }

    fn records(contents: &str) -> Vec<BTreeMap<String, String>> {
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

    fn fixture(mode: u8) -> &'static str {
        match mode {
            2 => include_str!("challenge_fixtures/mode2.txt"),
            3 => include_str!("challenge_fixtures/mode3.txt"),
            5 => include_str!("challenge_fixtures/mode5.txt"),
            _ => panic!("unsupported mode"),
        }
    }

    fn run<const K: usize, const L: usize>(mode_number: u8, mode: ParameterSet) {
        for record in records(fixture(mode_number)) {
            let case = &record["CASE"];

            let pk = decode_hex(&record["PK"]);
            let seed: [u8; 64] = decode_hex(&record["HYPERBALL_SEED"])
                .try_into()
                .expect("hyperball seed");
            let mu: [u8; 32] = decode_hex(&record["MU"]).try_into().expect("mu");

            let nonce: u16 = record["INITIAL_NONCE"].parse().expect("nonce");

            let sampled = sample_hyperball(mode_number, &seed, nonce).expect("hyperball sample");

            assert_eq!(
                sampled.next_nonce,
                record["NEXT_NONCE"].parse::<u16>().expect("next nonce"),
                "nonce mismatch mode={mode_number} case={case}"
            );
            assert_eq!(
                sampled.b,
                record["B"].parse::<u8>().expect("selector"),
                "selector mismatch mode={mode_number} case={case}"
            );

            assert_eq!(sampled.y1.len(), L);
            assert_eq!(sampled.y2.len(), K);

            for i in 0..L {
                assert_eq!(
                    Poly::new(sampled.y1[i]),
                    parse_poly(&record[&format!("Y1_{i}")]),
                    "Y1 mismatch mode={mode_number} case={case} poly={i}"
                );
            }

            for i in 0..K {
                assert_eq!(
                    Poly::new(sampled.y2[i]),
                    parse_poly(&record[&format!("Y2_{i}")]),
                    "Y2 mismatch mode={mode_number} case={case} poly={i}"
                );
            }

            let mut z1rnd = PolyVecL::<L>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| round_fixed(sampled.y1[i][j])))
            }));

            let mut z2rnd = PolyVecK::<K>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| round_fixed(sampled.y2[i][j])))
            }));

            let z1rnd0 = z1rnd.as_slice()[0].clone();

            assert_eq!(
                z1rnd0,
                parse_poly(&record["Z1RND0"]),
                "Z1RND0 mismatch mode={mode_number} case={case}"
            );

            z1rnd.ntt();

            for i in 0..L {
                assert_eq!(
                    z1rnd.as_slice()[i],
                    parse_poly(&record[&format!("Z1RND_NTT_{i}")]),
                    "Z1RND_NTT mismatch mode={mode_number} case={case} poly={i}"
                );
            }

            let vk = unpack_verification_key::<K, L>(&pk, mode).expect("verification key");

            let mut ay = PolyVecK::<K>::new(std::array::from_fn(|i| {
                vk.matrix[i].pointwise_acc_montgomery(&z1rnd)
            }));

            ay.invntt_tomont();

            z2rnd.double();

            for i in 0..K {
                assert_eq!(
                    z2rnd.as_slice()[i],
                    parse_poly(&record[&format!("Z2RND_DOUBLED_{i}")]),
                    "Z2RND_DOUBLED mismatch mode={mode_number} case={case} poly={i}"
                );
            }

            ay = ay.add(&z2rnd);

            // Signing-specific CRT: the C reference accepts unreduced
            // inverse-NTT coefficients and freezes modulo 2q afterward.
            //
            // Do not use PolyVecK::poly_fromcrt here: that operation
            // intentionally requires canonical modulo-q inputs.
            let ay_before_crt = ay.clone();
            ay = PolyVecK::<K>::new(std::array::from_fn(|i| {
                Poly::new(std::array::from_fn(|j| {
                    let xq = ay_before_crt.as_slice()[i].coeffs[j];
                    let parity = if i == 0 { z1rnd0.coeffs[j] & 1 } else { 0 };

                    let correction = crate::params::Q & -((xq ^ parity) & 1);
                    xq.checked_add(correction)
                        .expect("HAETAE signing CRT overflow")
                }))
            }));

            ay.freeze2q();

            for i in 0..K {
                assert_eq!(
                    ay.as_slice()[i],
                    parse_poly(&record[&format!("AY_{i}")]),
                    "AY mismatch mode={mode_number} case={case} poly={i}"
                );
            }

            let highbits = ay.highbits_hint(mode);
            let lsb = z1rnd0.lsb();

            for i in 0..K {
                assert_eq!(
                    highbits.as_slice()[i],
                    parse_poly(&record[&format!("HIGHBITS_{i}")]),
                    "HIGHBITS mismatch mode={mode_number} case={case} poly={i}"
                );
            }

            assert_eq!(
                lsb,
                parse_poly(&record["LSB"]),
                "LSB mismatch mode={mode_number} case={case}"
            );

            let transcript = pack_challenge_transcript(mode_number, highbits.as_slice(), &lsb)
                .expect("challenge transcript");

            assert_eq!(
                transcript,
                decode_hex(&record["TRANSCRIPT"]),
                "TRANSCRIPT mismatch mode={mode_number} case={case}"
            );

            let challenge = sample_challenge(mode_number, &transcript, &mu).expect("challenge");

            assert_eq!(
                challenge,
                parse_poly(&record["CHALLENGE"]),
                "CHALLENGE mismatch mode={mode_number} case={case}"
            );

            println!("MODE={mode_number} CASE={case} INTEGRATED_PARITY=PASS");
        }
    }

    #[test]
    fn integrated_challenge_mode2() {
        run::<2, 4>(2, ParameterSet::Haetae2);
    }

    #[test]
    fn integrated_challenge_mode3() {
        run::<3, 6>(3, ParameterSet::Haetae3);
    }

    #[test]
    fn integrated_challenge_mode5() {
        run::<4, 7>(5, ParameterSet::Haetae5);
    }

    #[test]
    fn fixed_point_rounding_boundaries() {
        for x in [
            -8193_i32, -8192, -4097, -4096, -1, 0, 4095, 4096, 8191, 8192,
        ] {
            assert_eq!(
                round_fixed(x),
                (i64::from(x) + 4096).div_euclid(8192) as i32
            );
        }
        assert_eq!(N, 256);
    }
}
