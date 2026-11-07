//! Authenticated HAETAE signing-response differential parity.
//!
//! Native signing-response arithmetic with authenticated differential tests.

use crate::packing::unpack_secret_key;
use crate::params::{ParameterSet, N};
use crate::poly::Poly;
use zeroize::Zeroizing;
// HAETAE_10K_7D_4B_2_RESPONSE_TEMPORARIES
use crate::polyvec::{PolyVecK, PolyVecL, PolyVecM};

fn add_fixed<const D: usize>(sampled: &[[i32; N]], correction: &[Poly]) -> [Poly; D] {
    assert_eq!(sampled.len(), D);
    assert_eq!(correction.len(), D);

    std::array::from_fn(|i| {
        Poly::new(std::array::from_fn(|j| {
            sampled[i][j]
                .checked_add(
                    correction[i].coeffs[j]
                        .checked_mul(8192)
                        .expect("fixed-point correction overflow"),
                )
                .expect("fixed-point response overflow")
        }))
    })
}

fn norm2(polynomials: &[Poly]) -> u64 {
    polynomials.iter().fold(0_u64, |total, poly| {
        poly.coeffs.iter().fold(total, |sum, &coefficient| {
            let value = i64::from(coefficient);
            sum.checked_add((value * value) as u64)
                .expect("squared norm overflow")
        })
    })
}

fn twice_minus_y<const D: usize>(response: &[Poly; D], sampled: &[[i32; N]]) -> [Poly; D] {
    std::array::from_fn(|i| {
        Poly::new(std::array::from_fn(|j| {
            response[i].coeffs[j]
                .checked_mul(2)
                .and_then(|value| value.checked_sub(sampled[i][j]))
                .expect("2z-y overflow")
        }))
    })
}

#[derive(Debug)]
pub(crate) struct SigningResponse<const L: usize, const K: usize> {
    pub(crate) z1: [Poly; L],
    pub(crate) z2: [Poly; K],
    pub(crate) norm_z: u64,
    pub(crate) norm_tmp: u64,
    pub(crate) reject1: u64,
    pub(crate) reject2: u64,
}

// HAETAE_10K_7D_4B_1_RESPONSE_LIFECYCLE
impl<const L: usize, const K: usize> SigningResponse<L, K> {
    fn zeroize_secret_material(&mut self) {
        use zeroize::Zeroize;

        for polynomial in &mut self.z1 {
            polynomial.coeffs.zeroize();
        }
        for polynomial in &mut self.z2 {
            polynomial.coeffs.zeroize();
        }
    }
}

impl<const L: usize, const K: usize> Drop for SigningResponse<L, K> {
    fn drop(&mut self) {
        self.zeroize_secret_material();
    }
}

#[cfg(test)]
mod signing_response_lifecycle_tests {
    use super::*;

    fn check<const L: usize, const K: usize>() {
        let mut response: SigningResponse<L, K> = SigningResponse {
            z1: std::array::from_fn(|_| Poly::new([0x1234; N])),
            z2: std::array::from_fn(|_| Poly::new([0x5678; N])),
            norm_z: 123,
            norm_tmp: 456,
            reject1: 1,
            reject2: 0,
        };

        response.zeroize_secret_material();

        assert!(response.z1.iter().all(|p| p.coeffs.iter().all(|&x| x == 0)));
        assert!(response.z2.iter().all(|p| p.coeffs.iter().all(|&x| x == 0)));

        assert_eq!(response.norm_z, 123);
        assert_eq!(response.norm_tmp, 456);
        assert_eq!(response.reject1, 1);
        assert_eq!(response.reject2, 0);

        response.zeroize_secret_material();

        assert!(response.z1.iter().all(|p| p.coeffs.iter().all(|&x| x == 0)));
        assert!(response.z2.iter().all(|p| p.coeffs.iter().all(|&x| x == 0)));
    }

    #[test]
    fn clears_all_haetae_response_dimensions() {
        check::<4, 2>();
        check::<6, 3>();
        check::<7, 4>();
    }
}

/// Evaluate the complete response, preserving coefficients for signature packing.
/// Evaluate one native Rust signing response and its rejection predicates.
pub(crate) fn evaluate_signing_response<const K: usize, const L: usize, const M: usize>(
    sk: &[u8],
    mode: ParameterSet,
    challenge: &Poly,
    b: u8,
    y1: &[[i32; N]],
    y2: &[[i32; N]],
    thresholds: (u64, u64),
) -> (u64, u64, u64, u64) {
    let response =
        evaluate_signing_response_complete::<K, L, M>(sk, mode, challenge, b, y1, y2, thresholds);
    debug_assert_eq!(response.z1.len(), L);
    debug_assert_eq!(response.z2.len(), K);
    (
        response.norm_z,
        response.norm_tmp,
        response.reject1,
        response.reject2,
    )
}

pub(crate) fn evaluate_signing_response_complete<const K: usize, const L: usize, const M: usize>(
    sk: &[u8],
    mode: ParameterSet,
    challenge: &Poly,
    b: u8,
    y1: &[[i32; N]],
    y2: &[[i32; N]],
    thresholds: (u64, u64),
) -> SigningResponse<L, K> {
    assert_eq!(M + 1, L);
    assert_eq!(y1.len(), L);
    assert_eq!(y2.len(), K);

    let mut decoded = unpack_secret_key::<K, M>(sk, mode).expect("secret key");

    decoded.s0.ntt();
    decoded.s1.ntt();

    evaluate_signing_response_predecoded::<K, L, M>(
        &decoded.s0,
        &decoded.s1,
        challenge,
        b,
        y1,
        y2,
        thresholds,
    )
}

/// Evaluate a response using predecoded NTT-domain secret polynomials.
///
/// The caller retains ownership of the secret vectors.
pub(crate) fn evaluate_signing_response_predecoded<
    const K: usize,
    const L: usize,
    const M: usize,
>(
    s0_ntt: &PolyVecM<M>,
    s1_ntt: &PolyVecK<K>,
    challenge: &Poly,
    b: u8,
    y1: &[[i32; N]],
    y2: &[[i32; N]],
    thresholds: (u64, u64),
) -> SigningResponse<L, K> {
    assert_eq!(M + 1, L);
    assert_eq!(y1.len(), L);
    assert_eq!(y2.len(), K);

    let mut challenge_ntt = challenge.clone();
    challenge_ntt.ntt();

    let mut cs1 = Zeroizing::new(PolyVecL::<L>::new(std::array::from_fn(|i| {
        if i == 0 {
            challenge.clone()
        } else {
            let mut product = challenge_ntt.pointwise_montgomery(&s0_ntt.as_slice()[i - 1]);
            product.invntt_tomont();
            product
        }
    })));

    let mut cs2 = Zeroizing::new(s1_ntt.pointwise_montgomery(&challenge_ntt));
    cs2.invntt_tomont();

    cs1.cneg(b & 1);
    cs2.cneg(b & 1);

    let z1 = add_fixed::<L>(y1, cs1.as_slice());
    let z2 = add_fixed::<K>(y2, cs2.as_slice());

    let norm_z = norm2(&z1)
        .checked_add(norm2(&z2))
        .expect("combined response norm overflow");

    let z1tmp = Zeroizing::new(twice_minus_y(&z1, y1));
    let z2tmp = Zeroizing::new(twice_minus_y(&z2, y2));

    let norm_tmp = norm2(&z1tmp[..])
        .checked_add(norm2(&z2tmp[..]))
        .expect("combined temporary norm overflow");

    let (threshold1, threshold0) = thresholds;

    let reject1 = (threshold1.wrapping_sub(norm_z) >> 63) & 1;

    let reject2 = ((norm_tmp.wrapping_sub(threshold0) >> 63) & 1) & u64::from((b >> 1) & 1);

    SigningResponse {
        z1,
        z2,
        norm_z,
        norm_tmp,
        reject1,
        reject2,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::params::signing_rejection_thresholds;
    use std::collections::BTreeMap;

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16).expect("hex")
            })
            .collect()
    }

    fn parse_poly(value: &str) -> Poly {
        let coefficients: Vec<i32> = value
            .split(',')
            .map(|item| item.parse::<i32>().expect("coefficient"))
            .collect();
        Poly::new(coefficients.try_into().expect("256 coefficients"))
    }

    fn response_fixture(mode: u8) -> &'static str {
        match mode {
            2 => include_str!("response_fixtures/response_mode2.txt"),
            3 => include_str!("response_fixtures/response_mode3.txt"),
            5 => include_str!("response_fixtures/response_mode5.txt"),
            _ => panic!("unsupported mode"),
        }
    }

    fn keypair_fixture(mode: u8) -> &'static str {
        match mode {
            2 => include_str!("response_fixtures/keypair_mode2.txt"),
            3 => include_str!("response_fixtures/keypair_mode3.txt"),
            5 => include_str!("response_fixtures/keypair_mode5.txt"),
            _ => panic!("unsupported mode"),
        }
    }

    fn response_records(contents: &str) -> Vec<BTreeMap<String, String>> {
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

    fn keypair_records(contents: &str) -> Vec<BTreeMap<String, String>> {
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 27);

        (0..5)
            .map(|case| {
                let block = &lines[2 + case * 5..2 + (case + 1) * 5];
                assert_eq!(block[0], format!("CASE={case}"));
                assert_eq!(block[4], format!("END_CASE={case}"));

                let mut record = BTreeMap::new();
                record.insert("CASE".into(), case.to_string());

                for line in &block[1..4] {
                    let (key, value) = line.split_once('=').expect("keypair field");
                    assert!(record.insert(key.into(), value.into()).is_none());
                }

                record
            })
            .collect()
    }

    fn assert_vector(
        record: &BTreeMap<String, String>,
        prefix: &str,
        actual: &[Poly],
        mode: u8,
        case: usize,
    ) {
        for (i, polynomial) in actual.iter().enumerate() {
            assert_eq!(
                *polynomial,
                parse_poly(&record[&format!("{prefix}_{i}")]),
                "MODE={mode} CASE={case} FIELD={prefix}_{i}"
            );
        }
    }

    /// Retrieve rejection thresholds from the authenticated response oracle.
    pub(crate) fn reference_response_thresholds(mode: u8) -> (u64, u64) {
        let parameter_set = match mode {
            2 => ParameterSet::Haetae2,
            3 => ParameterSet::Haetae3,
            5 => ParameterSet::Haetae5,
            _ => panic!("unsupported mode"),
        };

        let expected = signing_rejection_thresholds(parameter_set);

        for record in response_records(response_fixture(mode)) {
            let oracle = (
                record["THRESHOLD1"].parse::<u64>().expect("threshold1"),
                record["THRESHOLD0"].parse::<u64>().expect("threshold0"),
            );
            assert_eq!(expected, oracle, "normative threshold mismatch");
        }

        expected
    }

    fn run<const K: usize, const L: usize, const M: usize>(mode_number: u8, mode: ParameterSet) {
        assert_eq!(M + 1, L);

        let responses = response_records(response_fixture(mode_number));
        let keys = keypair_records(keypair_fixture(mode_number));

        for (case, (record, key)) in responses.iter().zip(&keys).enumerate() {
            assert_eq!(record["CASE"], case.to_string());
            assert_eq!(record["SEED"], key["SEED"]);

            let pk = decode_hex(&record["PK"]);
            assert_eq!(pk, decode_hex(&key["PK"]));

            let sk = decode_hex(&key["SK"]);
            let mut decoded = unpack_secret_key::<K, M>(&sk, mode).expect("secret key");
            assert_eq!(decoded.public_key, pk);

            let challenge = parse_poly(&record["CHALLENGE"]);
            let mut challenge_ntt = challenge.clone();
            challenge_ntt.ntt();

            decoded.s0.ntt();
            decoded.s1.ntt();

            let mut cs1 = PolyVecL::<L>::new(std::array::from_fn(|i| {
                if i == 0 {
                    challenge.clone()
                } else {
                    let mut product =
                        challenge_ntt.pointwise_montgomery(&decoded.s0.as_slice()[i - 1]);
                    product.invntt_tomont();
                    product
                }
            }));

            let mut cs2 = decoded.s1.pointwise_montgomery(&challenge_ntt);
            cs2.invntt_tomont();

            assert_vector(record, "CS1", cs1.as_slice(), mode_number, case);
            assert_vector(record, "CS2", cs2.as_slice(), mode_number, case);

            let b: u8 = record["B"].parse().expect("selector");
            cs1.cneg(b & 1);
            cs2.cneg(b & 1);

            assert_vector(record, "CS1_SIGNED", cs1.as_slice(), mode_number, case);
            assert_vector(record, "CS2_SIGNED", cs2.as_slice(), mode_number, case);

            let y1: Vec<[i32; N]> = (0..L)
                .map(|i| parse_poly(&record[&format!("Y1_{i}")]).coeffs)
                .collect();

            let y2: Vec<[i32; N]> = (0..K)
                .map(|i| parse_poly(&record[&format!("Y2_{i}")]).coeffs)
                .collect();

            let z1 = add_fixed::<L>(&y1, cs1.as_slice());
            let z2 = add_fixed::<K>(&y2, cs2.as_slice());

            assert_vector(record, "Z1", &z1, mode_number, case);
            assert_vector(record, "Z2", &z2, mode_number, case);

            let norm_z = norm2(&z1)
                .checked_add(norm2(&z2))
                .expect("combined norm overflow");

            let t1: u64 = record["THRESHOLD1"].parse().expect("threshold1");
            let t0: u64 = record["THRESHOLD0"].parse().expect("threshold0");

            assert_eq!(
                norm_z,
                record["NORM_Z"].parse::<u64>().expect("norm z"),
                "MODE={mode_number} CASE={case} NORM_Z"
            );

            let z1tmp = twice_minus_y(&z1, &y1);
            let z2tmp = twice_minus_y(&z2, &y2);

            let norm_tmp = norm2(&z1tmp)
                .checked_add(norm2(&z2tmp))
                .expect("combined temporary norm overflow");

            assert_eq!(
                norm_tmp,
                record["NORM_2Z_MINUS_Y"]
                    .parse::<u64>()
                    .expect("temporary norm"),
                "MODE={mode_number} CASE={case} NORM_2Z_MINUS_Y"
            );

            let reject1 = (t1.wrapping_sub(norm_z) >> 63) & 1;
            let reject2 = ((norm_tmp.wrapping_sub(t0) >> 63) & 1) & u64::from((b >> 1) & 1);

            assert_eq!(
                reject1,
                record["REJECT1"].parse::<u64>().expect("reject1"),
                "MODE={mode_number} CASE={case} REJECT1"
            );
            assert_eq!(
                reject2,
                record["REJECT2"].parse::<u64>().expect("reject2"),
                "MODE={mode_number} CASE={case} REJECT2"
            );
            assert_eq!(
                reject1 | reject2,
                record["REJECT"].parse::<u64>().expect("reject"),
                "MODE={mode_number} CASE={case} REJECT"
            );

            println!(
                "MODE={mode_number} CASE={case} \
             REJECT1={reject1} REJECT2={reject2} STATUS=PASS"
            );
        }
    }

    #[test]
    fn response_mode2() {
        run::<2, 4, 3>(2, ParameterSet::Haetae2);
    }

    #[test]
    fn response_mode3() {
        run::<3, 6, 5>(3, ParameterSet::Haetae3);
    }

    #[test]
    fn response_mode5() {
        run::<4, 7, 6>(5, ParameterSet::Haetae5);
    }
}
