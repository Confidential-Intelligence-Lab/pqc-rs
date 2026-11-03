// SPDX-License-Identifier: MIT

//! Native HAETAE 1.2.0 Gaussian arithmetic.
//!
//! CDT constants are extracted from the authenticated C reference.
//! This module is experimental and not yet suitable for production use.

const CDT83_HI: [u32; 76] = [
    0x063a5_u32,
    0x0c718_u32,
    0x129f6_u32,
    0x18bdf_u32,
    0x1ec73_u32,
    0x24b59_u32,
    0x2a83a_u32,
    0x302c6_u32,
    0x35ab6_u32,
    0x3afc7_u32,
    0x401be_u32,
    0x4506a_u32,
    0x49ba1_u32,
    0x4e343_u32,
    0x52736_u32,
    0x5676c_u32,
    0x5a3dc_u32,
    0x5dc86_u32,
    0x61172_u32,
    0x642ad_u32,
    0x6704c_u32,
    0x69a68_u32,
    0x6c120_u32,
    0x6e496_u32,
    0x704ef_u32,
    0x72255_u32,
    0x73cf1_u32,
    0x754f0_u32,
    0x76a7c_u32,
    0x77dc4_u32,
    0x78ef2_u32,
    0x79e32_u32,
    0x7abaf_u32,
    0x7b78f_u32,
    0x7c1fb_u32,
    0x7cb17_u32,
    0x7d304_u32,
    0x7d9e4_u32,
    0x7dfd4_u32,
    0x7e4f0_u32,
    0x7e950_u32,
    0x7ed0d_u32,
    0x7f03b_u32,
    0x7f2ec_u32,
    0x7f531_u32,
    0x7f71a_u32,
    0x7f8b3_u32,
    0x7fa08_u32,
    0x7fb24_u32,
    0x7fc0e_u32,
    0x7fccf_u32,
    0x7fd6e_u32,
    0x7fdf0_u32,
    0x7fe5a_u32,
    0x7feaf_u32,
    0x7fef5_u32,
    0x7ff2c_u32,
    0x7ff59_u32,
    0x7ff7d_u32,
    0x7ff99_u32,
    0x7ffb0_u32,
    0x7ffc2_u32,
    0x7ffd0_u32,
    0x7ffdb_u32,
    0x7ffe3_u32,
    0x7ffea_u32,
    0x7ffef_u32,
    0x7fff3_u32,
    0x7fff6_u32,
    0x7fff8_u32,
    0x7fffa_u32,
    0x7fffb_u32,
    0x7fffd_u32,
    0x7fffd_u32,
    0x7fffe_u32,
    0x7fffe_u32,
];

const CDT83_LO: [u64; 166] = [
    0x0aa572bc88db1e28_u64,
    0x4f3820e69064b2ee_u64,
    0xd68dc44dd1418704_u64,
    0x6587a04d9b97b1dd_u64,
    0x9b843ce0a65d0050_u64,
    0x02b62cb869003e7d_u64,
    0x0d44f194f8bf43c6_u64,
    0xfaa0c7acb211b4db_u64,
    0xa11387f7f524be80_u64,
    0x18526ca6f2ceb77f_u64,
    0x42a01a906b7dad17_u64,
    0x32e5337a1966b9a7_u64,
    0x6f00f7ac9735f58a_u64,
    0x0e6c48f40642ba60_u64,
    0xb6192fa1afb5e4ec_u64,
    0x7339dba8ffc2fcf5_u64,
    0x7746cbe1ac90c9eb_u64,
    0xb83004341d78466f_u64,
    0x781dcca572bb3d8a_u64,
    0xb880376cc82a5384_u64,
    0x9c68a5c477dfecb9_u64,
    0xbe45ceb02a25fef3_u64,
    0x7d1a8ccd208dbaa1_u64,
    0x452c002b9085e7db_u64,
    0xd7ef361c5551378d_u64,
    0x96b4ff49d9e5a8bb_u64,
    0xd337c94ede732d83_u64,
    0x28c75b8d3fe83c38_u64,
    0xe05d7bd130fe20e0_u64,
    0x6170e60b76d85108_u64,
    0xb0e59892414901ff_u64,
    0xff05cf70b911f3de_u64,
    0x4501460fdfd508c9_u64,
    0xf20b1303a2a54906_u64,
    0xa7d3badbeb04b20c_u64,
    0x05ce666b741b666d_u64,
    0x826e689fded20430_u64,
    0x5155d1354fcf6ff6_u64,
    0x55469226a1d318f6_u64,
    0x1c8d3820cfa9cabc_u64,
    0xe68d83bbf700fc40_u64,
    0xb1152d8944042803_u64,
    0x4c1e741aabe53700_u64,
    0x72b94c56e0f9a967_u64,
    0xe7e5a80a79e4539c_u64,
    0x9641c5d11feb4d12_u64,
    0xb18b71598b73dde0_u64,
    0xd9112fb5a7904d7e_u64,
    0x3a4f57cbefabc820_u64,
    0xb314025fd5022976_u64,
    0xf2a2b228aab1981b_u64,
    0x996ce1e60378cd98_u64,
    0x570ec64b38e3ca90_u64,
    0x0657269615dcd7c6_u64,
    0xc7360038bdc85312_u64,
    0x167fa02a57a8ae1a_u64,
    0xe380fab2ea9b2bef_u64,
    0xa36e6abd6509b5a2_u64,
    0x62bfcf1d6ba81c37_u64,
    0xd4946e8bf96caa93_u64,
    0x603e6262ea8cda2d_u64,
    0x2d18c8b333ae9203_u64,
    0x2ccdedb5a7718d61_u64,
    0x24333ecab8497c0a_u64,
    0xb2e06eb33bf2b7d9_u64,
    0x59a5f6c550dfe7e2_u64,
    0x800548f3927f906e_u64,
    0x78cac146b573bc40_u64,
    0x85e6dadec4b6aff1_u64,
    0xdba17dfa17def8ec_u64,
    0xa33f84d06ce20a93_u64,
    0xfd2fe967c5186746_u64,
    0x02d37ecd7e9b180f_u64,
    0xc7efafa8bd33f0bb_u64,
    0x5bda826341e791cc_u64,
    0xca6c1c6ce045599f_u64,
    0x1cc02c0faa9a526e_u64,
    0x59d002901a4a4e52_u64,
    0x86ecbd139ce07540_u64,
    0xa81f9f15ffb47f4c_u64,
    0xc075b17481687af0_u64,
    0xd23ad13e68301c65_u64,
    0xdf27955fae1c84cb_u64,
    0xe884cdb07368c266_u64,
    0xef46d4f897fc83f6_u64,
    0xf4227e46663ec049_u64,
    0xf79d091c1b5aff07_u64,
    0xfa183c533c3890a6_u64,
    0xfbdb8a602066b0f2_u64,
    0xfd1af06df3db86b7_u64,
    0xfdfc1a818587e2aa_u64,
    0xfe9a37a348ac2a93_u64,
    0xff08d0797970dbfe_u64,
    0xff55df73fd7a00bc_u64,
    0xff8b5aa573bca5ce_u64,
    0xffb053c109f51681_u64,
    0xffc9c9bd39a036ec_u64,
    0xffdb40bd4ee1f846_u64,
    0xffe72fa859b20a4a_u64,
    0xffef4edda93d266d_u64,
    0xfff4d07a9fb0d4e0_u64,
    0xfff88868ef31b1cc_u64,
    0xfffb08c16a3f5f0c_u64,
    0xfffcb5d30be5cabf_u64,
    0xfffdd43465d95fe6_u64,
    0xfffe929a538ad2fa_u64,
    0xffff10b1c2119732_u64,
    0xffff63df8795a2c9_u64,
    0xffff9a87a0a9f2af_u64,
    0xffffbe4df6f0f4a9_u64,
    0xffffd5a10f204910_u64,
    0xffffe4c6f1668b32_u64,
    0xffffee939680bfaf_u64,
    0xfffff4e4216290db_u64,
    0xfffff8f1c044613e_u64,
    0xfffffb892dc2b174_u64,
    0xfffffd2fb4188608_u64,
    0xfffffe3bc0a56eba_u64,
    0xfffffee523b218c6_u64,
    0xffffff4fc31097e3_u64,
    0xffffff929d76dbeb_u64,
    0xffffffbc5e7c0350_u64,
    0xffffffd6586c6684_u64,
    0xffffffe6716865f7_u64,
    0xfffffff0613c76e2_u64,
    0xfffffff67d62ab64_u64,
    0xfffffffa3b6664c0_u64,
    0xfffffffc83e13d66_u64,
    0xfffffffde713ef71_u64,
    0xfffffffebe18936f_u64,
    0xffffffff3fbfc997_u64,
    0xffffffff8d9fa29a_u64,
    0xffffffffbc372590_u64,
    0xffffffffd7fb7dfd_u64,
    0xffffffffe87747f9_u64,
    0xfffffffff2368b89_u64,
    0xfffffffff7f44d88_u64,
    0xfffffffffb52a49b_u64,
    0xfffffffffd4a9ffb_u64,
    0xfffffffffe700579_u64,
    0xffffffffff1a287f_u64,
    0xffffffffff7c6f06_u64,
    0xffffffffffb4fa99_u64,
    0xffffffffffd56300_u64,
    0xffffffffffe7e364_u64,
    0xfffffffffff268d7_u64,
    0xfffffffffff85e8e_u64,
    0xfffffffffffbbb6f_u64,
    0xfffffffffffd9f49_u64,
    0xfffffffffffeae2c_u64,
    0xffffffffffff453d_u64,
    0xffffffffffff9928_u64,
    0xffffffffffffc797_u64,
    0xffffffffffffe12f_u64,
    0xffffffffffffef3c_u64,
    0xfffffffffffff6eb_u64,
    0xfffffffffffffb1b_u64,
    0xfffffffffffffd60_u64,
    0xfffffffffffffe9a_u64,
    0xffffffffffffff43_u64,
    0xffffffffffffff9e_u64,
    0xffffffffffffffce_u64,
    0xffffffffffffffe7_u64,
    0xfffffffffffffff4_u64,
    0xfffffffffffffffb_u64,
    0xfffffffffffffffe_u64,
];

/// Reference-compatible 83-bit CDT sampler.
///
/// The input consists of 64 low bits and 19 high bits.
pub(crate) fn sample_gauss83(rand_lo: u64, rand_hi: u32) -> u64 {
    debug_assert!(rand_hi <= 0x7ffff);

    let random = (u128::from(rand_hi) << 64) | u128::from(rand_lo);
    let mut result = 0_u64;

    for i in 0..CDT83_LO.len() {
        let high = if i < CDT83_HI.len() {
            CDT83_HI[i]
        } else {
            0x7ffff
        };

        let threshold = (u128::from(high) << 64) | u128::from(CDT83_LO[i]);

        // Reference C counts a threshold strictly below the random value.
        result += u64::from(threshold < random);
    }

    result
}

/// Signed ceiling of a * b / 2^48, matching smulh48.
fn smulh48(a: i64, b: u64) -> i64 {
    let product = i128::from(a) * i128::from(b);
    let rounded = (product + ((1_i128 << 48) - 1)) >> 48;
    i64::try_from(rounded).expect("smulh48 result must fit i64")
}

/// Degree-10 reference polynomial approximation to exp(-x).
pub(crate) fn approx_exp(x: u64) -> u64 {
    let mut r = 55_868_746_i64;

    r = smulh48(r, x) - 743_564_434;
    r = smulh48(r, x) + 6_953_427_278;
    r = smulh48(r, x) - 55_833_338_892;
    r = smulh48(r, x) + 390_932_311_155;
    r = smulh48(r, x) - 2_345_623_661_771;
    r = smulh48(r, x) + 11_728_123_872_951;
    r = smulh48(r, x) - 46_912_496_106_200;
    r = smulh48(r, x) + 140_737_488_354_861;
    r = smulh48(r, x) - 281_474_976_710_650;
    r = smulh48(r, x) + 281_474_976_710_657;

    r as u64
}

/// Two-limb fixed-point value used by the HAETAE Gaussian sampler.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Fp96_76 {
    pub(crate) lo: u64,
    pub(crate) hi: u64,
}

const MASK48: u64 = (1_u64 << 48) - 1;

impl Fp96_76 {
    fn renormalize(&mut self) {
        self.hi = self.hi.wrapping_add(self.lo >> 48);
        self.lo &= MASK48;
    }
}

/// Reference-compatible fixed-point square.
///
/// This preserves the truncation points in the C implementation.
pub(crate) fn fixpoint_square(x: Fp96_76) -> Fp96_76 {
    let a = u128::from(x.lo);
    let b = u128::from(x.hi);

    // Reference sq48(a): retain the low 48 bits and the upper
    // product bits in the second limb.
    let aa = a * a;
    let mut lo = (aa as u64) & MASK48;
    let mut hi = ((aa >> 64) as u64) << 16;
    hi |= (aa as u64) >> 48;

    // Reference first shift by 48, without rounding.
    lo >>= 48;
    lo = lo.wrapping_add(hi);

    // Reference mul48(a, b), accumulated twice.
    let ab = a * b;
    let ab_lo = (ab as u64) & MASK48;
    let ab_hi = (((ab >> 64) as u64) << 16) | ((ab as u64) >> 48);

    lo = lo.wrapping_add(ab_lo << 1);
    hi = ab_hi << 1;

    // Reference shift by 28, without rounding.
    lo >>= 28;
    lo = lo.wrapping_add((hi << 20) & MASK48);
    hi >>= 28;

    // Reference sq64(b).
    let bb = b * b;
    let bb_lo = bb as u64;
    let bb_hi = (bb >> 64) as u64;

    lo = lo.wrapping_add((bb_lo << 20) & MASK48);
    hi = hi.wrapping_add((bb_lo >> 28).wrapping_add(bb_hi << 36));

    let mut result = Fp96_76 { lo, hi };
    result.renormalize();
    result
}

/// One 26-byte Gaussian candidate.
///
/// Returns (sample, squared value, accepted).
pub(crate) fn sample_gauss_sigma76(random: &[u8; 26]) -> (u64, Fp96_76, bool) {
    let rand_lo = u64::from_le_bytes(random[0..8].try_into().expect("eight bytes"));

    let rand_hi =
        u32::from(random[8]) | (u32::from(random[9]) << 8) | (u32::from(random[10]) << 16);

    let rand_hi = rand_hi & 0x7ffff;

    let rand_rej = random[11..17]
        .iter()
        .enumerate()
        .fold(0_u64, |acc, (i, &byte)| acc | (u64::from(byte) << (8 * i)));

    let x = sample_gauss83(rand_lo, rand_hi);

    let y_lo = random[17..23]
        .iter()
        .enumerate()
        .fold(0_u64, |acc, (i, &byte)| acc | (u64::from(byte) << (8 * i)));

    let y_hi = u64::from(random[23])
        | (u64::from(random[24]) << 8)
        | (u64::from(random[25]) << 16)
        | (x << 24);

    let y = Fp96_76 { lo: y_lo, hi: y_hi };

    let sample = (((y.lo >> 15) + 1) >> 1).wrapping_add(y.hi << 32);

    let square = fixpoint_square(y);

    let mut exp_in = square.hi.wrapping_sub((x * x) << 20);

    exp_in <<= 20;
    exp_in |= square.lo >> 28;
    exp_in = exp_in.wrapping_add(1);
    exp_in >>= 1;

    let probability = approx_exp(exp_in);

    // Equivalent to the reference's signed subtraction and sign test.
    let accepted_probability = (rand_rej & !1) < probability;

    // For zero, the lowest rejection bit provides the extra 1/2 factor.
    let accepted_zero = sample != 0 || (rand_rej & 1) != 0;

    (sample, square, accepted_probability && accepted_zero)
}

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const GAUSSIAN_BYTES: usize = 26;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GaussianOutput {
    pub(crate) samples: [u64; 256],
    pub(crate) signs: [u8; 32],
    pub(crate) sqsum: Fp96_76,
}

/// Reference-compatible Gaussian sampling from one SHAKE256 stream.
///
/// The reference initially squeezes a fixed number of blocks, then
/// continues squeezing on demand. SHAKE's output is a continuous
/// byte stream, so this produces identical candidate bytes.
pub(crate) fn sample_gauss_n(
    seed: &[u8; 64],
    nonce: u16,
    len: usize,
    initial_sqsum: Fp96_76,
) -> GaussianOutput {
    assert!(len == 256 || len == 257);

    let mut shake = Shake256::default();
    shake.update(seed);
    shake.update(&nonce.to_le_bytes());
    let mut reader = shake.finalize_xof();

    let mut samples = [0_u64; 256];
    let mut signs = [0_u8; 32];
    let mut sqsum = initial_sqsum;

    // C takes the first len / 8 bytes as signs.
    reader.read(&mut signs);

    let mut accepted = 0_usize;

    while accepted < len {
        let mut candidate = [0_u8; GAUSSIAN_BYTES];
        reader.read(&mut candidate);

        let (sample, square, valid) = sample_gauss_sigma76(&candidate);

        if valid {
            if accepted < 256 {
                samples[accepted] = sample;
            }

            sqsum.lo = sqsum.lo.wrapping_add(square.lo);
            sqsum.hi = sqsum.hi.wrapping_add(square.hi);

            accepted += 1;
        }
    }

    sqsum.renormalize();

    GaussianOutput {
        samples,
        signs,
        sqsum,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdt_boundaries() {
        assert_eq!(sample_gauss83(0, 0), 0);
        assert_eq!(sample_gauss83(u64::MAX, 0x7ffff), 166);

        for index in [0, 1, 37, 75, 76, 120, 165] {
            let high = if index < 76 { CDT83_HI[index] } else { 0x7ffff };
            let low = CDT83_LO[index];

            let threshold = (u128::from(high) << 64) | u128::from(low);
            let expected = (0..CDT83_LO.len())
                .filter(|&j| {
                    let h = if j < CDT83_HI.len() {
                        CDT83_HI[j]
                    } else {
                        0x7ffff
                    };
                    ((u128::from(h) << 64) | u128::from(CDT83_LO[j])) < threshold
                })
                .count() as u64;
            assert_eq!(sample_gauss83(low, high), expected);
        }
    }

    #[test]
    fn exponential_origin() {
        assert_eq!(approx_exp(0), 281_474_976_710_657);
    }

    #[test]
    fn fixed_point_square_zero_and_one() {
        assert_eq!(fixpoint_square(Fp96_76::default()), Fp96_76::default());

        let one = Fp96_76 {
            lo: 0,
            hi: 1_u64 << 28,
        };

        assert_eq!(fixpoint_square(one), one);
    }

    #[test]
    fn gaussian_candidate_is_deterministic() {
        for candidate in [[0_u8; 26], [0xff_u8; 26], [0x55_u8; 26]] {
            let a = sample_gauss_sigma76(&candidate);
            let b = sample_gauss_sigma76(&candidate);

            assert_eq!(a, b);
            assert!(a.1.lo <= MASK48);
        }
    }

    #[test]
    fn signed_multiplication_rounding() {
        assert_eq!(smulh48(1, 1), 1);
        assert_eq!(smulh48(-1, 1), 0);
        assert_eq!(smulh48(1, 1_u64 << 48), 1);
        assert_eq!(smulh48(-1, 1_u64 << 48), -1);
    }
}

#[cfg(test)]
mod gaussian_fixture_tests {
    use super::*;

    mod fixtures {
        include!("gaussian_fixtures.rs");
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn check_fixture(text: &str, expected_mode: usize) {
        let mut cases = 0_usize;
        let mut current = std::collections::BTreeMap::new();
        let mut inside_case = false;

        let reference_mode = match expected_mode {
            2 => 0,
            3 => 1,
            5 => 2,
            _ => panic!("unsupported HAETAE mode"),
        };

        assert!(text
            .lines()
            .any(|line| { line == "FORMAT=HAETAE_GAUSSIAN_ORACLE_V1" }));
        assert!(text
            .lines()
            .any(|line| { line == format!("MODE={reference_mode}") }));
        assert!(text.lines().any(|line| line == "N=256"));

        for line in text.lines() {
            if line == "BEGIN_CASE" {
                assert!(!inside_case);
                assert!(current.is_empty());
                inside_case = true;
            } else if line == "END_CASE" {
                assert!(inside_case);
                inside_case = false;
                let get = |key: &str| -> &str { current.get(key).copied().unwrap() };

                let seed_vec = hex_decode(get("SEED"));
                let seed: [u8; 64] = seed_vec.try_into().unwrap();

                let nonce: u16 = get("NONCE").parse().unwrap();
                let len: usize = get("LEN").parse().unwrap();

                let initial = Fp96_76 {
                    lo: get("SQSUM_BEFORE_LO").parse().unwrap(),
                    hi: get("SQSUM_BEFORE_HI").parse().unwrap(),
                };

                let actual = sample_gauss_n(&seed, nonce, len, initial);

                let expected_signs = hex_decode(get("SIGNS"));
                assert_eq!(
                    actual.signs.as_slice(),
                    expected_signs.as_slice(),
                    "mode={expected_mode} case={cases} signs"
                );

                let expected_samples: Vec<u64> = get("SAMPLES")
                    .split(',')
                    .map(|s| s.trim().parse().unwrap())
                    .collect();

                assert_eq!(expected_samples.len(), 256);
                assert_eq!(
                    actual.samples.as_slice(),
                    expected_samples.as_slice(),
                    "mode={expected_mode} case={cases} samples"
                );

                assert_eq!(
                    actual.sqsum.lo,
                    get("SQSUM_AFTER_LO").parse::<u64>().unwrap(),
                    "mode={expected_mode} case={cases} sqsum.lo"
                );
                assert_eq!(
                    actual.sqsum.hi,
                    get("SQSUM_AFTER_HI").parse::<u64>().unwrap(),
                    "mode={expected_mode} case={cases} sqsum.hi"
                );

                cases += 1;
                current.clear();
            } else if inside_case {
                let (key, value) = line
                    .split_once('=')
                    .expect("malformed Gaussian fixture field");
                assert!(
                    current.insert(key, value).is_none(),
                    "duplicate Gaussian fixture field: {key}"
                );
            }
        }

        assert!(!inside_case);
        assert!(current.is_empty());
        assert_eq!(cases, 20);
    }

    #[test]
    fn authenticated_gaussian_mode2() {
        check_fixture(fixtures::MODE2, 2);
    }

    #[test]
    fn authenticated_gaussian_mode3() {
        check_fixture(fixtures::MODE3, 3);
    }

    #[test]
    fn authenticated_gaussian_mode5() {
        check_fixture(fixtures::MODE5, 5);
    }
}
