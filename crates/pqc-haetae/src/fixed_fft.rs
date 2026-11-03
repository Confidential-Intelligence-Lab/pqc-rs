//! Reference-compatible fixed-point FFT for HAETAE 1.2.0.
//!
//! The reference uses signed Q16 complex values and a 256-point
//! radix-2 FFT. Twiddle factors are copied exactly from the
//! authenticated reference implementation.
//!
//! Arithmetic uses explicit wrapping where the reference operates
//! on signed 32-bit integers. This reproduces two's-complement
//! results but does not establish that arbitrary inputs are valid
//! under the reference's arithmetic bounds.

use crate::poly::Poly;

pub const FFT_N: usize = 256;
const FFT_LOGN: usize = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ComplexFp {
    pub real: i32,
    pub imag: i32,
}

const ROOTS: [ComplexFp; FFT_N] = [
    ComplexFp {
        real: 65536,
        imag: 0,
    },
    ComplexFp {
        real: 65531,
        imag: -804,
    },
    ComplexFp {
        real: 65516,
        imag: -1608,
    },
    ComplexFp {
        real: 65492,
        imag: -2412,
    },
    ComplexFp {
        real: 65457,
        imag: -3216,
    },
    ComplexFp {
        real: 65413,
        imag: -4019,
    },
    ComplexFp {
        real: 65358,
        imag: -4821,
    },
    ComplexFp {
        real: 65294,
        imag: -5623,
    },
    ComplexFp {
        real: 65220,
        imag: -6424,
    },
    ComplexFp {
        real: 65137,
        imag: -7224,
    },
    ComplexFp {
        real: 65043,
        imag: -8022,
    },
    ComplexFp {
        real: 64940,
        imag: -8820,
    },
    ComplexFp {
        real: 64827,
        imag: -9616,
    },
    ComplexFp {
        real: 64704,
        imag: -10411,
    },
    ComplexFp {
        real: 64571,
        imag: -11204,
    },
    ComplexFp {
        real: 64429,
        imag: -11996,
    },
    ComplexFp {
        real: 64277,
        imag: -12785,
    },
    ComplexFp {
        real: 64115,
        imag: -13573,
    },
    ComplexFp {
        real: 63944,
        imag: -14359,
    },
    ComplexFp {
        real: 63763,
        imag: -15143,
    },
    ComplexFp {
        real: 63572,
        imag: -15924,
    },
    ComplexFp {
        real: 63372,
        imag: -16703,
    },
    ComplexFp {
        real: 63162,
        imag: -17479,
    },
    ComplexFp {
        real: 62943,
        imag: -18253,
    },
    ComplexFp {
        real: 62714,
        imag: -19024,
    },
    ComplexFp {
        real: 62476,
        imag: -19792,
    },
    ComplexFp {
        real: 62228,
        imag: -20557,
    },
    ComplexFp {
        real: 61971,
        imag: -21320,
    },
    ComplexFp {
        real: 61705,
        imag: -22078,
    },
    ComplexFp {
        real: 61429,
        imag: -22834,
    },
    ComplexFp {
        real: 61145,
        imag: -23586,
    },
    ComplexFp {
        real: 60851,
        imag: -24335,
    },
    ComplexFp {
        real: 60547,
        imag: -25080,
    },
    ComplexFp {
        real: 60235,
        imag: -25821,
    },
    ComplexFp {
        real: 59914,
        imag: -26558,
    },
    ComplexFp {
        real: 59583,
        imag: -27291,
    },
    ComplexFp {
        real: 59244,
        imag: -28020,
    },
    ComplexFp {
        real: 58896,
        imag: -28745,
    },
    ComplexFp {
        real: 58538,
        imag: -29466,
    },
    ComplexFp {
        real: 58172,
        imag: -30182,
    },
    ComplexFp {
        real: 57798,
        imag: -30893,
    },
    ComplexFp {
        real: 57414,
        imag: -31600,
    },
    ComplexFp {
        real: 57022,
        imag: -32303,
    },
    ComplexFp {
        real: 56621,
        imag: -33000,
    },
    ComplexFp {
        real: 56212,
        imag: -33692,
    },
    ComplexFp {
        real: 55794,
        imag: -34380,
    },
    ComplexFp {
        real: 55368,
        imag: -35062,
    },
    ComplexFp {
        real: 54934,
        imag: -35738,
    },
    ComplexFp {
        real: 54491,
        imag: -36410,
    },
    ComplexFp {
        real: 54040,
        imag: -37076,
    },
    ComplexFp {
        real: 53581,
        imag: -37736,
    },
    ComplexFp {
        real: 53114,
        imag: -38391,
    },
    ComplexFp {
        real: 52639,
        imag: -39040,
    },
    ComplexFp {
        real: 52156,
        imag: -39683,
    },
    ComplexFp {
        real: 51665,
        imag: -40320,
    },
    ComplexFp {
        real: 51166,
        imag: -40951,
    },
    ComplexFp {
        real: 50660,
        imag: -41576,
    },
    ComplexFp {
        real: 50146,
        imag: -42194,
    },
    ComplexFp {
        real: 49624,
        imag: -42806,
    },
    ComplexFp {
        real: 49095,
        imag: -43412,
    },
    ComplexFp {
        real: 48559,
        imag: -44011,
    },
    ComplexFp {
        real: 48015,
        imag: -44604,
    },
    ComplexFp {
        real: 47464,
        imag: -45190,
    },
    ComplexFp {
        real: 46906,
        imag: -45769,
    },
    ComplexFp {
        real: 46341,
        imag: -46341,
    },
    ComplexFp {
        real: 45769,
        imag: -46906,
    },
    ComplexFp {
        real: 45190,
        imag: -47464,
    },
    ComplexFp {
        real: 44604,
        imag: -48015,
    },
    ComplexFp {
        real: 44011,
        imag: -48559,
    },
    ComplexFp {
        real: 43412,
        imag: -49095,
    },
    ComplexFp {
        real: 42806,
        imag: -49624,
    },
    ComplexFp {
        real: 42194,
        imag: -50146,
    },
    ComplexFp {
        real: 41576,
        imag: -50660,
    },
    ComplexFp {
        real: 40951,
        imag: -51166,
    },
    ComplexFp {
        real: 40320,
        imag: -51665,
    },
    ComplexFp {
        real: 39683,
        imag: -52156,
    },
    ComplexFp {
        real: 39040,
        imag: -52639,
    },
    ComplexFp {
        real: 38391,
        imag: -53114,
    },
    ComplexFp {
        real: 37736,
        imag: -53581,
    },
    ComplexFp {
        real: 37076,
        imag: -54040,
    },
    ComplexFp {
        real: 36410,
        imag: -54491,
    },
    ComplexFp {
        real: 35738,
        imag: -54934,
    },
    ComplexFp {
        real: 35062,
        imag: -55368,
    },
    ComplexFp {
        real: 34380,
        imag: -55794,
    },
    ComplexFp {
        real: 33692,
        imag: -56212,
    },
    ComplexFp {
        real: 33000,
        imag: -56621,
    },
    ComplexFp {
        real: 32303,
        imag: -57022,
    },
    ComplexFp {
        real: 31600,
        imag: -57414,
    },
    ComplexFp {
        real: 30893,
        imag: -57798,
    },
    ComplexFp {
        real: 30182,
        imag: -58172,
    },
    ComplexFp {
        real: 29466,
        imag: -58538,
    },
    ComplexFp {
        real: 28745,
        imag: -58896,
    },
    ComplexFp {
        real: 28020,
        imag: -59244,
    },
    ComplexFp {
        real: 27291,
        imag: -59583,
    },
    ComplexFp {
        real: 26558,
        imag: -59914,
    },
    ComplexFp {
        real: 25821,
        imag: -60235,
    },
    ComplexFp {
        real: 25080,
        imag: -60547,
    },
    ComplexFp {
        real: 24335,
        imag: -60851,
    },
    ComplexFp {
        real: 23586,
        imag: -61145,
    },
    ComplexFp {
        real: 22834,
        imag: -61429,
    },
    ComplexFp {
        real: 22078,
        imag: -61705,
    },
    ComplexFp {
        real: 21320,
        imag: -61971,
    },
    ComplexFp {
        real: 20557,
        imag: -62228,
    },
    ComplexFp {
        real: 19792,
        imag: -62476,
    },
    ComplexFp {
        real: 19024,
        imag: -62714,
    },
    ComplexFp {
        real: 18253,
        imag: -62943,
    },
    ComplexFp {
        real: 17479,
        imag: -63162,
    },
    ComplexFp {
        real: 16703,
        imag: -63372,
    },
    ComplexFp {
        real: 15924,
        imag: -63572,
    },
    ComplexFp {
        real: 15143,
        imag: -63763,
    },
    ComplexFp {
        real: 14359,
        imag: -63944,
    },
    ComplexFp {
        real: 13573,
        imag: -64115,
    },
    ComplexFp {
        real: 12785,
        imag: -64277,
    },
    ComplexFp {
        real: 11996,
        imag: -64429,
    },
    ComplexFp {
        real: 11204,
        imag: -64571,
    },
    ComplexFp {
        real: 10411,
        imag: -64704,
    },
    ComplexFp {
        real: 9616,
        imag: -64827,
    },
    ComplexFp {
        real: 8820,
        imag: -64940,
    },
    ComplexFp {
        real: 8022,
        imag: -65043,
    },
    ComplexFp {
        real: 7224,
        imag: -65137,
    },
    ComplexFp {
        real: 6424,
        imag: -65220,
    },
    ComplexFp {
        real: 5623,
        imag: -65294,
    },
    ComplexFp {
        real: 4821,
        imag: -65358,
    },
    ComplexFp {
        real: 4019,
        imag: -65413,
    },
    ComplexFp {
        real: 3216,
        imag: -65457,
    },
    ComplexFp {
        real: 2412,
        imag: -65492,
    },
    ComplexFp {
        real: 1608,
        imag: -65516,
    },
    ComplexFp {
        real: 804,
        imag: -65531,
    },
    ComplexFp {
        real: 0,
        imag: -65536,
    },
    ComplexFp {
        real: -804,
        imag: -65531,
    },
    ComplexFp {
        real: -1608,
        imag: -65516,
    },
    ComplexFp {
        real: -2412,
        imag: -65492,
    },
    ComplexFp {
        real: -3216,
        imag: -65457,
    },
    ComplexFp {
        real: -4019,
        imag: -65413,
    },
    ComplexFp {
        real: -4821,
        imag: -65358,
    },
    ComplexFp {
        real: -5623,
        imag: -65294,
    },
    ComplexFp {
        real: -6424,
        imag: -65220,
    },
    ComplexFp {
        real: -7224,
        imag: -65137,
    },
    ComplexFp {
        real: -8022,
        imag: -65043,
    },
    ComplexFp {
        real: -8820,
        imag: -64940,
    },
    ComplexFp {
        real: -9616,
        imag: -64827,
    },
    ComplexFp {
        real: -10411,
        imag: -64704,
    },
    ComplexFp {
        real: -11204,
        imag: -64571,
    },
    ComplexFp {
        real: -11996,
        imag: -64429,
    },
    ComplexFp {
        real: -12785,
        imag: -64277,
    },
    ComplexFp {
        real: -13573,
        imag: -64115,
    },
    ComplexFp {
        real: -14359,
        imag: -63944,
    },
    ComplexFp {
        real: -15143,
        imag: -63763,
    },
    ComplexFp {
        real: -15924,
        imag: -63572,
    },
    ComplexFp {
        real: -16703,
        imag: -63372,
    },
    ComplexFp {
        real: -17479,
        imag: -63162,
    },
    ComplexFp {
        real: -18253,
        imag: -62943,
    },
    ComplexFp {
        real: -19024,
        imag: -62714,
    },
    ComplexFp {
        real: -19792,
        imag: -62476,
    },
    ComplexFp {
        real: -20557,
        imag: -62228,
    },
    ComplexFp {
        real: -21320,
        imag: -61971,
    },
    ComplexFp {
        real: -22078,
        imag: -61705,
    },
    ComplexFp {
        real: -22834,
        imag: -61429,
    },
    ComplexFp {
        real: -23586,
        imag: -61145,
    },
    ComplexFp {
        real: -24335,
        imag: -60851,
    },
    ComplexFp {
        real: -25080,
        imag: -60547,
    },
    ComplexFp {
        real: -25821,
        imag: -60235,
    },
    ComplexFp {
        real: -26558,
        imag: -59914,
    },
    ComplexFp {
        real: -27291,
        imag: -59583,
    },
    ComplexFp {
        real: -28020,
        imag: -59244,
    },
    ComplexFp {
        real: -28745,
        imag: -58896,
    },
    ComplexFp {
        real: -29466,
        imag: -58538,
    },
    ComplexFp {
        real: -30182,
        imag: -58172,
    },
    ComplexFp {
        real: -30893,
        imag: -57798,
    },
    ComplexFp {
        real: -31600,
        imag: -57414,
    },
    ComplexFp {
        real: -32303,
        imag: -57022,
    },
    ComplexFp {
        real: -33000,
        imag: -56621,
    },
    ComplexFp {
        real: -33692,
        imag: -56212,
    },
    ComplexFp {
        real: -34380,
        imag: -55794,
    },
    ComplexFp {
        real: -35062,
        imag: -55368,
    },
    ComplexFp {
        real: -35738,
        imag: -54934,
    },
    ComplexFp {
        real: -36410,
        imag: -54491,
    },
    ComplexFp {
        real: -37076,
        imag: -54040,
    },
    ComplexFp {
        real: -37736,
        imag: -53581,
    },
    ComplexFp {
        real: -38391,
        imag: -53114,
    },
    ComplexFp {
        real: -39040,
        imag: -52639,
    },
    ComplexFp {
        real: -39683,
        imag: -52156,
    },
    ComplexFp {
        real: -40320,
        imag: -51665,
    },
    ComplexFp {
        real: -40951,
        imag: -51166,
    },
    ComplexFp {
        real: -41576,
        imag: -50660,
    },
    ComplexFp {
        real: -42194,
        imag: -50146,
    },
    ComplexFp {
        real: -42806,
        imag: -49624,
    },
    ComplexFp {
        real: -43412,
        imag: -49095,
    },
    ComplexFp {
        real: -44011,
        imag: -48559,
    },
    ComplexFp {
        real: -44604,
        imag: -48015,
    },
    ComplexFp {
        real: -45190,
        imag: -47464,
    },
    ComplexFp {
        real: -45769,
        imag: -46906,
    },
    ComplexFp {
        real: -46341,
        imag: -46341,
    },
    ComplexFp {
        real: -46906,
        imag: -45769,
    },
    ComplexFp {
        real: -47464,
        imag: -45190,
    },
    ComplexFp {
        real: -48015,
        imag: -44604,
    },
    ComplexFp {
        real: -48559,
        imag: -44011,
    },
    ComplexFp {
        real: -49095,
        imag: -43412,
    },
    ComplexFp {
        real: -49624,
        imag: -42806,
    },
    ComplexFp {
        real: -50146,
        imag: -42194,
    },
    ComplexFp {
        real: -50660,
        imag: -41576,
    },
    ComplexFp {
        real: -51166,
        imag: -40951,
    },
    ComplexFp {
        real: -51665,
        imag: -40320,
    },
    ComplexFp {
        real: -52156,
        imag: -39683,
    },
    ComplexFp {
        real: -52639,
        imag: -39040,
    },
    ComplexFp {
        real: -53114,
        imag: -38391,
    },
    ComplexFp {
        real: -53581,
        imag: -37736,
    },
    ComplexFp {
        real: -54040,
        imag: -37076,
    },
    ComplexFp {
        real: -54491,
        imag: -36410,
    },
    ComplexFp {
        real: -54934,
        imag: -35738,
    },
    ComplexFp {
        real: -55368,
        imag: -35062,
    },
    ComplexFp {
        real: -55794,
        imag: -34380,
    },
    ComplexFp {
        real: -56212,
        imag: -33692,
    },
    ComplexFp {
        real: -56621,
        imag: -33000,
    },
    ComplexFp {
        real: -57022,
        imag: -32303,
    },
    ComplexFp {
        real: -57414,
        imag: -31600,
    },
    ComplexFp {
        real: -57798,
        imag: -30893,
    },
    ComplexFp {
        real: -58172,
        imag: -30182,
    },
    ComplexFp {
        real: -58538,
        imag: -29466,
    },
    ComplexFp {
        real: -58896,
        imag: -28745,
    },
    ComplexFp {
        real: -59244,
        imag: -28020,
    },
    ComplexFp {
        real: -59583,
        imag: -27291,
    },
    ComplexFp {
        real: -59914,
        imag: -26558,
    },
    ComplexFp {
        real: -60235,
        imag: -25821,
    },
    ComplexFp {
        real: -60547,
        imag: -25080,
    },
    ComplexFp {
        real: -60851,
        imag: -24335,
    },
    ComplexFp {
        real: -61145,
        imag: -23586,
    },
    ComplexFp {
        real: -61429,
        imag: -22834,
    },
    ComplexFp {
        real: -61705,
        imag: -22078,
    },
    ComplexFp {
        real: -61971,
        imag: -21320,
    },
    ComplexFp {
        real: -62228,
        imag: -20557,
    },
    ComplexFp {
        real: -62476,
        imag: -19792,
    },
    ComplexFp {
        real: -62714,
        imag: -19024,
    },
    ComplexFp {
        real: -62943,
        imag: -18253,
    },
    ComplexFp {
        real: -63162,
        imag: -17479,
    },
    ComplexFp {
        real: -63372,
        imag: -16703,
    },
    ComplexFp {
        real: -63572,
        imag: -15924,
    },
    ComplexFp {
        real: -63763,
        imag: -15143,
    },
    ComplexFp {
        real: -63944,
        imag: -14359,
    },
    ComplexFp {
        real: -64115,
        imag: -13573,
    },
    ComplexFp {
        real: -64277,
        imag: -12785,
    },
    ComplexFp {
        real: -64429,
        imag: -11996,
    },
    ComplexFp {
        real: -64571,
        imag: -11204,
    },
    ComplexFp {
        real: -64704,
        imag: -10411,
    },
    ComplexFp {
        real: -64827,
        imag: -9616,
    },
    ComplexFp {
        real: -64940,
        imag: -8820,
    },
    ComplexFp {
        real: -65043,
        imag: -8022,
    },
    ComplexFp {
        real: -65137,
        imag: -7224,
    },
    ComplexFp {
        real: -65220,
        imag: -6424,
    },
    ComplexFp {
        real: -65294,
        imag: -5623,
    },
    ComplexFp {
        real: -65358,
        imag: -4821,
    },
    ComplexFp {
        real: -65413,
        imag: -4019,
    },
    ComplexFp {
        real: -65457,
        imag: -3216,
    },
    ComplexFp {
        real: -65492,
        imag: -2412,
    },
    ComplexFp {
        real: -65516,
        imag: -1608,
    },
    ComplexFp {
        real: -65531,
        imag: -804,
    },
];

#[inline]
fn mulrnd16(x: i32, y: i32) -> i32 {
    let product = i64::from(x) * i64::from(y);
    let rounded = (product + (1_i64 << 15)) >> 16;
    rounded as i32
}

#[inline]
fn complex_mul(x: ComplexFp, y: ComplexFp) -> ComplexFp {
    ComplexFp {
        real: mulrnd16(x.real, y.real).wrapping_sub(mulrnd16(x.imag, y.imag)),
        imag: mulrnd16(x.real, y.imag).wrapping_add(mulrnd16(x.imag, y.real)),
    }
}

#[inline]
fn bitreverse8(value: usize) -> usize {
    (value as u8).reverse_bits() as usize
}

/// Reference `fft_init_and_bitrev`.
///
/// Polynomial coefficients are multiplied by Q16 roots without
/// shifting, then stored in bit-reversed order.
pub fn init_and_bitrev(poly: &Poly) -> [ComplexFp; FFT_N] {
    let mut result = [ComplexFp::default(); FFT_N];

    for i in 0..FFT_N {
        let coefficient = poly.coeffs[i];
        let root = ROOTS[i];

        result[bitreverse8(i)] = ComplexFp {
            real: coefficient.wrapping_mul(root.real),
            imag: coefficient.wrapping_mul(root.imag),
        };
    }

    result
}

/// Reference `fft`, with the same stage and butterfly ordering.
pub fn fft(data: &mut [ComplexFp; FFT_N]) {
    for stage in 1..=FFT_LOGN {
        let width = 1usize << stage;
        let half = width >> 1;

        for base in (0..FFT_N).step_by(width) {
            for k in 0..half {
                let even = base + k;
                let odd = even + half;
                let twiddle = k << (FFT_LOGN - stage + 1);

                let u = data[even];
                let t = complex_mul(ROOTS[twiddle], data[odd]);

                data[even] = ComplexFp {
                    real: u.real.wrapping_add(t.real),
                    imag: u.imag.wrapping_add(t.imag),
                };

                data[odd] = ComplexFp {
                    real: u.real.wrapping_sub(t.real),
                    imag: u.imag.wrapping_sub(t.imag),
                };
            }
        }
    }
}

/// Reference `complex_fp_sqabs`.
pub fn squared_abs(value: ComplexFp) -> i32 {
    mulrnd16(value.real, value.real).wrapping_add(mulrnd16(value.imag, value.imag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_root_landmarks() {
        assert_eq!(
            ROOTS[0],
            ComplexFp {
                real: 65536,
                imag: 0
            }
        );
        assert_eq!(
            ROOTS[64],
            ComplexFp {
                real: 46341,
                imag: -46341
            }
        );
        assert_eq!(
            ROOTS[128],
            ComplexFp {
                real: 0,
                imag: -65536
            }
        );
    }

    #[test]
    fn bit_reversal_is_involutive() {
        for i in 0..FFT_N {
            assert_eq!(bitreverse8(bitreverse8(i)), i);
        }
    }

    #[test]
    fn zero_polynomial_stays_zero() {
        let poly = Poly::default();
        let mut data = init_and_bitrev(&poly);

        fft(&mut data);

        assert!(data.iter().all(|x| *x == ComplexFp::default()));
    }

    #[test]
    fn constant_polynomial_initialization() {
        let mut poly = Poly::default();
        poly.coeffs[0] = 1;

        let data = init_and_bitrev(&poly);

        assert_eq!(
            data[0],
            ComplexFp {
                real: 65536,
                imag: 0
            }
        );

        assert!(data[1..].iter().all(|x| *x == ComplexFp::default()));
    }

    #[test]
    fn multiplication_rounding() {
        assert_eq!(mulrnd16(65536, 65536), 65536);
        assert_eq!(mulrnd16(32768, 32768), 16384);
        assert_eq!(mulrnd16(-32768, 32768), -16384);
    }

    #[test]
    fn squared_magnitude() {
        assert_eq!(
            squared_abs(ComplexFp {
                real: 65536,
                imag: 0,
            }),
            65536
        );

        assert_eq!(squared_abs(ComplexFp { real: 0, imag: 0 }), 0);
    }
}
