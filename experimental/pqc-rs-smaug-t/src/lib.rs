//! Experimental SMAUG-T arithmetic.
//!
//! Not a complete KEM. Not suitable for production use.

pub mod encoding;
pub mod matrix;

pub const N: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub k: usize,
    pub q: u16,
    pub p: u16,
    pub p_prime: u16,
}

pub const SMAUG_T128: Parameters = Parameters {
    k: 2,
    q: 1024,
    p: 256,
    p_prime: 32,
};

pub const SMAUG_T192: Parameters = Parameters {
    k: 3,
    q: 2048,
    p: 512,
    p_prime: 16,
};

pub const SMAUG_T256: Parameters = Parameters {
    k: 4,
    q: 2048,
    p: 512,
    p_prime: 128,
};

pub const TIMER: Parameters = Parameters {
    k: 2,
    q: 1024,
    p: 256,
    p_prime: 8,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial {
    pub coefficients: [u16; N],
}

impl Polynomial {
    pub fn zero() -> Self {
        Self {
            coefficients: [0; N],
        }
    }

    pub fn add(&self, rhs: &Self, q: u16) -> Self {
        assert!(q > 0);
        let mut out = Self::zero();
        for i in 0..N {
            out.coefficients[i] =
                ((self.coefficients[i] as u32 + rhs.coefficients[i] as u32) % q as u32) as u16;
        }
        out
    }

    pub fn sub(&self, rhs: &Self, q: u16) -> Self {
        assert!(q > 0);
        let mut out = Self::zero();
        for i in 0..N {
            let a = self.coefficients[i] as i64;
            let b = rhs.coefficients[i] as i64;
            out.coefficients[i] = (a - b).rem_euclid(q as i64) as u16;
        }
        out
    }

    /// Schoolbook multiplication modulo x^256 + 1 and q.
    ///
    /// Baseline for correctness, not a performance claim.
    pub fn mul_negacyclic(&self, rhs: &Self, q: u16) -> Self {
        assert!(q > 0);
        let mut acc = [0i64; N];

        for i in 0..N {
            for j in 0..N {
                let product = self.coefficients[i] as i64 * rhs.coefficients[j] as i64;

                if i + j < N {
                    acc[i + j] += product;
                } else {
                    acc[i + j - N] -= product;
                }
            }
        }

        let mut out = Self::zero();
        for (dst, value) in out.coefficients.iter_mut().zip(acc.iter()) {
            *dst = value.rem_euclid(q as i64) as u16;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_moduli() {
        assert_eq!(SMAUG_T128.q, 1024);
        assert_eq!(SMAUG_T192.q, 2048);
        assert_eq!(SMAUG_T256.k, 4);
        assert_eq!(TIMER.p_prime, 8);
    }

    #[test]
    fn addition_wraps() {
        let mut a = Polynomial::zero();
        let mut b = Polynomial::zero();

        a.coefficients[0] = 1023;
        b.coefficients[0] = 2;

        assert_eq!(a.add(&b, 1024).coefficients[0], 1);
    }

    #[test]
    fn subtraction_wraps() {
        let a = Polynomial::zero();
        let mut b = Polynomial::zero();

        b.coefficients[0] = 1;

        assert_eq!(a.sub(&b, 1024).coefficients[0], 1023);
    }

    #[test]
    fn negacyclic_relation() {
        let mut a = Polynomial::zero();
        let mut b = Polynomial::zero();

        a.coefficients[255] = 1;
        b.coefficients[1] = 1;

        let product = a.mul_negacyclic(&b, 1024);

        assert_eq!(product.coefficients[0], 1023);
        assert!(product.coefficients[1..].iter().all(|&x| x == 0));
    }

    #[test]
    fn multiplicative_identity() {
        let mut a = Polynomial::zero();
        let mut one = Polynomial::zero();

        for i in 0..N {
            a.coefficients[i] = (i * 7 % 1024) as u16;
        }
        one.coefficients[0] = 1;

        assert_eq!(a.mul_negacyclic(&one, 1024), a);
    }

    // Independent reference using direct polynomial convolution.
    // Intended for correctness testing, not cryptographic execution.
    fn oracle_mul(a: &Polynomial, b: &Polynomial, q: u16) -> Polynomial {
        let mut full = [0i128; 2 * N - 1];

        for i in 0..N {
            for j in 0..N {
                full[i + j] += (a.coefficients[i] as i128) * (b.coefficients[j] as i128);
            }
        }

        let mut result = Polynomial::zero();

        for i in 0..N {
            let mut value = full[i];

            if i + N < full.len() {
                value -= full[i + N];
            }

            result.coefficients[i] = value.rem_euclid(q as i128) as u16;
        }

        result
    }

    fn next_random(state: &mut u64) -> u16 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        (*state >> 16) as u16
    }

    #[test]
    fn independent_oracle_randomized() {
        let mut state = 0x534D415547545253u64;

        for q in [1024u16, 2048u16] {
            for _case in 0..32 {
                let mut a = Polynomial::zero();
                let mut b = Polynomial::zero();

                for i in 0..N {
                    a.coefficients[i] = next_random(&mut state) % q;
                    b.coefficients[i] = next_random(&mut state) % q;
                }

                let expected = oracle_mul(&a, &b, q);
                let actual = a.mul_negacyclic(&b, q);

                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn all_parameter_sets_supported() {
        for params in [SMAUG_T128, SMAUG_T192, SMAUG_T256, TIMER] {
            assert_eq!(N, 256);
            assert!(params.q == 1024 || params.q == 2048);
            assert!(params.p.is_power_of_two());
            assert!(params.p_prime.is_power_of_two());
            assert!(params.q >= params.p);
            assert!(params.p >= params.p_prime);
        }
    }

    #[test]
    fn distributivity() {
        let mut a = Polynomial::zero();
        let mut b = Polynomial::zero();
        let mut c = Polynomial::zero();

        for i in 0..N {
            a.coefficients[i] = (i * 3 % 2048) as u16;
            b.coefficients[i] = (i * 5 % 2048) as u16;
            c.coefficients[i] = (i * 11 % 2048) as u16;
        }

        let lhs = a.add(&b, 2048).mul_negacyclic(&c, 2048);
        let rhs = a
            .mul_negacyclic(&c, 2048)
            .add(&b.mul_negacyclic(&c, 2048), 2048);

        assert_eq!(lhs, rhs);
    }
}
