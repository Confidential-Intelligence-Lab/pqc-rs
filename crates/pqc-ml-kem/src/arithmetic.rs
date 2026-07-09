//! Finite-field arithmetic for ML-KEM.

/// ML-KEM polynomial degree.
pub const N: usize = 256;

/// ML-KEM modulus.
pub const Q: i16 = 3329;

/// Reduce an integer modulo `Q` into `[0, Q)`.
pub fn reduce(x: i32) -> i16 {
    let mut r = x % i32::from(Q);
    if r < 0 {
        r += i32::from(Q);
    }
    r as i16
}

/// Add two field elements modulo `Q`.
pub fn add(a: i16, b: i16) -> i16 {
    reduce(i32::from(a) + i32::from(b))
}

/// Subtract two field elements modulo `Q`.
pub fn sub(a: i16, b: i16) -> i16 {
    reduce(i32::from(a) - i32::from(b))
}

/// Multiply two field elements modulo `Q`.
pub fn mul(a: i16, b: i16) -> i16 {
    reduce(i32::from(a) * i32::from(b))
}

/// Compress a coefficient to `d` bits.
pub fn compress_coefficient(x: i16, d: u32) -> u16 {
    debug_assert!(d <= 12);
    let q = u32::from(Q as u16);
    let x = u32::from(reduce(i32::from(x)) as u16);
    let scale = 1u32 << d;
    ((((x * scale) + (q / 2)) / q) & (scale - 1)) as u16
}

/// Decompress a `d`-bit coefficient.
pub fn decompress_coefficient(y: u16, d: u32) -> i16 {
    debug_assert!(d <= 12);
    let q = u32::from(Q as u16);
    let scale = 1u32 << d;
    let y = u32::from(y) & (scale - 1);
    (((y * q) + (scale / 2)) / scale) as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduction_outputs_canonical_representatives() {
        assert_eq!(reduce(0), 0);
        assert_eq!(reduce(3329), 0);
        assert_eq!(reduce(-1), 3328);
        assert_eq!(reduce(3330), 1);
    }

    #[test]
    fn field_operations_are_modular() {
        assert_eq!(add(3328, 2), 1);
        assert_eq!(sub(1, 2), 3328);
        assert_eq!(mul(3328, 3328), 1);
    }

    fn circular_distance_mod_q(a: i16, b: i16) -> i32 {
        let q = i32::from(Q);
        let diff = (i32::from(reduce(i32::from(a))) - i32::from(reduce(i32::from(b)))).abs();
        core::cmp::min(diff, q - diff)
    }

    #[test]
    fn coefficient_compression_round_trip_is_bounded_mod_q() {
        for x in [0, 1, 17, 100, 1024, 2048, 3328] {
            let c = compress_coefficient(x, 10);
            let d = decompress_coefficient(c, 10);
            assert!(
                circular_distance_mod_q(x, d) <= 3,
                "x={x}, compressed={c}, decompressed={d}"
            );
        }
    }
}
