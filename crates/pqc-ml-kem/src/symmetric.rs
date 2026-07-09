//! Symmetric primitives used by ML-KEM.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Sha3_512, Shake128, Shake256,
};

/// SHA3-256 digest.
pub fn h(input: &[u8]) -> [u8; 32] {
    let digest = Sha3_256::digest(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// SHA3-512 digest.
pub fn g(input: &[u8]) -> [u8; 64] {
    let digest = Sha3_512::digest(input);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// SHAKE128 XOF expansion with two domain bytes.
pub fn xof(seed: &[u8; 32], x: u8, y: u8, out: &mut [u8]) {
    let mut hasher = Shake128::default();
    hasher.update(seed);
    hasher.update(&[x, y]);
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}

/// SHAKE256 PRF expansion.
pub fn prf(seed: &[u8; 32], nonce: u8, out: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    hasher.update(&[nonce]);
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_have_expected_lengths() {
        assert_eq!(h(b"abc").len(), 32);
        assert_eq!(g(b"abc").len(), 64);
    }

    #[test]
    fn xof_is_deterministic_and_domain_separated() {
        let seed = [7u8; 32];
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut c = [0u8; 64];

        xof(&seed, 1, 2, &mut a);
        xof(&seed, 1, 2, &mut b);
        xof(&seed, 2, 1, &mut c);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
