//! Domain-separated SHAKE expanders used by ML-DSA.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake256,
};

/// Seed length used by `ExpandA`.
pub const RHO_BYTES: usize = 32;
/// Seed length used by `ExpandS`.
pub const RHO_PRIME_BYTES: usize = 64;
/// Seed length used by `ExpandMask`.
pub const RHO_DOUBLE_PRIME_BYTES: usize = 64;

/// SHAKE128 stream for matrix expansion.
pub struct ExpandAReader {
    reader: sha3::Shake128Reader,
}

impl ExpandAReader {
    /// Construct from `rho` and matrix coordinates.
    pub fn new(rho: &[u8; RHO_BYTES], row: u8, column: u8) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(rho);
        hasher.update(&[column, row]);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Read bytes from the stream.
    pub fn read(&mut self, output: &mut [u8]) {
        self.reader.read(output);
    }
}

/// SHAKE256 stream for secret expansion.
pub struct ExpandSReader {
    reader: sha3::Shake256Reader,
}

impl ExpandSReader {
    /// Construct from `rho_prime` and a 16-bit nonce.
    pub fn new(rho_prime: &[u8; RHO_PRIME_BYTES], nonce: u16) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(rho_prime);
        hasher.update(&nonce.to_le_bytes());
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Read bytes from the stream.
    pub fn read(&mut self, output: &mut [u8]) {
        self.reader.read(output);
    }
}

/// SHAKE256 stream for mask expansion.
pub struct ExpandMaskReader {
    reader: sha3::Shake256Reader,
}

impl ExpandMaskReader {
    /// Construct from `rho_double_prime` and a 16-bit nonce.
    pub fn new(rho_double_prime: &[u8; RHO_DOUBLE_PRIME_BYTES], nonce: u16) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(rho_double_prime);
        hasher.update(&nonce.to_le_bytes());
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Read bytes from the stream.
    pub fn read(&mut self, output: &mut [u8]) {
        self.reader.read(output);
    }
}

/// Expand bytes for `ExpandA`.
pub fn expand_a_bytes(rho: &[u8; RHO_BYTES], row: u8, column: u8, output: &mut [u8]) {
    ExpandAReader::new(rho, row, column).read(output);
}

/// Expand bytes for `ExpandS`.
pub fn expand_s_bytes(rho_prime: &[u8; RHO_PRIME_BYTES], nonce: u16, output: &mut [u8]) {
    ExpandSReader::new(rho_prime, nonce).read(output);
}

/// Expand bytes for `ExpandMask`.
pub fn expand_mask_bytes(
    rho_double_prime: &[u8; RHO_DOUBLE_PRIME_BYTES],
    nonce: u16,
    output: &mut [u8],
) {
    ExpandMaskReader::new(rho_double_prime, nonce).read(output);
}
