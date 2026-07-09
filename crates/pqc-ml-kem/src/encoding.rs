//! Message encoding helpers for ML-KEM K-PKE.

use crate::arithmetic::{N, Q};
use crate::kpke::{Message, MESSAGE_BYTES};
use crate::poly::Poly;

/// Convert a 32-byte message to a polynomial with coefficients `0` or `(q+1)/2`.
pub fn message_to_poly(message: &Message) -> Poly {
    let mut coeffs = [0i16; N];

    let mut i = 0;
    while i < N {
        let byte = message.as_bytes()[i / 8];
        let bit = (byte >> (i % 8)) & 1;
        coeffs[i] = if bit == 1 { (Q + 1) / 2 } else { 0 };
        i += 1;
    }

    Poly::from_coefficients(coeffs)
}

/// Convert a message polynomial back to 32 bytes by thresholding coefficients.
pub fn poly_to_message(poly: &Poly) -> Message {
    let mut out = [0u8; MESSAGE_BYTES];

    let mut i = 0;
    while i < N {
        let c = poly.coefficients()[i];
        let bit = if c > Q / 4 && c < (3 * Q) / 4 {
            1u8
        } else {
            0u8
        };
        out[i / 8] |= bit << (i % 8);
        i += 1;
    }

    Message::new(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_poly_round_trip() {
        let mut bytes = [0u8; MESSAGE_BYTES];
        let mut i = 0;
        while i < MESSAGE_BYTES {
            bytes[i] = (3 * i + 1) as u8;
            i += 1;
        }

        let message = Message::new(bytes);
        let poly = message_to_poly(&message);
        let decoded = poly_to_message(&poly);

        assert_eq!(decoded.as_bytes(), message.as_bytes());
    }
}
