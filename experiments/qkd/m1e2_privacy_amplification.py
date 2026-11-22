"""Experimental binary Toeplitz universal hashing for QKD privacy amplification.

No entropy estimation, finite-key bound, or security certification is performed.
Outputs MUST NOT be classified as qualified QKD secret keys.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass


class PrivacyAmplificationError(ValueError):
    """Invalid privacy-amplification inputs or requested output length."""


@dataclass(frozen=True)
class AmplificationResult:
    """Output of an experimental Toeplitz extraction operation."""

    key: bytes
    bit_length: int
    seed_bit_length: int
    security_qualified: bool = False


def _validate_bits(value: bytes, length: int, name: str) -> None:
    if not isinstance(value, bytes):
        raise PrivacyAmplificationError(f"{name} must be bytes")
    if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
        raise PrivacyAmplificationError(f"{name} bit length must be positive")
    if len(value) != (length + 7) // 8:
        raise PrivacyAmplificationError(f"{name} length mismatch")
    if length % 8 and value[-1] & ((1 << (8 - length % 8)) - 1):
        raise PrivacyAmplificationError(f"{name} has nonzero trailing padding bits")


def random_toeplitz_seed(input_bits: int, output_bits: int) -> bytes:
    """Generate a public seed with exactly n + ell - 1 random bits.

    Bits are encoded MSB-first; unused low padding bits are zero.
    """
    if not isinstance(input_bits, int) or isinstance(input_bits, bool) or input_bits <= 0:
        raise PrivacyAmplificationError("input_bits must be positive")
    if not isinstance(output_bits, int) or isinstance(output_bits, bool) or not 0 < output_bits <= input_bits:
        raise PrivacyAmplificationError("output_bits must lie in 1..input_bits")
    count = input_bits + output_bits - 1
    return (secrets.randbits(count) << ((-count) % 8)).to_bytes((count + 7) // 8, "big")


def toeplitz_hash(input_key: bytes, input_bits: int, output_bits: int, seed: bytes) -> AmplificationResult:
    """Compute y = T_s x over GF(2) using an MSB-first representation.

    Let n = input_bits, ell = output_bits. Seed index n-1+i-j defines
    T[i,j], 0 <= i < ell and 0 <= j < n. This yields a Toeplitz matrix.
    Output is MSB-first and any final unused low bits are zero.

    This primitive is not itself a QKD security proof or a certified KDF.
    """
    _validate_bits(input_key, input_bits, "input_key")
    if not isinstance(output_bits, int) or isinstance(output_bits, bool) or not 0 < output_bits <= input_bits:
        raise PrivacyAmplificationError("output_bits must lie in 1..input_bits")
    seed_bits = input_bits + output_bits - 1
    _validate_bits(seed, seed_bits, "seed")
    x = int.from_bytes(input_key, "big") >> ((-input_bits) % 8)
    s = int.from_bytes(seed, "big") >> ((-seed_bits) % 8)
    y = 0
    # Straightforward reference implementation; not constant-time.
    for i in range(output_bits):
        parity = 0
        for j in range(input_bits):
            if (x >> (input_bits - 1 - j)) & 1:
                parity ^= (s >> (seed_bits - 1 - (input_bits - 1 + i - j))) & 1
        y = (y << 1) | parity
    padding = (-output_bits) % 8
    encoded = (y << padding).to_bytes((output_bits + 7) // 8, "big")
    return AmplificationResult(encoded, output_bits, seed_bits)
