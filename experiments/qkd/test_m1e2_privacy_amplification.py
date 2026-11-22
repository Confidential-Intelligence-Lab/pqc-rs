"""Independent correctness tests for experimental Toeplitz extraction."""

import random
import unittest

from m1e2_privacy_amplification import (
    PrivacyAmplificationError,
    random_toeplitz_seed,
    toeplitz_hash,
)


def encode_bits(bits: list[int]) -> bytes:
    return (int("".join(str(b) for b in bits), 2) << ((-len(bits)) % 8)).to_bytes(
        (len(bits) + 7) // 8, "big"
    )


def reference_hash(x: list[int], seed: list[int], ell: int) -> bytes:
    n = len(x)
    result = [sum(x[j] & seed[n - 1 + i - j] for j in range(n)) % 2 for i in range(ell)]
    return encode_bits(result)


class ToeplitzTests(unittest.TestCase):
    def test_reference_matrix_multiple_shapes(self):
        rng = random.Random(20261120)
        for n, ell in [(1, 1), (3, 2), (8, 8), (13, 5), (33, 17), (128, 64)]:
            x = [rng.randrange(2) for _ in range(n)]
            seed = [rng.randrange(2) for _ in range(n + ell - 1)]
            result = toeplitz_hash(encode_bits(x), n, ell, encode_bits(seed))
            self.assertEqual(result.key, reference_hash(x, seed, ell))
            self.assertFalse(result.security_qualified)

    def test_alice_bob_agree(self):
        input_key = bytes(range(32))
        seed = random_toeplitz_seed(256, 128)
        alice = toeplitz_hash(input_key, 256, 128, seed)
        bob = toeplitz_hash(input_key, 256, 128, seed)
        self.assertEqual(alice, bob)
        self.assertEqual(len(alice.key), 16)

    def test_linearity(self):
        n, ell = 17, 9
        rng = random.Random(91)
        a = [rng.randrange(2) for _ in range(n)]
        b = [rng.randrange(2) for _ in range(n)]
        seed = [rng.randrange(2) for _ in range(n + ell - 1)]
        ha = toeplitz_hash(encode_bits(a), n, ell, encode_bits(seed)).key
        hb = toeplitz_hash(encode_bits(b), n, ell, encode_bits(seed)).key
        hab = toeplitz_hash(encode_bits([x ^ y for x, y in zip(a, b)]), n, ell, encode_bits(seed)).key
        self.assertEqual(hab, bytes(x ^ y for x, y in zip(ha, hb)))

    def test_seed_generation_length_and_padding(self):
        for n, ell in [(1, 1), (10, 5), (256, 128)]:
            seed = random_toeplitz_seed(n, ell)
            count = n + ell - 1
            self.assertEqual(len(seed), (count + 7) // 8)
            self.assertEqual(int.from_bytes(seed, "big") & ((1 << ((-count) % 8)) - 1), 0)

    def test_invalid_parameters_and_padding(self):
        seed = encode_bits([1] * 12)
        for x, n, ell, s in [
            (b"", 0, 1, seed),
            (b"\x80", 1, 2, seed),
            (b"\xff", 7, 1, encode_bits([1] * 7)),
            (b"\x80", 1, 1, b"\x81"),
            (b"\x80", 1, 1, b""),
        ]:
            with self.subTest(n=n, ell=ell):
                with self.assertRaises(PrivacyAmplificationError):
                    toeplitz_hash(x, n, ell, s)

    def test_input_sensitivity_not_guaranteed_every_flip(self):
        # A linear hash can collide; verify one known seeded example,
        # without claiming every changed input produces a changed output.
        x = encode_bits([1, 0, 0, 0])
        y = encode_bits([0, 0, 0, 0])
        seed = encode_bits([0, 0, 0, 1, 0, 0])
        self.assertNotEqual(toeplitz_hash(x, 4, 3, seed).key,
                            toeplitz_hash(y, 4, 3, seed).key)


if __name__ == "__main__":
    unittest.main()
