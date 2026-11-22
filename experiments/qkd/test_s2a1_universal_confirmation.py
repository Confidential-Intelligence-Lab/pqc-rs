"""S2.A1 additive confirmation regression tests."""
import itertools
import json
import unittest
from s2a1_universal_confirmation import (
    ConfirmationError, confirm_fixed_inputs, fresh_seed,
    toeplitz_confirmation_tag, public_report,
)

SESSION = b's2a1-session-id-01'
AUTH = b'auth-for-tests-only-' + b'k' * 32


def run(a, b, **kw):
    return confirm_fixed_inputs(a, b, session_id=SESSION, authentication_key=AUTH, **kw)


class S2A1Tests(unittest.TestCase):
    def test_equal_keys_and_public_metadata(self):
        x = '010101001101' * 8
        report = run(x, x, tag_bits=40)
        self.assertEqual(report.confirmation_tag_bits_disclosed, 40)
        self.assertEqual(report.public_seed_bits, len(x) + 39)
        self.assertEqual(report.epsilon_correctness_bound, '2^-40')
        self.assertFalse(report.security_qualified)
        self.assertFalse(report.hpke_export_authorized)
        self.assertNotIn(x, json.dumps(public_report(report)))

    def test_single_bit_mismatch_rejected_by_zero_seed_only_when_forced(self):
        self.assertEqual(toeplitz_confirmation_tag('01', '000', 2), '00')
        self.assertRaises(ConfirmationError, run, '00', '10', tag_bits=2,
                          seed_source=lambda n: '010')

    def test_all_mismatch_exhaustive_two_universal(self):
        n, t = 3, 2
        strings = [''.join(x) for x in itertools.product('01', repeat=n)]
        seeds = [''.join(x) for x in itertools.product('01', repeat=n + t - 1)]
        for a in strings:
            for b in strings:
                if a == b:
                    continue
                matches = sum(toeplitz_confirmation_tag(a, s, t) ==
                              toeplitz_confirmation_tag(b, s, t) for s in seeds)
                self.assertEqual(matches, len(seeds) // (2 ** t))

    def test_tampered_mac(self):
        with self.assertRaisesRegex(ConfirmationError, 'authentication failed'):
            run('0' * 24, '0' * 24, wire_hook=lambda data, tag: (data, bytes(32)))

    def test_session_substitution_with_recomputed_mac(self):
        import hashlib, hmac
        from s2a1_universal_confirmation import DOMAIN
        def replace(data, tag):
            obj = json.loads(data)
            obj['session'] = b'another-session-1'.hex()
            swapped = json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('ascii')
            return swapped, hmac.digest(AUTH, DOMAIN + swapped, 'sha256')
        with self.assertRaisesRegex(ConfirmationError, 'transcript mismatch'):
            run('101010', '101010', wire_hook=replace)

    def test_bad_inputs(self):
        for a, b in [('', ''), ('001', '01'), ('002', '002')]:
            with self.assertRaises(ValueError):
                run(a, b)
        with self.assertRaises(ValueError):
            run('0', '0', tag_bits=0)
        with self.assertRaises(ValueError):
            run('0', '0', tag_bits=True)
        with self.assertRaises(ValueError):
            confirm_fixed_inputs('0', '0', session_id=b'short', authentication_key=AUTH)

    def test_bad_seed(self):
        with self.assertRaisesRegex(ConfirmationError, 'invalid public seed'):
            run('0' * 24, '0' * 24, seed_source=lambda n: '0' * (n - 1))

    def test_fresh_seed_length(self):
        self.assertEqual(len(fresh_seed(73)), 73)
        self.assertRaises(ValueError, fresh_seed, 0)

    def test_confirmation_bound_not_full_security(self):
        report = run('1' * 512, '1' * 512, tag_bits=64)
        self.assertEqual(report.epsilon_correctness_bound, '2^-64')
        self.assertFalse(report.authentication_provisioning_validated)
        self.assertFalse(report.security_model_validated)

    def test_preexisting_wrong_key_not_always_pass(self):
        # Deterministic all-one Toeplitz seed is merely a regression vector.
        with self.assertRaises(ConfirmationError):
            run('0' * 8, '1' + '0' * 7, tag_bits=8,
                seed_source=lambda n: '1' * n)


if __name__ == '__main__':
    unittest.main()
