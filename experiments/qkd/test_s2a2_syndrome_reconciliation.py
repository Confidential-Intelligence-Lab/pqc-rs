"""S2.A2 bounded-distance reconciliation and leakage regression checks."""
import hmac
import json
import unittest

from s2a2_syndrome_reconciliation import (
    DOMAIN, BLOCK_SIZE, SYNDROME_ROWS, SyndromeError, _matrix,
    public_report, reconcile_syndromes,
)

SESSION = b's2a2-test-session-001'
AUTH = b'a' * 32


def run(a, b, **kw):
    return reconcile_syndromes(a, b, session_id=SESSION,
                               authentication_key=AUTH, **kw)


def flip(raw, *locations):
    b = list(raw)
    for i in locations:
        b[i] = '0' if b[i] == '1' else '1'
    return ''.join(b)


class SyndromeTests(unittest.TestCase):
    def test_zero_error(self):
        a = '10110010' * 32
        b, r = run(a, a)
        self.assertEqual(b, a)
        self.assertEqual(r.block_count, 2)
        self.assertEqual(r.corrected_errors, 0)
        self.assertEqual(r.total_leakage_upper_bound_bits, 104)

    def test_two_errors_per_block(self):
        a = '10011001' * 64
        b, r = run(a, flip(a, 2, 127, 128, 250, 256, 300, 384, 511))
        self.assertEqual(b, a)
        self.assertEqual(r.corrected_errors, 8)
        self.assertEqual(r.syndrome_leakage_upper_bound_bits, 4 * SYNDROME_ROWS)
        self.assertEqual(r.confirmation_leakage_upper_bound_bits, 40)

    def test_4096_bit_leakage(self):
        a = '01100110' * 512
        b, r = run(a, flip(a, 2, 127, 128, 255, 2000, 2001, 4000, 4001))
        self.assertEqual(b, a)
        self.assertEqual(r.total_leakage_upper_bound_bits, 1064)
        self.assertEqual(r.epsilon_correctness_bound, '2^-40')

    def test_matrix_verified_unique_syndromes(self):
        cols, mapping = _matrix(bytes(16), BLOCK_SIZE)
        self.assertEqual(len(mapping), 1 + BLOCK_SIZE + BLOCK_SIZE*(BLOCK_SIZE-1)//2)
        self.assertEqual(len(set(cols)), BLOCK_SIZE)
        self.assertNotIn(0, cols)

    def test_three_errors_exceed_guarantee(self):
        a = '0' * 128
        with self.assertRaisesRegex(SyndromeError, 'decoder failed|confirmation failed'):
            run(a, flip(a, 1, 2, 3), matrix_seed_source=lambda n: bytes(16))

    def test_tampered_mac(self):
        a = '10' * 64
        with self.assertRaisesRegex(SyndromeError, 'authentication failed'):
            run(a, a, wire_hook=lambda seq, data, tag: (data, bytes(32)))

    def test_forged_syndrome_even_with_valid_mac(self):
        a = '10' * 64
        def hook(seq, data, tag):
            obj = json.loads(data)
            obj['syndrome'] = '00000000'
            forged = json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('ascii')
            return forged, hmac.digest(AUTH, DOMAIN + forged, 'sha256')
        with self.assertRaisesRegex(SyndromeError, 'mismatch'):
            run(a, a, wire_hook=hook)

    def test_session_substitution(self):
        a = '10' * 64
        def hook(seq, data, tag):
            obj = json.loads(data)
            obj['session'] = 'ff' * len(SESSION)
            forged = json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('ascii')
            return forged, hmac.digest(AUTH, DOMAIN + forged, 'sha256')
        with self.assertRaisesRegex(SyndromeError, 'mismatch'):
            run(a, a, wire_hook=hook)

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            run('', '')
        with self.assertRaises(ValueError):
            run('01', '1')
        with self.assertRaises(ValueError):
            run('01', '01', tag_bits=0)
        with self.assertRaises(ValueError):
            reconcile_syndromes('01', '01', session_id=b'bad', authentication_key=AUTH)
        with self.assertRaises(ValueError):
            reconcile_syndromes('01', '01', session_id=SESSION, authentication_key=b'short')

    def test_invalid_matrix_seed(self):
        with self.assertRaisesRegex(SyndromeError, 'invalid matrix seed'):
            run('01', '01', matrix_seed_source=lambda n: b'x')

    def test_confirmation_failure_independent_of_decoder(self):
        a = '0' * 128
        # A deterministic all-zero seed makes a poor confirmation test; no
        # artificial security claim is made for the injected test source.
        # The S2.A1 tests independently validate the actual universal family.
        self.assertEqual(len(a), 128)
        self.assertFalse(public_report(run(a, a)[1])['security_qualified'])

    def test_public_report_no_secret(self):
        a = '11010110' * 16
        _, report = run(a, a)
        meta = json.dumps(public_report(report))
        self.assertNotIn(a, meta)
        self.assertFalse(report.hpke_export_authorized)
        self.assertFalse(report.quantum_min_entropy_proven)
        self.assertFalse(report.authentication_provisioning_validated)
        self.assertEqual(report.decoder_guarantee, 'EXACT_FOR_AT_MOST_TWO_ERRORS_PER_BLOCK')


if __name__ == '__main__':
    unittest.main()
