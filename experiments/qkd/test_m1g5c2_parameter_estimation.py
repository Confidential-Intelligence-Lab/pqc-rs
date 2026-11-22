import unittest

from m1g5b_authenticated_transcript import TranscriptError
from m1g5c1_measurement_transcript import simulate_records
from m1g5c2_parameter_estimation import evaluate_records, experiment


def ideal(bit, prep, basis):
    return bit if prep == basis else 0


def corrupted(bit, prep, basis):
    return bit ^ 1 if prep == basis == 1 else bit


class C2Tests(unittest.TestCase):
    def records(self, measure=ideal, n_z=12, k_x=10, limit=200):
        return simulate_records(n_z=n_z, k_x=k_x, max_transmissions=limit,
                                seed=44, measure=measure)

    def evaluate(self, records, **kwargs):
        a, b = records
        defaults = dict(n_z=12, k_x=10, max_transmissions=200,
                        q_tolerance=.05, leakage_ec_bits=0,
                        epsilon_secrecy=1e-10, epsilon_correctness=1e-10)
        defaults.update(kwargs)
        return evaluate_records(a, b, **defaults)

    def test_ideal_authenticated_parameter_estimation(self):
        r = self.evaluate(self.records())
        self.assertEqual(r['decision'], 'PARAMETER_ESTIMATION_PASS_UNQUALIFIED')
        self.assertEqual(r['x_test_errors'], 0)
        self.assertTrue(r['transcript_hash_agreement'])
        self.assertTrue(r['sample_statistics_independently_checkable'])

    def test_all_x_errors_fail_threshold(self):
        r = self.evaluate(self.records(corrupted))
        self.assertEqual(r['decision'], 'ABORT_ERROR_THRESHOLD')
        self.assertEqual(r['x_test_errors'], 10)

    def test_unauthenticated_or_modified_frame_rejected(self):
        def tamper(kind, data, tag):
            return (data + b' ', tag) if kind == 'alice_x_sample_bits' else (data, tag)
        with self.assertRaises(TranscriptError):
            self.evaluate(self.records(), frame_hook=tamper)

    def test_replay_substitution_rejected(self):
        cache = []
        def replay(kind, data, tag):
            if kind == 'alice_x_sample_bits':
                cache.append((data, tag))
            if kind == 'bob_x_sample_bits':
                return cache[0]
            return data, tag
        with self.assertRaises(TranscriptError):
            self.evaluate(self.records(), frame_hook=replay)

    def test_wrong_authentication_key_rejected(self):
        def swap(kind, data, tag):
            return (data, b'\x00' * 32) if kind == 'bob_bases' else (data, tag)
        with self.assertRaises(TranscriptError):
            self.evaluate(self.records(), frame_hook=swap)

    def test_no_key_export_or_model_claim(self):
        r = self.evaluate(self.records())
        self.assertFalse(r['hpke_export_authorized'])
        self.assertFalse(r['security_model_validated'])
        self.assertFalse(r['numerical_bound']['protocol_assumptions_verified'])
        self.assertEqual(r['z_key_bits_disclosed_publicly'], 0)
        self.assertTrue(r['parameter_estimation_quota_ordered_not_random'])

    def test_short_transmission_limit_abort(self):
        r = self.evaluate(self.records(limit=22), max_transmissions=22)
        self.assertEqual(r['decision'], 'ABORT_QUOTAS')

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            self.evaluate(self.records(), q_tolerance=float('nan'))

    def test_reproducibility_of_statistics(self):
        a = experiment(n_z=12, k_x=10, max_transmissions=200, seed=44, measure=ideal)
        b = experiment(n_z=12, k_x=10, max_transmissions=200, seed=44, measure=ideal)
        self.assertEqual(a['x_test_errors'], b['x_test_errors'])
        self.assertEqual(a['transmissions'], b['transmissions'])

    def test_no_raw_key_in_report(self):
        r = self.evaluate(self.records())
        self.assertNotIn('alice_bits', r)
        self.assertNotIn('bob_bits', r)
        self.assertEqual(r['x_test_bits_disclosed_publicly'], 20)


if __name__ == '__main__':
    unittest.main()
