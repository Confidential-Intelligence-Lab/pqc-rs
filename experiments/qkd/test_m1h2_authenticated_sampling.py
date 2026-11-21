import json
import unittest
from dataclasses import dataclass
from m1h2_authenticated_sampling import run_records, experiment, TranscriptError, DOMAIN, _canon
from m1g5c1_measurement_transcript import simulate_records
import hmac


def ideal(bit, prep, measurement):
    return bit if prep == measurement else 0


class H2Tests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = simulate_records(n_z=12, k_x=12, max_transmissions=200,
                                          seed=9, measure=ideal)
        self.kw = dict(n_key=12, k_test=12, max_transmissions=200,
                       selection_seed=19, authentication_key=b'A' * 32,
                       session_id=b'fixed-session-identity-01')

    def run_h2(self, **kwargs):
        params = dict(self.kw)
        params.update(kwargs)
        return run_records(self.a, self.b, **params)

    def test_ideal(self):
        r = self.run_h2()
        self.assertEqual(r['decision'], 'PARAMETER_ESTIMATION_PASS_UNQUALIFIED')
        self.assertTrue(r['authenticated_x_key_selection'])
        self.assertTrue(r['statistics_independently_verified'])
        self.assertEqual(r['public_x_key_bits_disclosed'], 0)
        self.assertEqual(r['public_z_bits_disclosed'], 24)
        self.assertEqual(r['public_discussion_messages'], 9)

    def test_no_secrecy_claim(self):
        r = self.run_h2()
        for name in ('security_model_validated', 'security_qualified',
                     'hpke_export_authorized', 'theorem_specific_protocol_validated'):
            self.assertFalse(r[name])
        self.assertNotIn('key_hex', json.dumps(r))

    def test_reproducible_observables(self):
        self.assertEqual(self.run_h2(), self.run_h2())

    def test_fresh_selection_marker(self):
        self.assertFalse(self.run_h2(selection_seed=None)['public_seed_is_not_secret'])

    def test_invalid_config(self):
        for k, v in [('n_key', 0), ('k_test', 0), ('max_transmissions', 4),
                     ('selection_seed', -1), ('q_tolerance', float('nan'))]:
            with self.subTest(k=k), self.assertRaises(ValueError):
                self.run_h2(**{k: v})

    def test_missing_quota_aborts(self):
        self.assertEqual(self.run_h2(n_key=100)['decision'], 'ABORT_QUOTAS')

    def test_tamper_mac(self):
        def modify(kind, data, tag):
            if kind == 'z_test_selection':
                return data + b' ', tag
            return data, tag
        with self.assertRaises(TranscriptError):
            self.run_h2(hook=modify)

    def test_replay_substitution(self):
        first = []
        def replay(kind, data, tag):
            if kind == 'x_key_selection':
                first[:] = [data, tag]
            if kind == 'z_test_selection':
                return first
            return data, tag
        with self.assertRaises(TranscriptError):
            self.run_h2(hook=replay)

    def test_wrong_session(self):
        def mutate(kind, data, tag):
            if kind == 'z_test_selection':
                obj = json.loads(data)
                obj['sid'] = '0' * 48
                data = _canon(obj)
                tag = hmac.digest(self.kw['authentication_key'], DOMAIN + data, 'sha256')
            return data, tag
        with self.assertRaises(TranscriptError):
            self.run_h2(hook=mutate)

    def test_nonmember_indices(self):
        def mutate(kind, data, tag):
            if kind == 'z_test_selection':
                obj = json.loads(data)
                obj['payload']['indices'] = [999] * 12
                data = _canon(obj)
                tag = hmac.digest(self.kw['authentication_key'], DOMAIN + data, 'sha256')
            return data, tag
        with self.assertRaises(TranscriptError):
            self.run_h2(hook=mutate)

    def test_disclosure_mismatch(self):
        def mutate(kind, data, tag):
            if kind == 'z_test_bits_bob':
                obj = json.loads(data)
                obj['payload']['bits'][0] ^= 1
                data = _canon(obj)
                tag = hmac.digest(self.kw['authentication_key'], DOMAIN + data, 'sha256')
            return data, tag
        with self.assertRaises(TranscriptError):
            self.run_h2(hook=mutate)

    def test_attack_threshold_abort(self):
        a, b = self.a, list(self.b)
        # Corrupt all Z-basis matched positions.
        from m1g5c1_measurement_transcript import BobRecord
        for i, (x, y) in enumerate(zip(a, b)):
            if x.basis == y.basis == 0:
                b[i] = BobRecord(y.bit ^ 1, y.basis)
        r = run_records(a, b, **self.kw)
        self.assertEqual(r['decision'], 'ABORT_QBER')
        self.assertEqual(r['observed_z_qber'], 1.0)
        self.assertFalse(r['hpke_export_authorized'])

    def test_actual_record_regression(self):
        r = experiment(n_key=12, k_test=12, max_transmissions=200,
                       seed=9, measure=ideal)
        self.assertTrue(r['authenticated_z_disclosures'])


if __name__ == '__main__':
    unittest.main()
