import json
import unittest
from m1h3b_sampling_conformance import experiment
from m1h3a_randomness import RandomnessConfiguration, RandomnessStreams
from m1h2_authenticated_sampling import run_records
from m1g5c1_measurement_transcript import AliceRecord, BobRecord


def ideal(bit, prep, measurement):
    return bit if prep == measurement else 0


class H3BTests(unittest.TestCase):
    def kwargs(self):
        return dict(n_key=12, k_test=10, max_transmissions=500, oversample=2,
                    randomness_mode='fixture', fixture_seed=44, measure=ideal)

    def test_fixture_integrated(self):
        r = experiment(**self.kwargs())
        self.assertEqual(r['decision'], 'PARAMETER_ESTIMATION_PASS_UNQUALIFIED')
        self.assertTrue(r['authenticated_z_disclosures'])
        self.assertTrue(r['protocol_randomness_integrated'])
        self.assertTrue(r['public_seed_is_not_secret'])
        self.assertFalse(r['theorem_sampling_distribution_validated'])

    def test_reproducible_observables(self):
        self.assertEqual(experiment(**self.kwargs()), experiment(**self.kwargs()))

    def test_os_mode_integrated(self):
        args = dict(self.kwargs(), randomness_mode='os', fixture_seed=None)
        r = experiment(**args)
        self.assertTrue(r['selection_randomness_os_backed'])
        self.assertFalse(r['public_seed_is_not_secret'])

    def test_os_mode_no_seed(self):
        with self.assertRaises(ValueError):
            experiment(**dict(self.kwargs(), randomness_mode='os'))

    def test_no_key_material(self):
        s = json.dumps(experiment(**self.kwargs()))
        for term in ('secret_hex', 'raw_key', 'key_bytes'):
            self.assertNotIn(term, s)

    def test_fail_closed(self):
        r = experiment(**self.kwargs())
        for name in ('security_model_validated', 'security_qualified',
                     'hpke_export_authorized', 'theorem_stopping_rule_validated'):
            self.assertFalse(r[name])

    def test_abort(self):
        r = experiment(**dict(self.kwargs(), max_transmissions=44))
        self.assertEqual(r['decision'], 'ABORT_QUOTAS')
        self.assertFalse(r['hpke_export_authorized'])

    def test_bad_arguments(self):
        for key, val in [('oversample',0), ('n_key',0),('q_tolerance',float('nan'))]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                experiment(**dict(self.kwargs(), **{key:val}))

    def test_detect_corrupted_z(self):
        def corrupted(bit, prep, basis):
            return (bit ^ 1) if prep == basis == 0 else ideal(bit, prep, basis)
        r = experiment(**dict(self.kwargs(), measure=corrupted))
        self.assertEqual(r['decision'], 'ABORT_QBER')
        self.assertEqual(r['observed_z_qber'],1.0)

    def test_tamper_auth(self):
        def hook(kind, data, tag):
            return (data + b' ', tag) if kind == 'z_test_selection' else (data,tag)
        with self.assertRaises(ValueError):
            experiment(**dict(self.kwargs(), hook=hook))

    def test_sampling_uniform_reference(self):
        # Independently check approximate uniformity of first selected index.
        # Statistical smoke test only; not a theorem proof.
        counts=[0]*4
        for seed in range(800):
            rng=RandomnessStreams(RandomnessConfiguration('fixture', seed))
            counts[rng.sample_indices(4,1)[0]]+=1
        self.assertTrue(all(140 < c < 260 for c in counts), counts)

    def test_selection_provider_rejects_seed_combination(self):
        a=tuple(AliceRecord(i%2, i%2) for i in range(60))
        b=tuple(BobRecord(i%2, i%2) for i in range(60))
        rng=RandomnessStreams(RandomnessConfiguration('fixture', 4))
        with self.assertRaises(ValueError):
            run_records(a,b,n_key=10,k_test=10,max_transmissions=100,
                        selection_seed=12,selection_streams=rng)

if __name__ == '__main__':
    unittest.main()
