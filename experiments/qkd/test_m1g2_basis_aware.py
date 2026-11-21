import unittest
from m1g2_basis_aware import experiment


def ideal(bit, prep, measurement):
    return bit if prep == measurement else 0


class BasisAwareTests(unittest.TestCase):
    def test_accounting(self):
        r = experiment(1000, 44, measure=ideal)
        self.assertTrue(r['accounting_valid'])
        self.assertGreater(r['z_key_candidates']['matched'], 0)
        self.assertGreater(r['x_parameter_estimation_candidates']['matched'], 0)

    def test_ideal_errors(self):
        r = experiment(1000, 44, measure=ideal)
        self.assertEqual(r['z_key_candidates']['errors'], 0)
        self.assertEqual(r['x_parameter_estimation_candidates']['errors'], 0)

    def test_reproducibility(self):
        self.assertEqual(experiment(300, 7, measure=ideal),
                         experiment(300, 7, measure=ideal))

    def test_bias(self):
        r = experiment(10000, 9, z_probability=.9, measure=ideal)
        self.assertGreater(r['z_key_candidates']['matched'],
                           r['x_parameter_estimation_candidates']['matched'])

    def test_rejected_inputs(self):
        for kw in ({'transmissions': 0}, {'intercept_percent': -1},
                   {'intercept_percent': 101}, {'z_probability': 0},
                   {'z_probability': 1}, {'seed': -1}):
            args = dict(transmissions=10, seed=2, measure=ideal)
            args.update(kw)
            with self.assertRaises(ValueError):
                experiment(**args)

    def test_no_claim_or_export(self):
        r = experiment(100, 7, measure=ideal)
        self.assertFalse(r['security_model_validated'])
        self.assertFalse(r['hpke_export_authorized'])
        self.assertIsNone(r['finite_key_phase_error_bound'])

    def test_attack_diagnostics(self):
        def adversarial(bit, prep, measurement):
            return bit ^ 1 if prep == measurement else bit
        r = experiment(400, 8, intercept_percent=100, measure=adversarial)
        self.assertTrue(r['accounting_valid'])
        self.assertFalse(r['security_qualified'])

if __name__ == '__main__':
    unittest.main()
