import unittest
from m1g5a_quota_sifting import experiment


def ideal(bit, prep, measurement):
    return bit if prep == measurement else 0


class QuotaSiftingTests(unittest.TestCase):
    def params(self, **changes):
        kw = dict(n_z=35, k_x=40, max_transmissions=1500, seed=20261120, measure=ideal)
        kw.update(changes)
        return kw

    def test_both_quotas_met_exactly(self):
        r = experiment(**self.params())
        self.assertEqual(r['decision'], 'QUOTAS_MET')
        self.assertEqual((r['z_matched_accepted'], r['x_matched_accepted']), (35, 40))
        self.assertTrue(r['accounting_valid'])

    def test_zero_error_ideal(self):
        r = experiment(**self.params())
        self.assertEqual((r['z_errors'], r['x_errors']), (0, 0))

    def test_strict_abort_limit(self):
        r = experiment(**self.params(max_transmissions=75))
        self.assertEqual(r['decision'], 'ABORT_MAX_TRANSMISSIONS')
        self.assertEqual(r['transmissions'], 75)
        self.assertEqual(r['abort_reason'], 'MATCHED_BASIS_QUOTAS_UNMET')
        self.assertTrue(r['accounting_valid'])

    def test_reproducible_diagnostics(self):
        self.assertEqual(experiment(**self.params()), experiment(**self.params()))

    def test_bias_quota_and_accounting(self):
        r = experiment(**self.params(n_z=80, k_x=10, z_probability=0.85,
                                     max_transmissions=4000))
        self.assertEqual(r['decision'], 'QUOTAS_MET')
        self.assertGreater(r['quota_filled_discards'], 0)
        self.assertTrue(r['accounting_valid'])

    def test_attacked_channel_has_errors(self):
        def flip(bit, prep, measurement):
            return 1 - bit if prep == measurement else bit
        r = experiment(**self.params(measure=flip, intercept_percent=0))
        self.assertGreater(r['z_errors'] + r['x_errors'], 0)
        self.assertTrue(r['accounting_valid'])

    def test_reject_invalid_arguments(self):
        for changed in (dict(n_z=0), dict(k_x=0), dict(max_transmissions=0),
                        dict(max_transmissions=74), dict(seed=-1),
                        dict(z_probability=0), dict(z_probability=1),
                        dict(intercept_percent=-1), dict(intercept_percent=101),
                        dict(n_z=True), dict(k_x=3.0)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                experiment(**self.params(**changed))

    def test_invalid_measurement_rejected(self):
        with self.assertRaises(ValueError):
            experiment(**self.params(measure=lambda *_: 2))

    def test_no_security_claim_or_export(self):
        r = experiment(**self.params())
        self.assertFalse(r['security_model_validated'])
        self.assertFalse(r['theorem_specific_protocol_validated'])
        self.assertFalse(r['hpke_export_authorized'])
        self.assertFalse(r['basis_announcement_authenticated'])
        self.assertNotIn('key', r)


if __name__ == '__main__':
    unittest.main()
