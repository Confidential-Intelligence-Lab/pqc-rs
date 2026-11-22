import math
import unittest
from m1h4a_sampling_model import QuotaModel, probabilities, stopping_pmf, uniform_subset_probability

class H4AModelTests(unittest.TestCase):
    def test_basis_probabilities(self):
        x,z,m = probabilities(0.5)
        self.assertEqual((x,z,m),(0.25,0.25,0.5))

    def test_quota_minimal_stop(self):
        r = stopping_pmf(QuotaModel(1,1,0.5,2))
        self.assertAlmostEqual(r['stop_pmf'][2], 0.125)
        self.assertAlmostEqual(r['p_abort_cap'], 0.875)

    def test_probability_conservation(self):
        for px in (0.2, 0.5, 0.8):
            r = stopping_pmf(QuotaModel(3,2,px,22))
            self.assertLess(r['mass_error'], 1e-12)
            self.assertGreaterEqual(r['p_abort_cap'], 0)

    def test_increasing_cap_reduces_abort(self):
        a = stopping_pmf(QuotaModel(3,2,0.5,10))
        b = stopping_pmf(QuotaModel(3,2,0.5,20))
        self.assertGreaterEqual(a['p_abort_cap'], b['p_abort_cap'])

    def test_conditioned_early_stop(self):
        r = stopping_pmf(QuotaModel(1,1,0.7,5))
        self.assertEqual(min(r['stop_pmf']), 2)

    def test_uniform_subset(self):
        probs = [uniform_subset_probability(5,2,(i,j)) for i in range(5) for j in range(i+1,5)]
        self.assertEqual(len(probs),10)
        self.assertAlmostEqual(sum(probs),1.0)

    def test_bad_subset(self):
        for subset in ((1,1), (0,5), (0,), (0.0,1)):
            with self.assertRaises(ValueError):
                uniform_subset_probability(5,2,subset)

    def test_invalid_model(self):
        for vals in ((0,2,0.5,10),(2,0,0.5,10),(2,2,1,10),(2,2,float('nan'),10),(2,2,0.5,3)):
            with self.assertRaises(ValueError):
                QuotaModel(*vals)

    def test_fail_closed(self):
        r=stopping_pmf(QuotaModel(2,2,0.5,20))
        self.assertFalse(r['security_model_validated'])
        self.assertFalse(r['hpke_export_authorized'])

if __name__ == '__main__':
    unittest.main()
