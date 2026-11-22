import unittest
from m1g4_independent_oracle import evaluate

class OracleTests(unittest.TestCase):
    def test_small_block_rejects(self):
        r = evaluate(274,222,0,141,1e-10,1e-10)
        self.assertEqual(r['decision'], 'NO_KEY')
        self.assertAlmostEqual(r['mu'], 0.4407711738132392, places=12)
    def test_large_reference_mu(self):
        r = evaluate(100000,10000,.02,10000,1e-10,1e-10)
        self.assertAlmostEqual(r['mu'], .05108180401213586, places=12)
    def test_more_leakage_reduces_budget(self):
        a = evaluate(100000,10000,.02,5000,1e-10,1e-10)
        b = evaluate(100000,10000,.02,10000,1e-10,1e-10)
        self.assertGreaterEqual(a['maximum_numerical_key_bits'],b['maximum_numerical_key_bits'])
    def test_stricter_epsilon_reduces_budget(self):
        a=evaluate(100000,10000,.02,10000,1e-6,1e-10)
        b=evaluate(100000,10000,.02,10000,1e-10,1e-10)
        self.assertGreaterEqual(a['maximum_numerical_key_bits'],b['maximum_numerical_key_bits'])
    def test_invalid(self):
        for args in [(0,100,0,0,1e-10,1e-10),(100,0,0,0,1e-10,1e-10),(100,100,-.1,0,1e-10,1e-10),(100,100,0,-1,1e-10,1e-10),(100,100,0,0,0,1e-10)]:
            with self.subTest(args=args), self.assertRaises(ValueError): evaluate(*args)
    def test_no_qualification(self):
        r=evaluate(100000,10000,.02,10000,1e-10,1e-10)
        self.assertFalse(r['security_model_validated'])
        self.assertFalse(r['hpke_export_authorized'])

if __name__ == '__main__': unittest.main()
