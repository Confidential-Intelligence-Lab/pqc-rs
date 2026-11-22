import math
import unittest
from m1g3_tomamichel_bound import BoundInput, BoundError, evaluate


class EquationTests(unittest.TestCase):
    def sample(self, **kw):
        d = dict(n_key=100000, k_test=10000, q_tolerance=0.02,
                 leakage_ec_bits=5000, epsilon_secrecy=1e-10,
                 epsilon_correctness=1e-10)
        d.update(kw)
        return evaluate(BoundInput(**d))

    def test_independent_equation_vector(self):
        # Independently evaluate Eq. 2 with direct mathematical components.
        r = self.sample()
        n, k, sec, cor = 100000, 10000, 1e-10, 1e-10
        fluctuation = math.sqrt((1/n + 1/k) * (1+1/k) * math.log(2/sec))
        phase = 0.02 + fluctuation
        entropy = -(phase*math.log2(phase)+(1-phase)*math.log2(1-phase))
        expected = n*(1-entropy)-5000-math.log2(2/(sec*sec*cor))
        self.assertAlmostEqual(r['mu'], fluctuation, places=13)
        self.assertAlmostEqual(r['raw_bound_bits'], expected, places=7)
        self.assertEqual(r['maximum_numerical_key_bits'], math.floor(math.nextafter(expected, -math.inf)))

    def test_small_blocks_produce_no_key(self):
        self.assertEqual(self.sample(n_key=274,k_test=222,leakage_ec_bits=141)['maximum_numerical_key_bits'],0)

    def test_more_leakage_never_increases_length(self):
        self.assertGreaterEqual(self.sample(leakage_ec_bits=1000)['maximum_numerical_key_bits'],
                                self.sample(leakage_ec_bits=2000)['maximum_numerical_key_bits'])

    def test_stricter_secrecy_never_increases_length(self):
        self.assertGreaterEqual(self.sample(epsilon_secrecy=1e-6)['maximum_numerical_key_bits'],
                                self.sample(epsilon_secrecy=1e-10)['maximum_numerical_key_bits'])

    def test_higher_qber_never_increases_length(self):
        self.assertGreaterEqual(self.sample(q_tolerance=0.01)['maximum_numerical_key_bits'],
                                self.sample(q_tolerance=0.04)['maximum_numerical_key_bits'])

    def test_invalid_parameters_rejected(self):
        for kw in (dict(k_test=0),dict(n_key=-1),dict(leakage_ec_bits=-1),
                   dict(q_tolerance=0.7),dict(epsilon_secrecy=0),
                   dict(epsilon_correctness=1),dict(preparation_quality=1.1),
                   dict(n_key=True),dict(q_tolerance=float('nan'))):
            with self.subTest(kw=kw), self.assertRaises(BoundError):
                self.sample(**kw)

    def test_always_unqualified(self):
        r = self.sample()
        self.assertFalse(r['security_model_validated'])
        self.assertFalse(r['hpke_export_authorized'])
        self.assertFalse(r['protocol_assumptions_verified'])


if __name__ == '__main__':
    unittest.main()
