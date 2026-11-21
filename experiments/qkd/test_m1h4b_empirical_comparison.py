import unittest
from m1h4b_empirical_comparison import compare_stopping, compare_authenticated_subset, campaign

class H4BTests(unittest.TestCase):
    def test_fixture_stopping(self):
        self.assertEqual(compare_stopping(n_x=2,k_z=2,p_x=.5,cap=24,trials=500)['status'],'PASS')

    def test_bias_stopping(self):
        self.assertEqual(compare_stopping(n_x=2,k_z=2,p_x=.35,cap=35,trials=600)['status'],'PASS')

    def test_os_stopping(self):
        self.assertEqual(compare_stopping(n_x=2,k_z=2,p_x=.5,cap=24,trials=500,mode='os')['status'],'PASS')

    def test_authenticated_subset(self):
        self.assertEqual(compare_authenticated_subset(trials=450)['status'],'PASS')

    def test_no_qualification(self):
        r=compare_stopping(n_x=2,k_z=2,p_x=.5,cap=24,trials=500)
        self.assertFalse(r['security_model_validated'])
        s=compare_authenticated_subset(trials=450)
        self.assertFalse(s['hpke_export_authorized'])

    def test_bad_trials(self):
        with self.assertRaises(ValueError):
            compare_stopping(n_x=2,k_z=2,p_x=.5,cap=24,trials=20)

    def test_campaign(self):
        result=campaign(500,450)
        self.assertEqual(result['decision'],'EMPIRICAL_COMPARISON_PASS')
        self.assertFalse(result['theorem_sampling_validated'])

if __name__=='__main__':
    unittest.main()
