import unittest
from fractions import Fraction
from m1h4g_conditional_sampling import conditional_law, postannouncement_law, conditional_on_success, report

class H4GTests(unittest.TestCase):
    def test_uniform_small(self):
        self.assertEqual(set(conditional_law(3,2).values()), {Fraction(1,3)})
    def test_law_normalizes(self):
        for n in (2,3,5):
            for k in range(1,n+1):
                self.assertEqual(sum(conditional_law(n,k).values()),1)
    def test_reject_invalid_selection(self):
        for n,k in ((0,1),(1,0),(1,2),(True,1),(2,False)):
            with self.assertRaises(ValueError):conditional_law(n,k)
    def test_postannouncement_delta(self):
        self.assertEqual(postannouncement_law(4,2,(1,3)), {(1,3):Fraction(1)})
    def test_reject_bad_announcement(self):
        for s in ((2,1),(0,0),(0,4),(0,),[0,1],(False,1)):
            with self.assertRaises(ValueError):postannouncement_law(4,2,s)
    def test_cap_conditioned_normalizes(self):
        r=conditional_on_success(2,2,8,1)
        self.assertEqual(sum(r['population_given_success'].values()),1)
        self.assertEqual(sum(r['subset_rank_given_success'].values()),1)
    def test_overshoot_mixture_not_uniform(self):
        r=conditional_on_success(1,1,7,1)
        d=r['subset_rank_given_success']
        self.assertGreater(d[(0,)],d[(1,)])
    def test_derive_mixture(self):
        r=conditional_on_success(2,1,8,1,'2/5')
        expected=sum((w*Fraction(1,x) for x,w in r['population_given_success'].items()),Fraction())
        self.assertEqual(r['subset_rank_given_success'][(0,)], expected)
    def test_cap_impact(self):
        a=conditional_on_success(2,1,5,1)
        b=conditional_on_success(2,1,12,1)
        self.assertNotEqual(a['population_given_success'],b['population_given_success'])
    def test_independent_of_z_for_fixed_population(self):
        self.assertEqual(conditional_law(4,2),conditional_law(4,2))
    def test_invalid_selection_exceeds_quota(self):
        with self.assertRaises(ValueError):conditional_on_success(2,2,8,3)
    def test_no_security_claim(self):
        v=report(2,2,8,1)
        for k in ('theorem_sampling_validated','security_model_validated','hpke_export_authorized','quantum_sampling_theorem_mapped'):
            self.assertIs(v[k],False)
    def test_public_only_report(self):
        v=report(2,1,7,1)
        self.assertNotIn('key_bits',v)
        self.assertNotIn('seed',v)

if __name__=='__main__':unittest.main()
