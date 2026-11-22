import unittest
from fractions import Fraction
from m1h4f_quota_overshoot import exact_joint, enumerate_small, event_probabilities, subset_probability, public_report

class H4FTests(unittest.TestCase):
    def test_independent_bruteforce(self):
        for n,k,c,p in [(1,1,3,'1/2'),(1,1,6,'2/5'),(2,1,7,'3/5'),(2,2,8,'1/3')]:
            result=exact_joint(n,k,c,p)
            brute=enumerate_small(n,k,c,p)
            self.assertEqual(result['joint'],brute['joint'])
            self.assertEqual(result['p_abort'],brute['p_abort'])
    def test_witness_zzx(self):
        v=exact_joint(1,1,3)
        self.assertEqual(v['joint'][(3,1,2)],Fraction(1,64))
        self.assertEqual(v['joint'][(3,2,1)],Fraction(1,64))
    def test_no_double_overshoot(self):
        v=exact_joint(2,2,12)
        self.assertTrue(all(x==2 or z==2 for _,x,z in v['joint']))
    def test_conservation(self):
        for p in ['1/2','1/3','7/10']:
            v=exact_joint(2,2,14,p)
            self.assertEqual(v['p_success']+v['p_abort'],1)
    def test_conditional_normalization(self):
        v=exact_joint(1,1,6)
        self.assertEqual(v['p_x_overshoot_given_success'],v['p_x_overshoot']/v['p_success'])
        self.assertLessEqual(v['p_x_overshoot_given_success']+v['p_z_overshoot_given_success'],1)
    def test_cap_effect(self):
        lo=exact_joint(2,2,6)
        hi=exact_joint(2,2,15)
        self.assertGreater(lo['p_abort'],hi['p_abort'])
    def test_probability_input(self):
        self.assertEqual(event_probabilities('1/2'),{'X':Fraction(1,4),'Z':Fraction(1,4),'M':Fraction(1,2)})
        for val in [0,1,'-1/5','7/6','bad']:
            with self.assertRaises(ValueError):event_probabilities(val)
    def test_validation(self):
        for args in [(0,1,5),(1,0,5),(1,1,1),(True,1,5),(1,1,257)]:
            with self.assertRaises(ValueError):exact_joint(*args)
        with self.assertRaises(ValueError):enumerate_small(1,1,11)
    def test_uniform_conditional_subset(self):
        self.assertEqual(subset_probability(4,2),Fraction(1,6))
        self.assertEqual(subset_probability(2,2),1)
        with self.assertRaises(ValueError):subset_probability(2,3)
    def test_no_security_claim(self):
        r=public_report(exact_joint(2,2,8))
        for key in ['theorem_stopping_rule_validated','theorem_sampling_validated','security_model_validated','hpke_export_authorized']:
            self.assertIs(r[key],False)
    def test_joint_support(self):
        v=exact_joint(1,1,8)
        self.assertTrue(all(t>=x+z for t,x,z in v['joint']))
        self.assertTrue(all(x>=1 and z>=1 for t,x,z in v['joint']))

if __name__=='__main__':unittest.main()
