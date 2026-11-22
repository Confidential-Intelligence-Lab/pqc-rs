"""S5.C fail-closed profile and numerical equation regression."""
import unittest
from dataclasses import replace

from s5c_research_profile import ResearchProfile, ProfileError, assess


class S5CResearchProfileTests(unittest.TestCase):
    def setUp(self):
        self.profile = ResearchProfile()

    def test_fixed_precommitted_parameterization(self):
        r = assess(self.profile)
        self.assertEqual(r['equation_k'], 16384)
        self.assertEqual(r['ec_leakage_upper_bits'], 4096)
        self.assertEqual(r['numerical_bound']['k_test'], 16384)

    def test_z_overshoot_never_promotes_k(self):
        r = assess(self.profile, observed_z_count=17000)
        self.assertEqual(r['observed_z_count'], 17000)
        self.assertEqual(r['equation_k'], 16384)
        self.assertFalse(r['observed_k_used_for_eq2'])

    def test_numerical_fitness_is_not_security(self):
        r = assess(self.profile)
        self.assertTrue(r['requested_length_numerically_fits'])
        for f in ('conditional_security_supported', 'security_qualified',
                  'hpke_export_authorized', 'qkd_psk_available',
                  'finite_key_theorem_hypotheses_verified'):
            self.assertIs(r[f], False)

    def test_report_separates_confirmation(self):
        r = assess(self.profile)
        self.assertEqual(r['confirmation_tag_bits_reported_separately'], 64)
        self.assertTrue(r['confirmation_tag_not_double_subtracted_from_tlgr_penalty'])

    def test_invalid_observed_z_rejected(self):
        for k in (16383, -1, 100001, True, 3.5):
            with self.subTest(k=k), self.assertRaises(ProfileError):
                assess(self.profile, observed_z_count=k)

    def test_bad_profiles_fail_closed(self):
        for p in (replace(self.profile, n_key=32),
                  replace(self.profile, max_transmissions=30000),
                  replace(self.profile, preparation_quality=0.98),
                  replace(self.profile, epsilon_secrecy=True),
                  replace(self.profile, block_size=64)):
            with self.subTest(p=p), self.assertRaises(ProfileError):
                assess(p)

    def test_nominal_budget_not_certified(self):
        r = assess(self.profile)
        self.assertTrue(r['nominal_budget_within_target'])
        self.assertFalse(r['nominal_authentication_advantage_proven'])

    def test_no_output_keys(self):
        r = assess(self.profile)
        self.assertFalse(any('secret_bytes' in x or 'raw_key' in x for x in r))


if __name__ == '__main__':
    unittest.main()
