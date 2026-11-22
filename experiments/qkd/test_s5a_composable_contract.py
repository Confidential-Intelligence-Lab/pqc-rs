"""S5.A negative security-contract tests; not a composable quantum proof."""
from dataclasses import replace
import unittest
from s5a_composable_contract import (PlanningBudget, SecurityContractError,
                                      OPEN_OBLIGATIONS, build_assessment)


class S5AContractTests(unittest.TestCase):
    def setUp(self):
        self.b = PlanningBudget('0.0000000000001', '0.0000000000001',
                                '0.0000000000001', '0.000000000001')

    def assess(self, **kw):
        args = dict(n_key=128, k_test=8, max_transmissions=2000,
                    confirmation_tag_bits=40, budget=self.b)
        args.update(kw)
        return build_assessment(**args)

    def test_budget_sum_is_planning_not_security(self):
        r = self.assess()
        self.assertEqual(r['epsilon_ledger']['planning_sum'], '3E-13')
        self.assertTrue(r['epsilon_ledger']['planning_sum_within_target'])
        self.assertFalse(r['epsilon_ledger']['sum_is_proven_bound'])

    def test_outside_target_does_not_certify(self):
        r = self.assess(budget=replace(self.b, authentication='0.1'))
        self.assertFalse(r['epsilon_ledger']['planning_sum_within_target'])
        self.assertFalse(r['security_qualified'])

    def test_reject_noncanonical_or_bad_budget(self):
        for x in ('NaN', 'Infinity', '-0.1', '0', '1', '1e-9', '0.100', ' 0.1'):
            with self.subTest(x=x), self.assertRaises(SecurityContractError):
                PlanningBudget(x, '0.1', '0.1', '0.5')

    def test_quantum_obligations_cannot_be_promoted(self):
        r = self.assess(numerical_report={'decision': 'NUMERICAL_CANDIDATE',
                                          'maximum_numerical_key_bits': 256})
        self.assertEqual(r['proof_obligations_open'], list(OPEN_OBLIGATIONS))
        self.assertFalse(r['quantum_min_entropy_proven'])
        self.assertFalse(r['hpke_export_authorized'])

    def test_forged_positive_reports_rejected(self):
        for field in ('security_qualified', 'hpke_export_authorized',
                      'quantum_min_entropy_proven', 'protocol_assumptions_verified'):
            with self.subTest(field=field), self.assertRaises(SecurityContractError):
                self.assess(numerical_report={field: True})

    def test_confirmation_not_double_debited_in_syndrome_field(self):
        r = self.assess(n_key=257, k_test=8, max_transmissions=1000)
        self.assertEqual(r['ec_syndrome_disclosure_upper_bits'], 96)
        self.assertEqual(r['confirmation_tag_bits'], 40)
        self.assertEqual(r['s3d_outer_frame_resource_count'], 20)

    def test_invalid_profile_sizes_rejected(self):
        for kw in (dict(n_key=127), dict(n_key=True), dict(k_test=0),
                   dict(max_transmissions=130), dict(confirmation_tag_bits=257)):
            with self.subTest(kw=kw), self.assertRaises(SecurityContractError):
                self.assess(**kw)

    def test_abort_real_ideal_definitions_and_denials(self):
        r = self.assess()
        self.assertIn('ABORT', r['real_ideal_definition'])
        self.assertEqual(r['correctness_event'], 'ACCEPT_AND_KEY_MISMATCH')
        for f in ('security_qualified', 'security_model_validated',
                  'hpke_export_authorized', 'qkd_psk_available',
                  'production_handoff_permitted'):
            self.assertIs(r[f], False)


if __name__ == '__main__':
    unittest.main()
