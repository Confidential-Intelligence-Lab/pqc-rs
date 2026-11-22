"""S4.D: illustrative proof-hygiene tests; NOT a QKD security proof."""
import math
import unittest
from types import SimpleNamespace

from s2b2_strict_theorem_reference import assess_prefix
from m1g3_tomamichel_bound import BoundInput, evaluate as numerical_bound
from m1e3_finite_key import FiniteKeyInput, evaluate as finite_key_evaluate


def total_variation_subnormalized(real, ideal):
    """Classical trace-distance analogue on one shared outcome space."""
    assert set(real) == set(ideal)
    return 0.5 * sum(abs(real[k] - ideal[k]) for k in real)


class S4DAcceptedBranchTests(unittest.TestCase):
    def test_public_filter_contracts_subnormalized_distance(self):
        real = {'a0': 0.36, 'a1': 0.04, 'b0': 0.15, 'b1': 0.45}
        ideal = {'a0': 0.20, 'a1': 0.20, 'b0': 0.30, 'b1': 0.30}
        d0 = total_variation_subnormalized(real, ideal)
        selected = ('a0', 'a1')
        # Add the same real/ideal abort event AFTER public acceptance filtering.
        filt_r = {k: real[k] if k in selected else 0.0 for k in real}
        filt_i = {k: ideal[k] if k in selected else 0.0 for k in ideal}
        self.assertLessEqual(total_variation_subnormalized(filt_r, filt_i), d0)

    def test_normalized_postselection_can_amplify_distance(self):
        # Accepted mass 0.1; conditional real {0:0.9,1:0.1}; ideal uniform.
        real = {'0': .09, '1': .01}
        ideal = {'0': .05, '1': .05}
        sub = total_variation_subnormalized(real, ideal)
        conditional = total_variation_subnormalized(
            {k: v / .1 for k, v in real.items()},
            {k: v / .1 for k, v in ideal.items()})
        self.assertAlmostEqual(sub, .04)
        self.assertAlmostEqual(conditional, .4)
        self.assertGreater(conditional, sub)

    def test_first_hit_with_cap_is_public_observable(self):
        x = SimpleNamespace(basis=1)
        z = SimpleNamespace(basis=0)
        a = (x, x, z, z)
        p = assess_prefix(a, a, n_key=2, k_test=2, max_transmissions=8)
        self.assertEqual(p.decision, 'PREFIX_CONFORMS_UNQUALIFIED')
        self.assertEqual(p.first_quota_hit_index, 3)
        self.assertFalse(p.quantum_sampling_theorem_verified)

    def test_cap_abort_is_not_a_key_acceptance(self):
        x = SimpleNamespace(basis=1)
        a = (x, x)
        p = assess_prefix(a, a, n_key=2, k_test=2, max_transmissions=4)
        self.assertEqual(p.decision, 'ABORT_QUOTAS_NOT_MET')
        self.assertFalse(p.hpke_export_authorized)

    def test_k_actual_can_exceed_minimum(self):
        x = SimpleNamespace(basis=1)
        z = SimpleNamespace(basis=0)
        a = (z, z, z, z, x, x)
        p = assess_prefix(a, a, n_key=2, k_test=2, max_transmissions=8)
        self.assertEqual(p.decision, 'PREFIX_CONFORMS_UNQUALIFIED')
        self.assertEqual(p.matched_z, 4)
        self.assertEqual(p.k_test_quota, 2)
        self.assertEqual(p.z_overshoot, 2)
        self.assertFalse(p.quantum_sampling_theorem_verified)

    def test_numerical_positive_never_qualifies(self):
        b = numerical_bound(BoundInput(
            n_key=100000, k_test=20000, q_tolerance=.01,
            leakage_ec_bits=1000, epsilon_secrecy=1e-10,
            epsilon_correctness=1e-12))
        self.assertGreater(b['maximum_numerical_key_bits'], 0)
        for field in ('security_model_validated', 'security_qualified', 'hpke_export_authorized'):
            self.assertIs(b[field], False)

    def test_unproved_entropy_still_rejected(self):
        f = finite_key_evaluate(FiniteKeyInput(
            sifted_bits=2048, test_bits=1024, test_errors=0,
            reconciled_bits=1024, reconciliation_leak_bits=256,
            confirmation_leak_bits=40, requested_key_bits=64,
            epsilon_pa=1e-6, pre_leak_min_entropy_bits=None,
            entropy_evidence_id=None, authenticated_transcript=True,
            uniform_independent_toeplitz_seed=True,
            reconciliation_confirmed=True))
        self.assertEqual(f.decision, 'REJECT')
        self.assertFalse(f.hpke_export_authorized)

    def test_monotonicity_of_published_mu_at_fixed_n(self):
        # Algebraic numerical sanity only; does NOT validate random-k substitution.
        def mu(n, k, eps):
            return math.sqrt(((n+k)/(n*k))*((k+1)/k)*math.log(2/eps))
        self.assertGreater(mu(10000, 100, 1e-10), mu(10000, 101, 1e-10))


if __name__ == '__main__':
    unittest.main()
