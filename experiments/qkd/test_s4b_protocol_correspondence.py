"""S4.B observational protocol conformance checks; NOT quantum-security proofs.

Run: python3 -m unittest discover -s experiments/qkd -p 'test_s4b_protocol_correspondence.py' -v
"""
from __future__ import annotations

from types import SimpleNamespace
import unittest

from s2b2_strict_theorem_reference import assess_prefix
from m1e3_finite_key import FiniteKeyInput, evaluate
from m1h3a_randomness import RandomnessStreams, RandomnessConfiguration, RandomnessError


def record(basis):
    return SimpleNamespace(basis=basis)


class S4BObservableCorrespondenceTests(unittest.TestCase):
    def test_exact_first_hit(self):
        a = [record(1)] * 128 + [record(0)] * 8
        r = assess_prefix(a, a, n_key=128, k_test=8, max_transmissions=200)
        self.assertEqual(r.decision, 'PREFIX_CONFORMS_UNQUALIFIED')
        self.assertEqual(r.first_quota_hit_index, 135)
        self.assertFalse(r.quantum_sampling_theorem_verified)

    def test_post_stop_observations_rejected(self):
        a = [record(1)] * 128 + [record(0)] * 9
        r = assess_prefix(a, a, n_key=128, k_test=8, max_transmissions=200)
        self.assertEqual(r.decision, 'REJECT_POST_STOP_RECORDS')

    def test_cap_abort(self):
        a = [record(1)] * 128 + [record(0)] * 7
        r = assess_prefix(a, a, n_key=128, k_test=8, max_transmissions=200)
        self.assertEqual(r.decision, 'ABORT_QUOTAS_NOT_MET')
        self.assertIsNone(r.first_quota_hit_index)

    def test_mismatched_bases_not_counted(self):
        a = [record(1)] * 128 + [record(0)] * 8
        b = [record(1)] * 127 + [record(0)] * 9
        r = assess_prefix(a, b, n_key=128, k_test=8, max_transmissions=200)
        self.assertEqual(r.decision, 'ABORT_QUOTAS_NOT_MET')

    def test_z_overshoot_recorded(self):
        a = [record(0)] * 10 + [record(1)] * 128
        r = assess_prefix(a, a, n_key=128, k_test=8, max_transmissions=200)
        self.assertEqual(r.decision, 'PREFIX_CONFORMS_UNQUALIFIED')
        self.assertEqual(r.z_overshoot, 2)
        self.assertEqual(r.matched_z, 10)

    def test_explicit_deterministic_mode(self):
        fixture = RandomnessStreams(RandomnessConfiguration('fixture', 123))
        self.assertEqual(fixture.mode, 'fixture')
        with self.assertRaises(RandomnessError):
            RandomnessStreams(RandomnessConfiguration('os', 123))

    def test_sampling_without_replacement(self):
        streams = RandomnessStreams(RandomnessConfiguration('fixture', 123))
        chosen = streams.sample_indices(150, 128)
        self.assertEqual(len(chosen), 128)
        self.assertEqual(len(set(chosen)), 128)
        self.assertTrue(all(0 <= i < 150 for i in chosen))

    def test_entropy_missing_means_reject(self):
        p = FiniteKeyInput(sifted_bits=136, test_bits=8, test_errors=0,
                           reconciled_bits=128, reconciliation_leak_bits=32,
                           confirmation_leak_bits=40, requested_key_bits=32,
                           epsilon_pa=1e-6, authenticated_transcript=True,
                           uniform_independent_toeplitz_seed=True,
                           reconciliation_confirmed=True)
        out = evaluate(p)
        self.assertEqual(out.decision, 'REJECT')
        self.assertEqual(out.reason, 'NO_EXTERNALLY_JUSTIFIED_MIN_ENTROPY_BOUND')
        self.assertFalse(out.security_qualified)
        self.assertFalse(out.hpke_export_authorized)

    def test_placeholder_entropy_id_is_not_proof(self):
        # Evaluator is a numeric calculator; it can return a length-only
        # conditional result for user-supplied numbers. Such a result MUST NOT
        # qualify keys or authorize HPKE export.
        p = FiniteKeyInput(sifted_bits=640, test_bits=128, test_errors=0,
                           reconciled_bits=512, reconciliation_leak_bits=128,
                           confirmation_leak_bits=40, requested_key_bits=32,
                           epsilon_pa=1e-6, pre_leak_min_entropy_bits=512,
                           entropy_evidence_id='TEST_ONLY_NOT_PROOF',
                           authenticated_transcript=True,
                           uniform_independent_toeplitz_seed=True,
                           reconciliation_confirmed=True)
        out = evaluate(p)
        self.assertEqual(out.decision, 'CONDITIONAL_PASS')
        self.assertFalse(out.security_qualified)
        self.assertFalse(out.hpke_export_authorized)


if __name__ == '__main__':
    unittest.main()
