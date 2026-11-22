"""S3.D contract tests; CPU-only and no credential leaks."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from s3b_persistent_strict_path import StrictSessionError
from s3d_authentication_contract import (
    AssumedProvisionedCredential, AuthenticationBudget,
    planned_outer_frames, validate_auth_contract, run_s3d_profiled_simulation)
from s4e_proof_precommit import ProofProfile
from test_s2a3_distillation_integration import fixture


class S3DAuthContractTests(unittest.TestCase):
    def setUp(self):
        self.p = ProofProfile(
            theorem_id='TLGR-2012-Phi',
            source_model_id='pqc-rs/qkd/s4a/ideal-bb84/v0.1',
            measurement_model_id='ideal-projective-lossless-v1',
            randomness_mode='os', n_key=128, k_test=8,
            max_transmissions=2000, z_probability_ppm=500000,
            q_tolerance_ppm=50000, requested_key_bits=32,
            confirmation_tag_bits=40, epsilon_pa='0.000001',
            epsilon_secrecy='0.0000000001',
            epsilon_correctness='0.0000000001')
        self.credential = AssumedProvisionedCredential(bytes(range(32)), 's3d-test-root')
        self.budget = AuthenticationBudget(18)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.registry = Path(tmp.name) / 'registry'
        self.registry.mkdir(mode=0o700)

    def test_exact_normal_path_budget(self):
        self.assertEqual(planned_outer_frames(self.p), 18)
        self.assertEqual(validate_auth_contract(self.p, self.credential, self.budget), 18)
        self.assertEqual(planned_outer_frames(replace(self.p, n_key=256)), 19)

    def test_insufficient_budget_fails_before_lease(self):
        with self.assertRaises(StrictSessionError):
            validate_auth_contract(self.p, self.credential, AuthenticationBudget(17))
        with self.assertRaises(StrictSessionError):
            run_s3d_profiled_simulation(proof_profile=self.p,
                credential=self.credential, budget=AuthenticationBudget(17),
                session_id=b's3d-session-000001', registry_dir=self.registry)
        self.assertEqual(validate_auth_contract(self.p, self.credential, self.budget), 18)

    def test_root_too_short_and_bad_origin_rejected(self):
        with self.assertRaises(StrictSessionError):
            AssumedProvisionedCredential(b'x'*31, 'x')
        with self.assertRaises(StrictSessionError):
            AssumedProvisionedCredential(bytes(range(32)), 'x', origin_model='attested')

    def test_invalid_budget_or_multi_session_rejected(self):
        for kwargs in ({'max_outer_frames': True}, {'max_outer_frames': 17, 'max_root_sessions': 2},
                       {'max_outer_frames': 17, 'model_id': 'unknown'}):
            with self.assertRaises(StrictSessionError):
                AuthenticationBudget(**kwargs)

    def test_credential_repr_never_contains_secret(self):
        secret = b'SUPERSECRET' + b'0' * 32
        c = AssumedProvisionedCredential(secret, 'k')
        self.assertNotIn('SUPERSECRET', repr(c))
        self.assertIn('<redacted>', repr(c))

    def test_success_is_unqualified_and_root_burns(self):
        with patch('s4f_source_conformance.simulate_records', return_value=fixture(128,8)):
            out = run_s3d_profiled_simulation(
                proof_profile=self.p, credential=self.credential, budget=self.budget,
                session_id=b's3d-session-000001', registry_dir=self.registry)
        self.assertTrue(out['s3d_root_single_use_reserved'])
        self.assertFalse(out['s3d_credential_origin_verified'])
        self.assertFalse(out['s3d_cryptographic_authentication_bound_proven'])
        self.assertFalse(out['security_qualified'])
        self.assertFalse(out['hpke_export_authorized'])
        with self.assertRaises(StrictSessionError):
            run_s3d_profiled_simulation(
                proof_profile=self.p, credential=self.credential, budget=self.budget,
                session_id=b's3d-session-000002', registry_dir=self.registry)

    def test_acquisition_failure_still_burns_root(self):
        with patch('s4f_source_conformance.simulate_records', side_effect=RuntimeError('fail')):
            with self.assertRaises(RuntimeError):
                run_s3d_profiled_simulation(proof_profile=self.p,
                    credential=self.credential, budget=self.budget,
                    session_id=b's3d-session-000001', registry_dir=self.registry)
        with self.assertRaises(StrictSessionError):
            run_s3d_profiled_simulation(proof_profile=self.p,
                credential=self.credential, budget=self.budget,
                session_id=b's3d-session-000002', registry_dir=self.registry)

    def test_profile_mismatch_fails_before_acquisition_and_burns(self):
        with patch('s4f_source_conformance.simulate_records') as acquisition:
            with self.assertRaises(ValueError):
                run_s3d_profiled_simulation(proof_profile=self.p,
                    credential=self.credential, budget=self.budget,
                    bob_expected_profile=replace(self.p, max_transmissions=2001),
                    session_id=b's3d-session-000001', registry_dir=self.registry)
            acquisition.assert_not_called()
        with self.assertRaises(StrictSessionError):
            run_s3d_profiled_simulation(proof_profile=self.p,
                credential=self.credential, budget=self.budget,
                session_id=b's3d-session-000002', registry_dir=self.registry)


if __name__ == '__main__':
    unittest.main()
