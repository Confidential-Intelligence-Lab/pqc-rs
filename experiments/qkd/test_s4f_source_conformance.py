"""S4.F structural circuit and profile-to-acquisition conformance, unqualified."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from s3b_persistent_strict_path import StrictSessionError
from s4e_proof_precommit import ProofProfile
from s4f_source_conformance import (audit_prepare_and_measure,
    ProfiledAcquisition, run_profiled_simulation)
from test_s2a3_distillation_integration import fixture


class S4FTests(unittest.TestCase):
    def setUp(self):
        self.profile = ProofProfile(
            theorem_id='TLGR-2012-Phi',
            source_model_id='pqc-rs/qkd/s4a/ideal-bb84/v0.1',
            measurement_model_id='ideal-projective-lossless-v1',
            randomness_mode='os', n_key=128, k_test=8,
            max_transmissions=2000, z_probability_ppm=370000,
            q_tolerance_ppm=50000, requested_key_bits=32,
            confirmation_tag_bits=40, epsilon_pa='0.000001',
            epsilon_secrecy='0.0000000001',
            epsilon_correctness='0.0000000001')

    def test_circuit_exact_structure(self):
        self.assertTrue(audit_prepare_and_measure()['circuit_structure_matches_ideal_model'])

    def test_circuit_mutation_fails_closed(self):
        source = Path(__file__).with_name('bb84_cudaq.py').read_text()
        self.assertIn('if measurement_basis == 1:', source)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'changed.py'
            path.write_text(source.replace('if measurement_basis == 1:',
                                           'if measurement_basis == 0:', 1))
            with self.assertRaises(StrictSessionError):
                audit_prepare_and_measure(path)

    def test_kernel_decorator_mutation_fails_closed(self):
        source = Path(__file__).with_name('bb84_cudaq.py').read_text()
        self.assertIn('@cudaq.kernel', source)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'changed.py'
            path.write_text(source.replace('@cudaq.kernel', '# @cudaq.kernel', 1))
            with self.assertRaises(StrictSessionError):
                audit_prepare_and_measure(path)

    def test_committed_acquisition_parameters(self):
        captured = {}
        def fake(**kwargs):
            captured.update(kwargs)
            return fixture(128, 8)
        with patch('s4f_source_conformance.simulate_records', side_effect=fake):
            ProfiledAcquisition()(self.profile)
        self.assertEqual(captured['n_z'], 8)
        self.assertEqual(captured['k_x'], 128)
        self.assertEqual(captured['max_transmissions'], 2000)
        self.assertEqual(captured['z_probability'], .37)
        self.assertEqual(captured['randomness'].mode, 'os')
        self.assertEqual(captured['intercept_percent'], 0)
        self.assertIsNone(captured['measure'])

    def test_probability_change_reaches_acquisition(self):
        calls = []
        with patch('s4f_source_conformance.simulate_records',
                   side_effect=lambda **kw: (calls.append(kw), fixture(128,8))[1]):
            ProfiledAcquisition()(replace(self.profile, z_probability_ppm=630000))
        self.assertEqual(calls[0]['z_probability'], .63)

    def test_not_fixture_randomness(self):
        with patch('s4f_source_conformance.RandomnessStreams') as constructor:
            instance = constructor.return_value
            instance.mode = 'fixture'
            with self.assertRaises(StrictSessionError):
                ProfiledAcquisition()(self.profile)

    def test_profiled_execution_denies_export(self):
        with tempfile.TemporaryDirectory() as root:
            registry = Path(root) / 'private'
            registry.mkdir(mode=0o700)
            with patch('s4f_source_conformance.simulate_records', return_value=fixture(128,8)):
                result = run_profiled_simulation(
                    proof_profile=self.profile,
                    authentication_key=bytes(range(32)),
                    key_id='s4f-fixture', session_id=b's4f-fixture-session-0001',
                    registry_dir=registry)
            self.assertTrue(result['s4f_source_adapter_enforced'])
            self.assertFalse(result['s4f_source_attested'])
            self.assertFalse(result['security_qualified'])
            self.assertFalse(result['hpke_export_authorized'])
            self.assertFalse(result['qkd_psk_available'])
            self.assertEqual(result['decision'], 'REJECT_NO_VERIFIED_ENTROPY')

    def test_secrecy_parameters_forwarded_to_h2(self):
        import inspect
        from m2a_authenticated_distillation import run_distillation
        from s4e_proof_precommit import run_precommitted_distillation
        s4e = inspect.getsource(run_precommitted_distillation)
        m2a = inspect.getsource(run_distillation)
        self.assertIn('epsilon_secrecy=float(proof_profile.epsilon_secrecy)', s4e)
        self.assertIn('epsilon_correctness=float(proof_profile.epsilon_correctness)', s4e)
        self.assertIn('epsilon_secrecy=epsilon_secrecy', m2a)
        self.assertIn('epsilon_correctness=epsilon_correctness', m2a)


if __name__ == '__main__':
    unittest.main()
