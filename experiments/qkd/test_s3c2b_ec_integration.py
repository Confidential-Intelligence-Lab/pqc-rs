"""S3.C-2b: real S2.A2/S2.A1 authenticated transport integration tests."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from s3b_persistent_strict_path import run_strict_distillation, StrictSessionError
from s3c_authenticated_transcript import TranscriptError, TranscriptSession
from test_s2a3_distillation_integration import fixture


class ExtendedReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / 'private'
        self.directory.mkdir(mode=0o700)
        self.root = bytes(range(32))  # public/insecure test fixture
        self.sid = b's3c2b-session-test-id-0001'

    def run_strict(self, *, n_key=128, session_id=None):
        alice, bob = fixture(512, 80)
        return run_strict_distillation(
            alice, bob, authentication_key=self.root, key_id='s3c2b-fixture',
            session_id=self.sid if session_id is None else session_id,
            registry_dir=self.directory, n_key=n_key, k_test=8,
            max_transmissions=2000)

    def test_end_to_end_128(self):
        result = self.run_strict()
        self.assertTrue(result['s3c_ec_authenticated'])
        self.assertTrue(result['s3c_ec_digest_agreement'])
        self.assertEqual(result['reconciliation']['status'], 'PASS')
        self.assertEqual(len(result['s3c_final_transcript_digest']), 64)
        self.assertFalse(result['hpke_export_authorized'])
        self.assertFalse(result['security_qualified'])
        self.assertEqual(result['decision'], 'REJECT_NO_VERIFIED_ENTROPY')
        self.assertNotIn(self.root.hex(), json.dumps(result))

    def test_multiple_syndrome_blocks(self):
        result = self.run_strict(n_key=256)
        self.assertEqual(result['reconciliation']['authenticated_syndrome_messages'], 2)
        self.assertTrue(result['s3c_ec_digest_agreement'])
        self.assertFalse(result['hpke_export_authorized'])

    def _reject_mutated_stage(self, stage):
        original = TranscriptSession.receive
        hit = [False]
        def altered(receiver, frame, tag):
            if not hit[0] and ('"stage":"' + stage + '"').encode() in frame:
                hit[0] = True
                frame += b' '
            return original(receiver, frame, tag)
        with patch.object(TranscriptSession, 'receive', altered):
            with self.assertRaises(TranscriptError):
                self.run_strict()
        self.assertTrue(hit[0], f'expected stage {stage} did not execute')
        with self.assertRaises(StrictSessionError):
            self.run_strict()  # persistent session ID consumed even on failure

    def test_syndrome_tamper_aborts(self):
        self._reject_mutated_stage('ec_syndrome')

    def test_confirmation_tamper_aborts(self):
        self._reject_mutated_stage('ec_confirmation')

    def test_ack_tamper_aborts(self):
        self._reject_mutated_stage('ec_ack')

    def test_commit_tamper_aborts(self):
        self._reject_mutated_stage('ec_commit')

    def test_wrong_ec_schedule_fails_closed(self):
        with self.assertRaises(TranscriptError):
            TranscriptSession(root=self.root, key_id='fixture', session_id=self.sid,
                              role='alice', alice_id='alice', bob_id='bob',
                              schedule_id='h2-ec-v1', reconciliation_blocks=0)

    def test_wrong_ec_schedule_parameters_fail(self):
        with self.assertRaises(TranscriptError):
            TranscriptSession(root=self.root, key_id='fixture', session_id=self.sid,
                              role='alice', alice_id='alice', bob_id='bob',
                              schedule_id='h2-ec-v1', reconciliation_blocks=513)

    def test_stage_prefix_binding(self):
        from s3c_authenticated_transcript import H2_PASS, distillation_schedule
        schedule = distillation_schedule(2)
        self.assertEqual(schedule[:len(H2_PASS)], H2_PASS)
        self.assertEqual(schedule[-5:], (
            ('ec_syndrome', 'alice'), ('ec_syndrome', 'alice'),
            ('ec_confirmation', 'alice'), ('ec_ack', 'bob'), ('ec_commit', 'alice')))


if __name__ == '__main__':
    unittest.main()
