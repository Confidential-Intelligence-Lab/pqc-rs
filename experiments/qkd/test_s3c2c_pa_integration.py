"""S3.C-2c: public PA seed and parameters bound to authenticated transcript.

All sessions are unqualified. No secret QKD material is exported.
"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from s3b_persistent_strict_path import run_strict_distillation, StrictSessionError
from s3c_authenticated_transcript import (
    TranscriptError, TranscriptSession, H2_PASS, PA_STAGES,
    distillation_schedule, full_distillation_schedule,
)
from test_s2a3_distillation_integration import fixture


class PrivacyAmplificationBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / 'private'
        self.directory.mkdir(mode=0o700)
        self.key = bytes(range(32))  # insecure test-only credential
        self.sid = b's3c2c-session-fixture-0001'

    def run_strict(self, *, n_key=128, session_id=None, **opts):
        alice, bob = fixture(512, 80)
        return run_strict_distillation(
            alice, bob, authentication_key=self.key, key_id='s3c2c-fixture',
            session_id=self.sid if session_id is None else session_id,
            registry_dir=self.directory, n_key=n_key, k_test=8,
            max_transmissions=2000, **opts)

    def test_proposal_and_final_transcript_no_export(self):
        r = self.run_strict()
        self.assertTrue(r['s3c_pa_parameters_authenticated'])
        self.assertTrue(r['s3c_pa_digest_agreement'])
        self.assertTrue(r['s3c_ec_authenticated'])
        self.assertEqual(r['decision'], 'REJECT_NO_VERIFIED_ENTROPY')
        self.assertEqual(r['privacy_amplification']['status'],
                         'AUTHENTICATED_PARAMETERS_NO_VERIFIED_ENTROPY')
        self.assertEqual(r['privacy_amplification']['toeplitz_seed_bits'], 159)
        self.assertFalse(r['privacy_amplification']['key_bytes_exported'])
        self.assertFalse(r['security_qualified'])
        self.assertFalse(r['hpke_export_authorized'])
        self.assertFalse(r['qkd_psk_available'])
        self.assertEqual(len(r['s3c_final_transcript_digest']), 64)
        self.assertNotIn(self.key.hex(), json.dumps(r))

    def test_multi_block_key_and_distinct_session(self):
        a = self.run_strict(n_key=256)
        b = self.run_strict(n_key=256, session_id=b's3c2c-session-fixture-0002')
        self.assertEqual(a['reconciliation']['authenticated_syndrome_messages'], 2)
        self.assertEqual(a['privacy_amplification']['toeplitz_seed_bits'], 287)
        self.assertNotEqual(a['s3c_final_transcript_digest'], b['s3c_final_transcript_digest'])
        self.assertFalse(a['hpke_export_authorized'])

    def test_replay_session_id_rejected_after_completion(self):
        self.run_strict()
        with self.assertRaises(StrictSessionError):
            self.run_strict()

    def test_schedule_is_exact_extension(self):
        self.assertEqual(full_distillation_schedule(2), distillation_schedule(2) + PA_STAGES)
        self.assertEqual(full_distillation_schedule(2)[:len(H2_PASS)], H2_PASS)
        self.assertEqual(full_distillation_schedule(2)[-3:], PA_STAGES)

    def test_bad_key_length_rejects_without_export(self):
        with self.assertRaises((TranscriptError, ValueError)):
            self.run_strict(requested_key_bits=129)
        with self.assertRaises(StrictSessionError):
            self.run_strict()  # still burned

    def _tamper(self, stage):
        original = TranscriptSession.receive
        hit = [False]
        def changed(receiver, body, tag):
            if not hit[0] and ('"stage":"' + stage + '"').encode() in body:
                hit[0] = True
                body += b' '
            return original(receiver, body, tag)
        with patch.object(TranscriptSession, 'receive', changed):
            with self.assertRaises(TranscriptError):
                self.run_strict()
        self.assertTrue(hit[0], stage)
        with self.assertRaises(StrictSessionError):
            self.run_strict()

    def test_parameter_tamper_fails_closed(self):
        self._tamper('pa_parameters')

    def test_acknowledgement_tamper_fails_closed(self):
        self._tamper('pa_ack')

    def test_commit_tamper_fails_closed(self):
        self._tamper('pa_commit')

    def test_wrong_profile_cannot_open_pa_schedule(self):
        with self.assertRaises(TranscriptError):
            TranscriptSession(root=self.key, key_id='fixture', session_id=self.sid,
                              role='alice', alice_id='alice', bob_id='bob',
                              schedule_id='h2-ec-pa-v1', reconciliation_blocks=0)


if __name__ == '__main__':
    unittest.main()
