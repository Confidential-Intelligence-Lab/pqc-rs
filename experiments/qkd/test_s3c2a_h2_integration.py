"""S3.C-2a: real H2 wire integration, regression and adversarial checks."""
import json
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from s3b_persistent_strict_path import run_strict_distillation, StrictSessionError
from s3c_authenticated_transcript import TranscriptError, TranscriptSession
from test_s2a3_distillation_integration import fixture


class ActualH2Integration(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.registry = Path(self.tmp.name) / 'private'
        self.registry.mkdir(mode=0o700)
        self.root = bytes(range(32))  # deliberately public test credential
        self.sid = b's3c2a-test-session-0001'

    def run_strict(self, sid=None, alice=None, bob=None, **kw):
        if alice is None or bob is None:
            alice, bob = fixture(256, 40)
        return run_strict_distillation(
            alice, bob, authentication_key=self.root, key_id='s3c-fixture',
            session_id=self.sid if sid is None else sid,
            registry_dir=self.registry, n_key=128, k_test=8,
            max_transmissions=1000, **kw)

    def test_real_h2_messages_traverse_unified_transport(self):
        out = self.run_strict()
        h2 = out['authenticated_parameter_estimation']
        self.assertEqual(h2['decision'], 'PARAMETER_ESTIMATION_PASS_UNQUALIFIED')
        self.assertTrue(h2['s3c_h2_authenticated'])
        self.assertTrue(h2['s3c_h2_digest_agreement'])
        self.assertFalse(out['security_qualified'])
        self.assertFalse(out['hpke_export_authorized'])
        self.assertNotIn(self.root.hex(), json.dumps(out))

    def test_s3c_transport_rejects_modified_public_message(self):
        real_receive = TranscriptSession.receive
        triggered = [False]
        def modified_receive(receiver, body, tag):
            if not triggered[0]:
                triggered[0] = True
                body = body + b' '
            return real_receive(receiver, body, tag)
        with patch.object(TranscriptSession, 'receive', modified_receive):
            with self.assertRaises(TranscriptError):
                self.run_strict()
        self.assertTrue(triggered[0])
        with self.assertRaises(StrictSessionError):
            self.run_strict()

    def test_wrong_transcript_key_rejects_real_h2(self):
        real_send = TranscriptSession.send
        triggered = [False]
        def wrong_stage(sender, stage, payload):
            if not triggered[0]:
                triggered[0] = True
                stage = 'h2_z_test_selection'
            return real_send(sender, stage, payload)
        with patch.object(TranscriptSession, 'send', wrong_stage):
            with self.assertRaises(TranscriptError):
                self.run_strict()
        self.assertTrue(triggered[0])

    def test_no_security_claim_from_h2_integration(self):
        out = self.run_strict()
        self.assertFalse(out.get('security_model_validated', False))
        self.assertFalse(out.get('qkd_psk_available', False))
        self.assertFalse(out.get('provisioning_origin_verified', False))
