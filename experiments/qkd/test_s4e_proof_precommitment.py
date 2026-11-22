"""S4.E test-only proof-profile ordering and authenticated transcript binding."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from s3b_persistent_strict_path import StrictSessionError, run_strict_distillation
from s3c_authenticated_transcript import TranscriptError, TranscriptSession
from s4e_proof_precommit import ProofProfile, run_precommitted_distillation
from test_s2a3_distillation_integration import fixture


class S4EPrecommitmentTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.registry = Path(tmp.name)/'sessions'
        self.registry.mkdir(mode=0o700)
        self.key = bytes(range(32))  # Insecure test credential, never deploy.
        self.sid = b's4e-fixture-session-00001'
        self.profile = ProofProfile(
            theorem_id='TLGR-2012-Phi',
            source_model_id='pqc-rs/qkd/s4a/ideal-bb84/v0.1',
            measurement_model_id='ideal-projective-lossless-v1',
            randomness_mode='os', n_key=128, k_test=8,
            max_transmissions=2000, z_probability_ppm=500000,
            q_tolerance_ppm=50000, requested_key_bits=32,
            confirmation_tag_bits=40, epsilon_pa='0.000001',
            epsilon_secrecy='0.0000000001',
            epsilon_correctness='0.0000000001')

    def run_once(self, callback=None, sid=None, profile=None, peer=None):
        if callback is None:
            callback = lambda p: fixture(128, 8)
        return run_precommitted_distillation(
            callback, proof_profile=profile or self.profile,
            bob_expected_profile=peer,
            authentication_key=self.key, key_id='s4e-fixture',
            session_id=sid or self.sid, registry_dir=self.registry)

    def test_precommit_before_acquisition_and_no_export(self):
        seen=[]
        orig=TranscriptSession.receive
        def receive(s,b,t):
            result=orig(s,b,t)
            if b'"stage":"proof_' in b:
                seen.append(result[0])
            return result
        def acquire(profile):
            self.assertEqual(seen,['proof_profile','proof_ack'])
            self.assertEqual(profile,self.profile)
            return fixture(128,8)
        with patch.object(TranscriptSession,'receive',receive):
            out=self.run_once(acquire)
        self.assertTrue(out['s4e_preacquisition_profile_authenticated'])
        self.assertTrue(out['s4e_acquisition_order_checked'])
        self.assertFalse(out['s4e_source_attested'])
        self.assertEqual(len(out['s4e_precommit_digest']),64)
        self.assertFalse(out['security_model_validated'])
        self.assertFalse(out['security_qualified'])
        self.assertFalse(out['hpke_export_authorized'])
        self.assertFalse(out['qkd_psk_available'])
        self.assertEqual(out['decision'],'REJECT_NO_VERIFIED_ENTROPY')

    def test_profile_fingerprint_changes_with_cap(self):
        other=replace(self.profile,max_transmissions=2001)
        self.assertNotEqual(other.fingerprint,self.profile.fingerprint)
        self.assertNotEqual(other.encode(),self.profile.encode())

    def test_profile_object_immutable(self):
        with self.assertRaises((AttributeError,TypeError)):
            self.profile.n_key=256

    def test_downgrade_and_fixture_rejected(self):
        for override in [dict(randomness_mode='fixture'),dict(theorem_id='UNKNOWN'),
                         dict(schedule_id='h2-ec-v1'),dict(confirmation_tag_bits=0)]:
            with self.assertRaises(StrictSessionError):
                replace(self.profile,**override)

    def test_peer_profile_disagreement_aborts_before_acquisition(self):
        called=[]
        with self.assertRaises(TranscriptError):
            self.run_once(lambda p: called.append(True),
                peer=replace(self.profile,max_transmissions=2001))
        self.assertFalse(called)
        with self.assertRaises(StrictSessionError):
            self.run_once()

    def test_precommit_tamper_blocks_acquisition_and_burns(self):
        called=[]
        orig=TranscriptSession.receive
        def change(s,b,t):
            if b'"stage":"proof_profile"' in b:
                b += b' '
            return orig(s,b,t)
        with patch.object(TranscriptSession,'receive',change):
            with self.assertRaises(TranscriptError):
                self.run_once(lambda p: called.append(True))
        self.assertFalse(called)
        with self.assertRaises(StrictSessionError):
            self.run_once()

    def test_ack_tamper_blocks_acquisition(self):
        called=[]
        orig=TranscriptSession.receive
        def change(s,b,t):
            if b'"stage":"proof_ack"' in b:
                b += b' '
            return orig(s,b,t)
        with patch.object(TranscriptSession,'receive',change):
            with self.assertRaises(TranscriptError):
                self.run_once(lambda p: called.append(True))
        self.assertFalse(called)

    def test_callback_failure_burns_session(self):
        def fail(p):
            raise RuntimeError('source unavailable')
        with self.assertRaises(RuntimeError):
            self.run_once(fail)
        with self.assertRaises(StrictSessionError):
            self.run_once()

    def test_post_stop_records_rejected(self):
        def extra(p):
            a,b=fixture(128,8)
            return a+[a[-1]],b+[b[-1]]
        with self.assertRaises(StrictSessionError):
            self.run_once(extra)

    def test_legacy_not_labeled_precommitted(self):
        a,b=fixture(128,8)
        r=run_strict_distillation(a,b,authentication_key=self.key,
            key_id='legacy-fixture',session_id=b's4e-legacy-session-0001',
            registry_dir=self.registry,n_key=128,k_test=8,max_transmissions=2000)
        self.assertNotIn('s4e_preacquisition_profile_authenticated',r)
        self.assertFalse(r['hpke_export_authorized'])

    def test_replay_after_completed_session(self):
        self.run_once()
        with self.assertRaises(StrictSessionError):
            self.run_once()


if __name__=='__main__':
    unittest.main()
