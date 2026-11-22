"""S3.B strict fail-closed session reservation and pipeline tests."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from s3b_persistent_strict_path import StrictSessionError, burn_session_id, run_strict_distillation
from test_s2a3_distillation_integration import fixture


class StrictPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / 'private'
        self.directory.mkdir(mode=0o700)
        self.key = bytes(range(32))
        self.sid = b's3b-unique-session-id-0001'

    def call(self, **kw):
        a,b = fixture(256,40)
        options = dict(authentication_key=self.key, key_id='fixture-key',
                       session_id=self.sid, registry_dir=self.directory,
                       n_key=128, k_test=8, max_transmissions=1000)
        options.update(kw)
        return run_strict_distillation(a,b,**options)

    def test_real_pipeline_fail_closed(self):
        r = self.call()
        self.assertEqual(r['reconciliation']['status'], 'PASS')
        self.assertEqual(r['decision'], 'REJECT_NO_VERIFIED_ENTROPY')
        self.assertTrue(r['strict_provisioned_authentication_path'])
        self.assertTrue(r['replay_tracking_persistent'])
        self.assertFalse(r['provisioning_origin_verified'])
        self.assertFalse(r['hpke_export_authorized'])
        self.assertNotIn(self.key.hex(), json.dumps(r))

    def test_restart_replay_rejected(self):
        self.call()
        with self.assertRaises(StrictSessionError):self.call()

    def test_distinct_sessions_accepted(self):
        self.call()
        self.assertEqual(self.call(session_id=b's3b-unique-session-id-0002')['decision'], 'REJECT_NO_VERIFIED_ENTROPY')

    def test_same_session_different_key_id(self):
        self.call()
        self.assertEqual(self.call(key_id='second-key')['decision'], 'REJECT_NO_VERIFIED_ENTROPY')

    def test_unsafe_permissions(self):
        os.chmod(self.directory,0o755)
        with self.assertRaises(StrictSessionError):self.call()

    def test_registry_symlink(self):
        path=self.directory.parent/'alias'
        path.symlink_to(self.directory)
        with self.assertRaises(StrictSessionError):self.call(registry_dir=path)

    def test_root_key_required(self):
        with self.assertRaises(StrictSessionError):self.call(authentication_key=None)
        self.assertEqual(list(self.directory.iterdir()),[])

    def test_fixture_controls_forbidden(self):
        for name,value in [('selection_seed',1), ('demo_pre_leak_min_entropy_bits',1000),
                           ('hook',lambda *x:x), ('selection_streams',{})]:
            with self.subTest(name=name),self.assertRaises(StrictSessionError):self.call(**{name:value})
        self.assertEqual(list(self.directory.iterdir()),[])

    def test_failed_pipeline_burns_session(self):
        with patch('s3b_persistent_strict_path.run_distillation', side_effect=ValueError('abort')):
            with self.assertRaises(ValueError):self.call()
        with self.assertRaises(StrictSessionError):self.call()

    def test_downstream_forged_qualification_rejected(self):
        with patch('s3b_persistent_strict_path.run_distillation', return_value={
            'hpke_export_authorized':True,'security_qualified':True
        }):
            with self.assertRaises(StrictSessionError):self.call()

    def test_bad_registry_path(self):
        with self.assertRaises(StrictSessionError):burn_session_id('relative', 'kid', self.sid)

    def test_invalid_session(self):
        with self.assertRaises(StrictSessionError):burn_session_id(self.directory, 'kid', b'short')

    def test_missing_private_directory(self):
        with self.assertRaises(StrictSessionError):burn_session_id(self.directory/'none', 'kid', self.sid)

    def test_existing_marker(self):
        burn_session_id(self.directory,'kid',self.sid)
        with self.assertRaises(StrictSessionError):burn_session_id(self.directory,'kid',self.sid)

    def test_direct_strict_credentials_required(self):
        from m2a_authenticated_distillation import run_distillation
        a,b=fixture(256,40)
        with self.assertRaises(ValueError):
            run_distillation(a,b,n_key=128,k_test=8,max_transmissions=1000,
                             strict_provisioned=True)
        with self.assertRaises(ValueError):
            run_distillation(a,b,n_key=128,k_test=8,max_transmissions=1000,
                             strict_provisioned=True,authentication_key=self.key,
                             session_id=self.sid,selection_seed=19)

    def test_direct_partial_credentials_rejected(self):
        from m2a_authenticated_distillation import run_distillation
        a,b=fixture(256,40)
        with self.assertRaises(ValueError):
            run_distillation(a,b,n_key=128,k_test=8,max_transmissions=1000,
                             authentication_key=self.key)

    def test_bad_key_id(self):
        with self.assertRaises(StrictSessionError):burn_session_id(self.directory,'../unsafe',self.sid)


if __name__ == '__main__':unittest.main()
