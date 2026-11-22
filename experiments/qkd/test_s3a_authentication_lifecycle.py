"""Safety and functional tests for S3.A experimental authenticated sessions."""
import json
import unittest

from s3a_authentication_lifecycle import LifecycleError, ProvisionedKeyStore


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.sid = bytes(range(24))
        self.secret = bytes(range(32))
        self.a_store = ProvisionedKeyStore(self.secret, 'fixture-id')
        self.b_store = ProvisionedKeyStore(self.secret, 'fixture-id')
        self.a = self.a_store.open(self.sid, 'alice')
        self.b = self.b_store.open(self.sid, 'bob')

    def test_send_receive(self):
        frame, tag = self.a.send('sifting', b'public transcript')
        self.assertEqual(self.b.receive(frame, tag), ('sifting', b'public transcript'))

    def test_bidirectional(self):
        frame, tag = self.b.send('parameter_estimation', b'z-basis tally')
        self.assertEqual(self.a.receive(frame, tag)[1], b'z-basis tally')
        frame2, tag2 = self.a.send('confirmation', b'public tag')
        self.assertEqual(self.b.receive(frame2, tag2)[0], 'confirmation')

    def test_replay_rejected(self):
        frame, tag = self.a.send('sifting', b'a')
        self.b.receive(frame, tag)
        with self.assertRaises(LifecycleError):
            self.b.receive(frame, tag)

    def test_mac_tamper_rejected(self):
        frame, tag = self.a.send('sifting', b'a')
        with self.assertRaises(LifecycleError):
            self.b.receive(frame, bytes(32))
        self.assertEqual(self.b.receive(frame, tag)[1], b'a')

    def test_payload_tamper_rejected(self):
        frame, tag = self.a.send('sifting', b'a')
        bad = frame.replace(b'61', b'62')
        with self.assertRaises(LifecycleError):
            self.b.receive(bad, tag)

    def test_wrong_root_rejected(self):
        evil = ProvisionedKeyStore(b'x' * 32, 'fixture-id').open(self.sid, 'bob')
        frame, tag = self.a.send('sifting', b'a')
        with self.assertRaises(LifecycleError):
            evil.receive(frame, tag)

    def test_cross_session_rejected(self):
        other = self.b_store.open(bytes(reversed(self.sid)), 'bob')
        frame, tag = self.a.send('sifting', b'a')
        with self.assertRaises(LifecycleError):
            other.receive(frame, tag)

    def test_key_id_mismatch_rejected(self):
        other = ProvisionedKeyStore(self.secret, 'another-id').open(self.sid, 'bob')
        frame, tag = self.a.send('sifting', b'a')
        with self.assertRaises(LifecycleError):
            other.receive(frame, tag)

    def test_session_id_burned_on_open(self):
        with self.assertRaises(LifecycleError):
            self.a_store.open(self.sid, 'bob')
        self.a.close()
        with self.assertRaises(LifecycleError):
            self.a_store.open(self.sid, 'alice')

    def test_close_rejects_send_and_receive(self):
        frame, tag = self.a.send('sifting', b'a')
        self.a.close()
        with self.assertRaises(LifecycleError):
            self.a.send('sifting', b'a')
        self.b.close()
        with self.assertRaises(LifecycleError):
            self.b.receive(frame, tag)

    def test_stage_rollback_rejected(self):
        self.a.send('reconciliation', b'one')
        with self.assertRaises(LifecycleError):
            self.a.send('sifting', b'two')

    def test_export_stage_forbidden(self):
        with self.assertRaises(LifecycleError):
            self.a.send('hpke_handoff', b'pretend-authorized')

    def test_invalid_key(self):
        for key in (b'', b'x' * 31, 's' * 32, None):
            with self.subTest(key=key), self.assertRaises(LifecycleError):
                ProvisionedKeyStore(key, 'x')

    def test_invalid_session(self):
        with self.assertRaises(LifecycleError):
            self.a_store.open(b'x' * 15, 'bob')
        with self.assertRaises(LifecycleError):
            self.a_store.open(self.sid, 'neither')

    def test_invalid_payload(self):
        for payload in (b'x' * 65537, None, 'text'):
            with self.subTest(payload_type=type(payload)), self.assertRaises(LifecycleError):
                self.a.send('sifting', payload)

    def test_noncanonical_frame_rejected(self):
        frame, tag = self.a.send('sifting', b'a')
        with self.assertRaises(LifecycleError):
            self.b.receive(frame + b' ', tag)

    def test_report_is_unqualified_and_secret_free(self):
        report = self.a.report()
        self.assertFalse(report.provisioning_origin_verified)
        self.assertFalse(report.authentication_failure_bound_proven)
        self.assertFalse(report.hpke_export_authorized)
        self.assertNotIn(self.secret.hex(), json.dumps(report.__dict__))

    def test_destroy_blocks_reopen(self):
        self.a_store.destroy()
        with self.assertRaises(LifecycleError):
            self.a_store.open(b'z' * 24, 'alice')

    def test_stage_tag_substitution_rejected(self):
        frame, tag = self.a.send('sifting', b'a')
        altered = frame.replace(b'"sifting"', b'"confirmation"')
        with self.assertRaises(LifecycleError):
            self.b.receive(altered, tag)

    def test_different_session_keys(self):
        a2 = self.a_store.open(b'z' * 24, 'alice')
        f1, t1 = self.a.send('sifting', b'public')
        f2, t2 = a2.send('sifting', b'public')
        self.assertNotEqual(t1, t2)
        self.assertNotEqual(f1, f2)


if __name__ == '__main__':
    unittest.main()
