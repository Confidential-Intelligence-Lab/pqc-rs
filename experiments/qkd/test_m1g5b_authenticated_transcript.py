import copy
import json
import unittest
from m1g5b_authenticated_transcript import PublicDiscussion, TranscriptError, synthetic_demo

KEY = b"K" * 32
SID = b"unique-16-byte-id-001"


def peers(key=KEY, sid=SID):
    return PublicDiscussion(key, sid, 'alice'), PublicDiscussion(key, sid, 'bob')


class TranscriptTests(unittest.TestCase):
    def test_full_protocol_and_chain_agreement(self):
        r = synthetic_demo()
        self.assertTrue(r['authenticated_synthetic_transcript'])
        self.assertFalse(r['actual_cudaq_sifting_authenticated'])
        self.assertFalse(r['hpke_export_authorized'])

    def test_tamper_rejected(self):
        a, b = peers()
        data, tag = a.send('alice_bases', {'bases': [0, 1]})
        with self.assertRaises(TranscriptError):
            b.receive(data.replace(b'[0,1]', b'[1,1]'), tag)

    def test_wrong_key_and_session(self):
        a, _ = peers()
        data, tag = a.send('alice_bases', {'bases': [0, 1]})
        for receiver in (PublicDiscussion(b'Z'*32, SID, 'bob'),
                         PublicDiscussion(KEY, b'unique-16-byte-id-002', 'bob')):
            with self.assertRaises(TranscriptError):
                receiver.receive(data, tag)

    def test_replay_rejected(self):
        a, b = peers()
        data, tag = a.send('alice_bases', {'bases': [0, 1]})
        b.receive(data, tag)
        with self.assertRaises(TranscriptError):
            b.receive(data, tag)

    def test_out_of_order_and_wrong_sender(self):
        a, b = peers()
        with self.assertRaises(TranscriptError):
            a.send('quota_status', {'decision': 'QUOTAS_MET', 'z_accepted': 1, 'x_accepted': 1, 'transmissions': 2})
        with self.assertRaises(TranscriptError):
            b.send('alice_bases', {'bases': [0, 1]})

    def test_omitted_frame_and_chain_mismatch(self):
        a, b = peers()
        frame1, tag1 = a.send('alice_bases', {'bases': [0, 1]})
        b.receive(frame1, tag1)
        # Forged skip-forward frame signed under the shared key: fails sequence/chain checks.
        raw = json.loads(frame1)
        raw['seq'] = 2
        altered = json.dumps(raw, sort_keys=True, separators=(',', ':')).encode()
        import hmac
        from m1g5b_authenticated_transcript import DOMAIN
        with self.assertRaises(TranscriptError):
            b.receive(altered, hmac.digest(KEY, DOMAIN + altered, 'sha256'))

    def test_abort_propagation(self):
        a, b = peers()
        data, tag = a.send('abort', {'reason': 'TRANSMISSION_LIMIT'})
        b.receive(data, tag)
        self.assertTrue(a.aborted and b.aborted)
        with self.assertRaises(TranscriptError):
            a.send('alice_bases', {'bases': [0, 1]})

    def test_malformed_and_duplicate_indices(self):
        a, b = peers()
        for sender, receiver, kind, payload in [
            (a, b, 'alice_bases', {'bases': [0, 1, 0, 1]}),
            (b, a, 'bob_bases', {'bases': [0, 1, 0, 1]}),
            (a, b, 'quota_status', {'decision': 'QUOTAS_MET', 'z_accepted': 2, 'x_accepted': 2, 'transmissions': 4}),
        ]:
            data, tag = sender.send(kind, payload)
            receiver.receive(data, tag)
        with self.assertRaises(TranscriptError):
            a.send('sample_selection', {'indices': [0, 0], 'population_size': 2})
        with self.assertRaises(TranscriptError):
            a.send('sample_selection', {'indices': [0], 'population_size': 999})

    def test_invalid_baselines(self):
        for key, sid, role in ((b'k', SID, 'alice'), (KEY, b'x', 'alice'), (KEY, SID, 'eve')):
            with self.assertRaises(ValueError):
                PublicDiscussion(key, sid, role)

    def test_no_secret_material_and_no_claims(self):
        text = json.dumps(synthetic_demo())
        self.assertNotIn(KEY.hex(), text)
        self.assertIn('"security_model_validated": false', text)


if __name__ == '__main__':
    unittest.main()
