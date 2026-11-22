"""S3.C-1 conformance and negative tests; CPU-only, no CUDA-Q installation."""
import json
import unittest

from s3c_authenticated_transcript import (
    TranscriptSession, TranscriptError, SCHEDULE, canonical
)

ROOT = bytes(range(32))  # TEST FIXTURE ONLY: public and insecure
SID = bytes(range(16))


def pair(**changes):
    params = dict(root=ROOT, key_id='fixture', session_id=SID,
                  alice_id='alice-unit', bob_id='bob-unit')
    params.update(changes)
    return (TranscriptSession(role='alice', **params),
            TranscriptSession(role='bob', **params))


class TranscriptTests(unittest.TestCase):
    def test_full_trace_and_identical_digest(self):
        a, b = pair()
        for stage, sender in SCHEDULE:
            x, y = (a, b) if sender == 'alice' else (b, a)
            body, tag = x.send(stage, b'PUBLIC/' + stage.encode())
            self.assertEqual(y.receive(body, tag), (stage, b'PUBLIC/' + stage.encode()))
        self.assertTrue(a.status().closed and b.status().closed)
        self.assertEqual(a.status().transcript_digest, b.status().transcript_digest)
        self.assertFalse(a.status().hpke_export_authorized)
        self.assertFalse(b.status().security_qualified)
        with self.assertRaises(TranscriptError):
            a.send('close', b'late')

    def test_replay_aborts(self):
        a, b = pair()
        frame, tag = a.send('parameters', b'public')
        b.receive(frame, tag)
        with self.assertRaises(TranscriptError):
            b.receive(frame, tag)
        self.assertTrue(b.status().aborted)

    def test_skipping_stage_aborts(self):
        a, _ = pair()
        with self.assertRaises(TranscriptError):
            a.send('sifting', b'skipped')
        self.assertTrue(a.status().aborted)

    def test_wrong_turn_aborts(self):
        _, b = pair()
        with self.assertRaises(TranscriptError):
            b.send('parameters', b'before alice')

    def test_wrong_root_aborts(self):
        a, _ = pair()
        _, wrong = pair(root=b'x' * 32)
        frame, tag = a.send('parameters', b'data')
        with self.assertRaises(TranscriptError):
            wrong.receive(frame, tag)

    def test_cross_session_splice_aborts(self):
        a, _ = pair()
        _, wrong = pair(session_id=b'z' * 16)
        frame, tag = a.send('parameters', b'data')
        with self.assertRaises(TranscriptError):
            wrong.receive(frame, tag)

    def test_wrong_peer_identity_aborts(self):
        a, _ = pair()
        _, wrong = pair(bob_id='other-bob')
        frame, tag = a.send('parameters', b'data')
        with self.assertRaises(TranscriptError):
            wrong.receive(frame, tag)

    def test_key_id_substitution_aborts(self):
        a, _ = pair()
        _, wrong = pair(key_id='different')
        frame, tag = a.send('parameters', b'data')
        with self.assertRaises(TranscriptError):
            wrong.receive(frame, tag)

    def test_tamper_and_noncanonical_abort(self):
        a, b = pair()
        frame, tag = a.send('parameters', b'good')
        changed = canonical(dict(json.loads(frame), payload_hex=b'bad'.hex()))
        with self.assertRaises(TranscriptError):
            b.receive(changed, tag)
        self.assertTrue(b.status().aborted)
        _, b2 = pair()
        with self.assertRaises(TranscriptError):
            b2.receive(frame + b' ', tag)

    def test_drop_then_reorder_aborts(self):
        a, b = pair()
        first, tag = a.send('parameters', b'first')
        # Sender has advanced; receiver cannot accept a later stage without first.
        with self.assertRaises(TranscriptError):
            b.send('parameters', b'wrong turn')
        self.assertTrue(b.status().aborted)
        self.assertFalse(a.status().closed)

    def test_reflection_aborts(self):
        a, _ = pair()
        frame, tag = a.send('parameters', b'public')
        with self.assertRaises(TranscriptError):
            a.receive(frame, tag)

    def test_public_status_no_secrets(self):
        a, _ = pair()
        report = json.dumps(a.status().__dict__)
        self.assertNotIn(ROOT.hex(), report)
        self.assertFalse(a.status().security_model_validated)
        self.assertFalse(a.status().security_qualified)

    def test_bad_context_rejected(self):
        with self.assertRaises(TranscriptError):
            pair(root=b'x' * 31)
        with self.assertRaises(TranscriptError):
            pair(session_id=b'x' * 15)
        with self.assertRaises(TranscriptError):
            pair(alice_id='same', bob_id='same')

    def test_abort_is_terminal(self):
        a, _ = pair()
        a.abort()
        with self.assertRaises(TranscriptError):
            a.send('parameters', b'data')


if __name__ == '__main__':
    unittest.main()
