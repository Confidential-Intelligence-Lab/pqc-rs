"""S5.D-5 bounded authenticated confirmation and root resource tests."""
import random
import tempfile
import unittest

from s3c_authenticated_transcript import TranscriptSession, TranscriptError
from s3d_authentication_contract import AssumedProvisionedCredential
from s5d3_bounded_cascade import BoundedProfile
from s5d5_peer_confirmation import (CascadeAuthenticationBudget, S5D5Error,
                                     run_single_use_confirmed_cascade)

ROOT = b'A'*32
SID = b's5d5-peer-test-session-01'
SEED = b'P'*32


class S5D5Tests(unittest.TestCase):
    def test_budget_rejects_unaccounted_messages(self):
        with self.assertRaises(S5D5Error):
            CascadeAuthenticationBudget(max_outer_frames=9605)
        with self.assertRaises(S5D5Error):
            CascadeAuthenticationBudget(max_pairs=4800,max_outer_frames=9608)

    def test_frozen_research_session_and_single_use(self):
        rng = random.Random(1234)
        alice=''.join(str(rng.randrange(2)) for _ in range(16384))
        bob=list(alice)
        for i in rng.sample(range(16384),300):
            bob[i] = str(1-int(bob[i]))
        cred=AssumedProvisionedCredential(root=ROOT,key_id='s5d5-unique-root')
        with tempfile.TemporaryDirectory() as tmp:
            out = run_single_use_confirmed_cascade(
                alice,''.join(bob),credential=cred,session_id=SID,
                registry_dir=tmp,permutation_seed=SEED)
            self.assertTrue(out['confirmation_authenticated_in_s3c'])
            self.assertEqual(out['authenticated_outer_frames'],2*out['parity_pairs']+7)
            self.assertEqual(out['max_outer_frames'],9607)
            self.assertGreaterEqual(out['numerical_candidate_key_bits'],256)
            self.assertFalse(out['security_qualified'])
            self.assertFalse(out['independent_distributed_role_execution'])
            self.assertNotIn('key',out)
            with self.assertRaises(Exception):
                run_single_use_confirmed_cascade(alice,''.join(bob),credential=cred,
                    session_id=SID,registry_dir=tmp,permutation_seed=SEED)

    def test_rejects_credential_profile_budget_mismatch(self):
        cred=AssumedProvisionedCredential(root=ROOT,key_id='s5d5-budget-root')
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(S5D5Error):
                run_single_use_confirmed_cascade('0'*16384,'0'*16384,
                    credential=cred,session_id=SID,registry_dir=tmp,
                    permutation_seed=SEED,profile=BoundedProfile(max_parity_pairs=4700))

    def test_s3c_confirmation_order_and_digest(self):
        opts=dict(root=ROOT,key_id='s5d5-schedule',session_id=SID,
                  alice_id='alice',bob_id='bob',schedule_id='s5d5-cascade-v1',
                  cascade_max_pairs=1,precommit_digest='a'*64)
        alice=TranscriptSession(role='alice',**opts)
        bob=TranscriptSession(role='bob',**opts)
        for sender,receiver,stage in (
            (alice,bob,'cascade_profile'),(bob,alice,'cascade_profile_ack'),
            (alice,bob,'cascade_alice_parity'),(bob,alice,'cascade_bob_parity'),
            (bob,alice,'cascade_confirmation_seed'),
            (alice,bob,'cascade_confirmation_tag'),
            (alice,bob,'cascade_finish'),(bob,alice,'cascade_finish_ack'),
            (alice,bob,'cascade_commit')):
            body,tag=sender.send(stage,b'{}')
            self.assertEqual(receiver.receive(body,tag),(stage,b'{}'))
        self.assertTrue(alice.status().closed and bob.status().closed)
        self.assertEqual(alice.status().transcript_digest,bob.status().transcript_digest)

    def test_s3c_rejects_unauthorized_finish_before_confirmation(self):
        opts=dict(root=ROOT,key_id='s5d5-schedule',session_id=SID,
                  alice_id='alice',bob_id='bob',schedule_id='s5d5-cascade-v1',
                  cascade_max_pairs=1,precommit_digest='a'*64)
        alice=TranscriptSession(role='alice',**opts)
        bob=TranscriptSession(role='bob',**opts)
        for sender,receiver,stage in (
            (alice,bob,'cascade_profile'),(bob,alice,'cascade_profile_ack'),
            (alice,bob,'cascade_alice_parity'),(bob,alice,'cascade_bob_parity')):
            body,tag=sender.send(stage,b'{}')
            receiver.receive(body,tag)
        with self.assertRaises(TranscriptError):
            alice.send('cascade_finish',b'{}')

    def test_tampered_confirmation_rejected(self):
        a='0'*16384
        cred=AssumedProvisionedCredential(root=ROOT,key_id='s5d5-tamper-root')
        def tamper(index,stage,body,tag):
            if stage=='cascade_confirmation_tag':
                return body,bytes([tag[0]^1])+tag[1:]
            return body,tag
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(TranscriptError):
                run_single_use_confirmed_cascade(a,a,credential=cred,session_id=SID,
                    registry_dir=tmp,permutation_seed=SEED,wire_hook=tamper)


if __name__=='__main__':
    unittest.main()
