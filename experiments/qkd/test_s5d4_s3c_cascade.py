"""S5.D-4 S3.C variable-length Cascade transcript conformance tests."""
import json
import random
import unittest
from s3c_authenticated_transcript import TranscriptSession, TranscriptError
from s5d4_s3c_cascade import run_s3c_cascade, IntegratedCascadeError
from s5d3_bounded_cascade import BoundedProfile


ROOT = b'R'*32
SID = b's5d4-test-session-00000001'
SEED = b'p'*32


class AdaptiveScheduleTests(unittest.TestCase):
    def pair(self, cap=2):
        opts = dict(root=ROOT,key_id='test-root',session_id=SID,
                    alice_id='alice',bob_id='bob',
                    schedule_id='s5d4-cascade-v1',cascade_max_pairs=cap,
                    precommit_digest='a'*64)
        return (TranscriptSession(role='alice',**opts),
                TranscriptSession(role='bob',**opts))

    def deliver(self, sender, receiver, stage):
        body, tag = sender.send(stage,b'{}')
        self.assertEqual(receiver.receive(body,tag),(stage,b'{}'))
        return body,tag

    def test_full_adaptive_schedule_and_equal_digests(self):
        a,b = self.pair()
        self.deliver(a,b,'cascade_profile')
        self.deliver(b,a,'cascade_profile_ack')
        self.deliver(a,b,'cascade_alice_parity')
        self.deliver(b,a,'cascade_bob_parity')
        self.deliver(a,b,'cascade_finish')
        self.deliver(b,a,'cascade_finish_ack')
        self.deliver(a,b,'cascade_commit')
        self.assertTrue(a.status().closed and b.status().closed)
        self.assertEqual(a.status().transcript_digest,b.status().transcript_digest)

    def test_finish_before_first_parity_pair_fails_closed(self):
        a,b = self.pair()
        self.deliver(a,b,'cascade_profile')
        self.deliver(b,a,'cascade_profile_ack')
        with self.assertRaises(TranscriptError):
            a.send('cascade_finish',b'{}')
        self.assertTrue(a.status().aborted)

    def test_wrong_role_stage_fails_closed(self):
        a,b = self.pair()
        with self.assertRaises(TranscriptError):
            b.send('cascade_profile',b'{}')
        self.assertTrue(b.status().aborted)

    def test_exceed_pair_cap_fails_closed(self):
        a,b = self.pair(cap=1)
        self.deliver(a,b,'cascade_profile')
        self.deliver(b,a,'cascade_profile_ack')
        self.deliver(a,b,'cascade_alice_parity')
        self.deliver(b,a,'cascade_bob_parity')
        with self.assertRaises(TranscriptError):
            a.send('cascade_alice_parity',b'{}')
        self.assertTrue(a.status().aborted)

    def test_replay_fails_closed(self):
        a,b = self.pair()
        body,tag=self.deliver(a,b,'cascade_profile')
        with self.assertRaises(TranscriptError):
            b.receive(body,tag)
        self.assertTrue(b.status().aborted)

    def test_invalid_or_unbound_adaptive_context_fails(self):
        with self.assertRaises(TranscriptError):
            TranscriptSession(root=ROOT,key_id='test-root',session_id=SID,
               alice_id='alice',bob_id='bob',role='alice',schedule_id='s5d4-cascade-v1',
               cascade_max_pairs=4801,precommit_digest='a'*64)
        a,b=self.pair()
        self.deliver(a,b,'cascade_profile')
        self.deliver(b,a,'cascade_profile_ack')
        with self.assertRaises(TranscriptError):
            a.send('cascade_bob_parity',b'{}')


class IntegratedResearchTests(unittest.TestCase):
    def inputs(self,n=16384,errors=0):
        rng=random.Random(811)
        a=''.join(str(rng.randrange(2)) for _ in range(n))
        b=list(a)
        for i in rng.sample(range(n),errors):
            b[i]='1' if b[i]=='0' else '0'
        return a,''.join(b)

    def test_full_frozen_profile_zero_errors(self):
        a,b=self.inputs()
        out=run_s3c_cascade(a,b,root=ROOT,session_id=SID,permutation_seed=SEED)
        self.assertEqual(out['authenticated_outer_frames'],2*out['parity_pairs']+5)
        self.assertEqual(out['max_outer_frames'],9605)
        self.assertEqual(out['public_parity_disclosure_ceiling_bits'],9600)
        self.assertTrue(out['independent_s3c_endpoint_states'])
        self.assertFalse(out['independent_distributed_role_execution'])
        self.assertFalse(out['confirmation_authenticated_in_s3c'])
        self.assertFalse(out['security_qualified'])
        self.assertFalse(out['hpke_export_authorized'])
        self.assertNotIn('corrected_key',out)
        self.assertNotIn('key',out)

    def test_full_profile_with_errors(self):
        a,b=self.inputs(errors=300)
        out=run_s3c_cascade(a,b,root=ROOT,session_id=SID,permutation_seed=SEED)
        self.assertGreater(out['parity_pairs'],0)
        self.assertLessEqual(out['parity_pairs'],4800)
        self.assertLessEqual(out['public_parity_disclosure_bits'],9600)

    def test_tamper_aborts(self):
        a,b=self.inputs()
        def tamper(index,stage,body,tag):
            if index==0:
                return body,bytes([tag[0]^1])+tag[1:]
            return body,tag
        with self.assertRaises(TranscriptError):
            run_s3c_cascade(a,b,root=ROOT,session_id=SID,permutation_seed=SEED,
                            wire_hook=tamper)

    def test_invalid_local_input(self):
        with self.assertRaises(IntegratedCascadeError):
            run_s3c_cascade('0'*128,'0'*128,root=ROOT,session_id=SID,
                            permutation_seed=SEED)


if __name__=='__main__':
    unittest.main()
