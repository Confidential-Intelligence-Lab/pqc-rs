"""S5.D-3 fail-closed disclosure-profile and local relay conformance tests."""
import unittest
from unittest.mock import patch

from s5d3_bounded_cascade import (BoundedProfile, BoundedCascadeError,
                                  _AuthenticatedLocalRelay, run_local_bounded_reconciliation)


class S5D3Tests(unittest.TestCase):
    def test_frozen_profile_candidate(self):
        p = BoundedProfile()
        r = p.candidate()
        self.assertEqual(r['worst_case_parity_disclosure_bits'], 9600)
        self.assertGreaterEqual(r['candidate_key_bits'], 256)
        self.assertFalse(r['theorem_applicability_proven'])

    def test_tampered_profile_rejected(self):
        for kw in ({'n_key': 8192}, {'max_parity_pairs': 4801},
                   {'confirmation_tag_bits': 40}, {'q_tolerance_ppm': 50000}):
            with self.subTest(kw=kw), self.assertRaises(BoundedCascadeError):
                BoundedProfile(**kw)

    def test_relay_sequence_replay_rejected(self):
        q = _AuthenticatedLocalRelay(b's'*24,b'k'*32,BoundedProfile(max_parity_pairs=1))
        body, tag = b'a', b't'*32
        self.assertEqual(q.hook(0,body,tag),(body,tag))
        with self.assertRaises(BoundedCascadeError):
            q.hook(0,body,tag)
        with self.assertRaises(BoundedCascadeError):
            q.hook(1,body,tag)

    def test_profile_changes_transcript_binding(self):
        a = _AuthenticatedLocalRelay(b's'*24,b'k'*32,BoundedProfile())
        b = _AuthenticatedLocalRelay(b's'*24,b'k'*32,BoundedProfile(max_parity_pairs=4700))
        self.assertNotEqual(a.context,b.context)

    def test_reject_wrong_input_lengths_before_exchange(self):
        with self.assertRaises(BoundedCascadeError):
            run_local_bounded_reconciliation('0'*128,'0'*128,
                session_id=b's'*24,authentication_key=b'k'*32)

    def test_research_output_never_exports_key(self):
        a = '0'*16384
        r = run_local_bounded_reconciliation(a,a,session_id=b's'*24,
                authentication_key=b'k'*32,permutation_seed=b'p'*32)
        self.assertTrue(r['parity_pairs'] <= 4800)
        self.assertEqual(r['relay_authenticated_parity_frames'],r['parity_pairs'])
        self.assertFalse(r['security_qualified'])
        self.assertFalse(r['hpke_export_authorized'])
        self.assertFalse(r['s3c_transcript_schedule_integrated'])
        self.assertNotIn('key',r)
        self.assertNotIn('corrected',r)

    def test_precommitted_cap_abort(self):
        import random
        rng = random.Random(3)
        a = ''.join(str(rng.randrange(2)) for _ in range(16384))
        b = ''.join('1' if ch=='0' else '0' for ch in a)
        with self.assertRaises((BoundedCascadeError,ValueError)):
            run_local_bounded_reconciliation(a,b,session_id=b's'*24,
                authentication_key=b'k'*32,profile=BoundedProfile(max_parity_pairs=1),
                permutation_seed=b'p'*32)


if __name__ == '__main__':
    unittest.main()
