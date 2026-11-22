import random
import unittest

from s5d2_cascade_reconciliation import reconcile_cascade, CascadeError, public_report


class CascadeResearchTests(unittest.TestCase):
    def setUp(self):
        self.sid = b'session-s5d2-test-000000'
        self.auth = b'k'*32
        self.seed = b'p'*32

    def run_pair(self, a, b, **overrides):
        kw = dict(session_id=self.sid, authentication_key=self.auth,
                  permutation_seed=self.seed)
        kw.update(overrides)
        return reconcile_cascade(a, b, **kw)

    def test_clean(self):
        a='0'*1024
        fixed, report=self.run_pair(a,a)
        self.assertEqual(fixed,a)
        self.assertEqual(report.corrections,0)

    def test_iid_2pct_4k(self):
        r = random.Random(144)
        a=''.join(str(r.randrange(2)) for _ in range(4096))
        b=''.join(str(int(x) ^ (r.random() < .02)) for x in a)
        fixed, report=self.run_pair(a,b)
        self.assertEqual(fixed,a)
        self.assertGreater(report.corrections,0)

    def test_fail_closed_on_public_limit(self):
        with self.assertRaises(CascadeError):
            self.run_pair('0'*1024,'0'*1024,max_parity_pairs=1)

    def test_tamper_rejected(self):
        def hook(seq, payload, tag):
            return payload+b' ',tag
        with self.assertRaises(CascadeError):
            self.run_pair('0'*1024,'0'*1024,wire_hook=hook)

    def test_tag_tamper_rejected(self):
        def hook(seq, payload, tag):
            return payload, bytes(32)
        with self.assertRaises(CascadeError):
            self.run_pair('0'*1024,'0'*1024,wire_hook=hook)

    def test_no_security_promotion(self):
        a='0'*1024
        _, report=self.run_pair(a,a)
        v=public_report(report)
        for k in ('security_qualified','security_model_validated','hpke_export_authorized','qkd_psk_available'):
            self.assertFalse(v[k])
        self.assertEqual(v['reconciliation_disclosure_upper_bits'],2*v['public_parity_pairs']+64)

    def test_invalid_input(self):
        with self.assertRaises(CascadeError):
            self.run_pair('0'*1024,'2'*1024)

if __name__=='__main__':
    unittest.main()

# Long-profile regression is appended as a separate TestCase for discover.
class FrozenProfileResearchTests(unittest.TestCase):
    def test_16k_iid_2pct_reconciles_without_security_promotion(self):
        r=random.Random(401)
        a=''.join(str(r.randrange(2)) for _ in range(16384))
        b=''.join(str(int(x) ^ (r.random() < .02)) for x in a)
        fixed, report=reconcile_cascade(a,b,session_id=b's5d2-profile-16k',
                         authentication_key=b'k'*32, permutation_seed=b'p'*32)
        self.assertEqual(fixed,a)
        # Existing TLGR candidate uses 4,096 EC bits; at most 9,801 EC
        # bits keeps candidate >=256, but DOES NOT qualify that result.
        self.assertLessEqual(report.parity_disclosure_upper_bits,9801)
        self.assertFalse(report.security_qualified)
