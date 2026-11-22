"""H4.D full-Z authenticated parameter estimation and regression checks."""
import json
import hmac
import unittest
from m1g5c1_measurement_transcript import AliceRecord, BobRecord
from m1h2_authenticated_sampling import run_records, _canon, DOMAIN, TranscriptError
from m1g3_tomamichel_bound import BoundInput, evaluate


def trace(bits):
    return ([AliceRecord(v, 0 if i < len(bits)-1 else 1) for i,v in enumerate(bits)],
            [BobRecord(v, 0 if i < len(bits)-1 else 1) for i,v in enumerate(bits)])

class FullZTests(unittest.TestCase):
    def records(self, z=2, flipped=()):
        a=[AliceRecord(i%2, 0) for i in range(z)]+[AliceRecord(1, 1)]
        b=[BobRecord((i%2) ^ (i in flipped),0) for i in range(z)]+[BobRecord(1,1)]
        return a,b
    def run_case(self, z=2, flipped=(), hook=None):
        a,b=self.records(z,flipped)
        return run_records(a,b,n_key=1,k_test=1,max_transmissions=80,
                           selection_seed=21,authentication_key=b'Z'*32,
                           session_id=b'full-z-h4d-session-001',hook=hook)
    def test_zzx_witness_discloses_both_z(self):
        r=self.run_case()
        self.assertEqual(r['z_test_bits'],2)
        self.assertEqual(r['public_z_bits_disclosed'],4)
        self.assertEqual(r['eligible_z_count'],2)
        self.assertTrue(r['all_eligible_z_disclosed'])
    def test_observed_qber_uses_complete_z(self):
        r=self.run_case(flipped=(0,))
        self.assertEqual(r['z_test_errors'],1)
        self.assertEqual(r['observed_z_qber'],0.5)
        self.assertEqual(r['decision'],'ABORT_QBER')
    def test_bound_uses_actual_z_count(self):
        r=self.run_case(z=8)
        ref=evaluate(BoundInput(1,8,.05,0,1e-10,1e-10))
        self.assertEqual(r['numerical_bound']['maximum_numerical_key_bits'],ref['maximum_numerical_key_bits'])
        self.assertEqual(r['z_test_bits'],8)
    def test_zero_x_leakage_and_no_key_export(self):
        r=self.run_case(z=5)
        self.assertEqual(r['public_x_key_bits_disclosed'],0)
        self.assertFalse(r['security_model_validated'])
        self.assertFalse(r['hpke_export_authorized'])
        self.assertNotIn('key_hex',json.dumps(r))
    def test_recomputed_mac_cannot_omit_eligible_z(self):
        def hook(kind,data,tag):
            if kind == 'z_test_selection':
                obj=json.loads(data)
                obj['payload']['indices']=obj['payload']['indices'][:1]
                data=_canon(obj)
                tag=hmac.digest(b'Z'*32, DOMAIN + data,'sha256')
            return data,tag
        with self.assertRaises(TranscriptError):
            self.run_case(z=3,hook=hook)
    def test_full_z_indices_announced(self):
        seen=[]
        def hook(kind,data,tag):
            if kind=='z_test_selection':
                seen.extend(json.loads(data)['payload']['indices'])
            return data,tag
        r=self.run_case(z=4,hook=hook)
        self.assertEqual(seen,list(range(4)))
        self.assertEqual(r['public_discussion_messages'],9)
    def test_distinct_validated_pre_and_post_selection_sizes(self):
        r=self.run_case(z=6)
        self.assertEqual(r['x_key_bits'],1)
        self.assertEqual(r['z_test_bits'],6)
        self.assertEqual(r['public_z_bits_disclosed'],12)
    def test_validation_rejects_quota_failures(self):
        a,b=self.records(3)
        r=run_records(a,b,n_key=2,k_test=1,max_transmissions=80,selection_seed=21)
        self.assertEqual(r['decision'],'ABORT_QUOTAS')

if __name__=='__main__': unittest.main()
