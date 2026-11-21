import unittest
from m2b_handoff_probe import evidence, public_wire

class HandoffTests(unittest.TestCase):
    def test_m2a_rejects(self):
        r = evidence()
        self.assertEqual(r['decision'], 'REJECT_NO_VERIFIED_ENTROPY')
        self.assertFalse(r['qkd_psk_available'])
        self.assertFalse(r['hpke_export_authorized'])
    def test_public_wire_is_only_evidence(self):
        v = public_wire(evidence())
        f = v.split('\t')
        self.assertEqual(len(f), 8)
        self.assertEqual(f[0], 'M2A_EVIDENCE_V1')
        self.assertEqual(f[1], 'CUDA_Q_SIMULATION_NOT_SECURE_QKD')
        self.assertEqual(f[2:7], ['false']*5)
        self.assertNotIn('raw_key',v)
    def test_never_accept_demo_claims(self):
        r=evidence()
        r['hpke_export_authorized']=True
        self.assertIn('\ttrue\t',public_wire(r))
        self.assertEqual(r['provenance'], 'CUDA_Q_SIMULATION_NOT_SECURE_QKD')
if __name__=='__main__':unittest.main()
