import unittest
from dataclasses import dataclass
from m2a_authenticated_distillation import run_distillation

@dataclass(frozen=True)
class Record:
    bit: int
    basis: int

def records(nx=12,nz=4, flip=None):
    a=[Record(i%2,1) for i in range(nx)] + [Record(i%2,0) for i in range(nz)]
    b=list(a)
    for j in flip or []:
        b[j]=Record(1-a[j].bit,a[j].basis)
    return a,b

class M2ATests(unittest.TestCase):
    def opts(self, a, b, **kwargs):
        return run_distillation(a,b,n_key=8,k_test=4,max_transmissions=100,
                                selection_seed=9,**kwargs)

    def test_authenticated_handoff_and_fail_closed(self):
        a,b=records()
        r=self.opts(a,b)
        self.assertEqual(r['reconciliation']['status'],'NOT_RUN')
        self.assertEqual(r['decision'],'ABORT_UNSUPPORTED_RECONCILIATION_SIZE')
        self.assertEqual(r['finite_key']['reason'],'PARAMETER_ESTIMATION_NOT_ACCEPTED')
        self.assertEqual(r['decision'],'ABORT_UNSUPPORTED_RECONCILIATION_SIZE')
        self.assertEqual(r['authenticated_parameter_estimation']['z_test_bits'],4)
        self.assertFalse(r['hpke_export_authorized'])
        self.assertFalse(r['qkd_psk_available'])
        self.assertEqual(r['privacy_amplification']['status'],'NOT_RUN')

    def test_overshoot_z_full(self):
        a,b=records(nx=12,nz=7)
        r=self.opts(a,b)
        self.assertEqual(r['authenticated_parameter_estimation']['z_test_bits'],7)
        self.assertEqual(r['reconciliation']['status'],'NOT_RUN')
        self.assertEqual(r['decision'],'ABORT_UNSUPPORTED_RECONCILIATION_SIZE')

    def test_qber_abort_prevents_reconciliation(self):
        a,b=records(flip=[12,13])
        r=self.opts(a,b)
        self.assertEqual(r['decision'],'ABORT_PARAMETER_ESTIMATION')
        self.assertEqual(r['reconciliation']['status'],'NOT_RUN')

    def test_transcript_tamper_rejected(self):
        a,b=records()
        def tamper(kind,data,tag):
            if kind=='x_key_selection':return data+b' ',tag
            return data,tag
        with self.assertRaises(Exception):self.opts(a,b,hook=tamper)

    def test_no_key_leak_in_json(self):
        import json
        a,b=records(nx=20)
        r=self.opts(a,b)
        blob=json.dumps(r)
        for k in ('"key"','"psk"','"seed"','raw_key','secret_bytes'):
            self.assertNotIn(k,blob)

    def test_wrong_configuration_rejected(self):
        a,b=records()
        with self.assertRaises(ValueError):self.opts(a,b,requested_key_bits=0)

    def test_quota_abort(self):
        a,b=records(nx=2)
        r=self.opts(a,b)
        self.assertEqual(r['decision'],'ABORT_PARAMETER_ESTIMATION')
        self.assertFalse(r['hpke_export_authorized'])

    def test_demo_only_not_authorized(self):
        a,b=records(nx=512,nz=16)
        r=run_distillation(a,b,n_key=512,k_test=16,max_transmissions=600,
             requested_key_bits=16,selection_seed=10,demo_pre_leak_min_entropy_bits=512)
        self.assertEqual(r['finite_key']['decision'],'CONDITIONAL_PASS')
        self.assertEqual(r['privacy_amplification']['status'],'HYPOTHETICAL_DEMO_ONLY')
        self.assertFalse(r['hpke_export_authorized'])
        self.assertFalse(r['qkd_psk_available'])

if __name__=='__main__': unittest.main()
