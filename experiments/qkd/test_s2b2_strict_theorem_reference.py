"""S2.B2 prefix and downstream evidence validation regression tests."""
from __future__ import annotations

import unittest
from dataclasses import dataclass
from unittest.mock import patch
from s2b2_strict_theorem_reference import (
    assess_prefix,run_strict_reference,ReferenceProtocolError)

@dataclass(frozen=True)
class Record:
    basis: int
    bit: int = 0

def batch(nx=128,nz=40):
    a=[Record(1,i&1) for i in range(nx)]+[Record(0,i&1) for i in range(nz)]
    return a,list(a)

class StrictReferenceTests(unittest.TestCase):
    def test_exact_prefix(self):
        a,b=batch()
        p=assess_prefix(a,b,n_key=128,k_test=40,max_transmissions=200)
        self.assertEqual(p.decision,'PREFIX_CONFORMS_UNQUALIFIED')
        self.assertEqual(p.first_quota_hit_index,167)
        self.assertFalse(p.quantum_sampling_theorem_verified)

    def test_extra_after_stop_rejected(self):
        a,b=batch()
        p=assess_prefix(a+[Record(0)],b+[Record(0)],n_key=128,k_test=40,max_transmissions=200)
        self.assertEqual(p.decision,'REJECT_POST_STOP_RECORDS')

    def test_overshoot_z_at_hitting_event_accepted(self):
        # At final record, the Z quota has already been exceeded while X hits.
        a=[Record(0)]*43+[Record(1)]*128
        p=assess_prefix(a,a,n_key=128,k_test=40,max_transmissions=200)
        self.assertEqual(p.decision,'PREFIX_CONFORMS_UNQUALIFIED')
        self.assertEqual(p.z_overshoot,3)

    def test_overshoot_x_at_hitting_event_accepted(self):
        a=[Record(1)]*132+[Record(0)]*40
        p=assess_prefix(a,a,n_key=128,k_test=40,max_transmissions=200)
        self.assertEqual(p.decision,'PREFIX_CONFORMS_UNQUALIFIED')
        self.assertEqual(p.x_overshoot,4)

    def test_quota_unmet(self):
        a,b=batch(nz=39)
        p=assess_prefix(a,b,n_key=128,k_test=40,max_transmissions=200)
        self.assertEqual(p.decision,'ABORT_QUOTAS_NOT_MET')

    def test_mismatched_basis_counts(self):
        a,b=batch()
        b[-1]=Record(1)
        p=assess_prefix(a,b,n_key=128,k_test=40,max_transmissions=200)
        self.assertEqual(p.decision,'ABORT_QUOTAS_NOT_MET')

    def test_cap_overflow(self):
        a,b=batch()
        with self.assertRaises(ReferenceProtocolError):
            assess_prefix(a,b,n_key=128,k_test=40,max_transmissions=167)

    def test_bad_parameter_types(self):
        a,b=batch()
        for bad in (True,128.0,'128'):
            with self.subTest(bad=bad),self.assertRaises(ReferenceProtocolError):
                assess_prefix(a,b,n_key=bad,k_test=40,max_transmissions=200)

    def test_invalid_basis_and_no_bit_inspection(self):
        a,b=batch()
        a[-1]=Record(2)
        with self.assertRaises(ReferenceProtocolError):
            assess_prefix(a,b,n_key=128,k_test=40,max_transmissions=200)

    def test_failed_prefix_never_calls_pipeline(self):
        a,b=batch()
        a.append(Record(0));b.append(Record(0))
        with patch('m2a_authenticated_distillation.run_distillation') as mock:
            r=run_strict_reference(a,b,n_key=128,k_test=40,max_transmissions=200)
            mock.assert_not_called()
        self.assertEqual(r['decision'],'REJECT_POST_STOP_RECORDS')

    def test_unsupported_short_key_no_pipeline(self):
        a,b=batch(nx=8,nz=4)
        with patch('m2a_authenticated_distillation.run_distillation') as mock:
            r=run_strict_reference(a,b,n_key=8,k_test=4,max_transmissions=20)
            mock.assert_not_called()
        self.assertEqual(r['decision'],'ABORT_UNSUPPORTED_RECONCILIATION_SIZE')

    def test_reference_pipeline_real(self):
        a,b=batch()
        r=run_strict_reference(a,b,n_key=128,k_test=40,max_transmissions=200)
        self.assertEqual(r['decision'],'PIPELINE_UNQUALIFIED_REJECT_NO_VERIFIED_ENTROPY')
        self.assertEqual(r['pipeline']['reconciliation']['syndrome_leak_bits'],32)
        self.assertEqual(r['pipeline']['reconciliation']['confirmation_leak_bits'],40)
        self.assertFalse(r['hpke_export_authorized'])

    def test_wrong_downstream_data_rejected(self):
        a,b=batch()
        bad={'decision':'REJECT_NO_VERIFIED_ENTROPY',
             'authenticated_parameter_estimation':{'decision':'PARAMETER_ESTIMATION_PASS_UNQUALIFIED',
              'transmissions':len(a),'x_key_bits':128,'z_test_bits':39,
              'eligible_z_count':40,'all_eligible_z_disclosed':True,
              'public_x_key_bits_disclosed':0,'theorem_specific_protocol_validated':False},
             'hpke_export_authorized':False,'qkd_psk_available':False,'finite_key':{'decision':'REJECT'}}
        with patch('m2a_authenticated_distillation.run_distillation',return_value=bad):
            with self.assertRaisesRegex(ReferenceProtocolError,'evidence inconsistent'):
                run_strict_reference(a,b,n_key=128,k_test=40,max_transmissions=200)

    def test_downstream_qualification_rejected(self):
        a,b=batch()
        bad={'decision':'OK','authenticated_parameter_estimation':{},
             'hpke_export_authorized':True,'qkd_psk_available':False,'finite_key':{'decision':'REJECT'}}
        with patch('m2a_authenticated_distillation.run_distillation',return_value=bad):
            with self.assertRaisesRegex(ReferenceProtocolError,'unauthorized'):
                run_strict_reference(a,b,n_key=128,k_test=40,max_transmissions=200)

if __name__=='__main__': unittest.main()
