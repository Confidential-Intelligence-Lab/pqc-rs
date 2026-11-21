import unittest
from pathlib import Path
from m1h4e_postcorrection_audit import audit, stop, exhaustive, strict_reference_candidate, guard_sources
from m1g5c1_measurement_transcript import AliceRecord, BobRecord

ROOT=Path(__file__).resolve().parent

def ideal(bit, alice_basis, bob_basis):
    return bit if alice_basis==bob_basis else 0

class H4ETests(unittest.TestCase):
    def test_zzx_witness(self):
        r=stop('ZZX',1,1)
        self.assertEqual((r['stop'],r['matched_z'],r['z_excess']),(3,2,1))
    def test_xxz_witness(self):
        r=stop('XXZ',1,1)
        self.assertEqual((r['stop'],r['matched_x'],r['x_excess']),(3,2,1))
    def test_cap_abort(self):
        self.assertEqual(stop('ZZX',1,1,cap=2)['decision'],'ABORT_OR_INCOMPLETE')
    def test_bad_trace(self):
        with self.assertRaises(ValueError): stop('ZQX',1,1)
    def test_exhaustive(self):
        d=exhaustive()
        self.assertGreater(d['traces_with_z_overshoot'],0)
        self.assertGreater(d['traces_with_x_overshoot'],0)
    def test_source_guards(self):
        self.assertTrue(all(guard_sources(ROOT).values()))
    def test_strict_candidate_audit(self):
        d=audit(ROOT,n_key=8,k_test=8,oversample=1,cap=256)
        self.assertTrue(d['proof_obligations']['explicit_oversampling_eliminated'])
        self.assertFalse(d['box1_exact_protocol_equivalent'])
    def test_oversampled_audit(self):
        d=audit(ROOT,n_key=8,k_test=8,oversample=2,cap=256)
        self.assertEqual(d['mode'],'EXPERIMENTAL_OVERSAMPLING')
        self.assertFalse(d['proof_obligations']['explicit_oversampling_eliminated'])
    def test_invalid_audit(self):
        with self.assertRaises(ValueError): audit(ROOT,cap=1)
    def test_candidate_fixture(self):
        d=strict_reference_candidate(n_key=3,k_test=3,cap=128,
              randomness_mode='fixture',fixture_seed=123,measure=ideal)
        self.assertEqual(d['mode'],'STRICT_REFERENCE_CANDIDATE')
        self.assertEqual(d['decision'],'PARAMETER_ESTIMATION_PASS_UNQUALIFIED')
        self.assertFalse(d['hpke_export_authorized'])
    def test_candidate_os(self):
        d=strict_reference_candidate(n_key=2,k_test=2,cap=128,
              randomness_mode='os',fixture_seed=None,measure=ideal)
        self.assertEqual(d['mode'],'STRICT_REFERENCE_CANDIDATE')
        self.assertFalse(d['security_model_validated'])
    def test_no_export_even_aborted(self):
        d=strict_reference_candidate(n_key=3,k_test=3,cap=6,
              randomness_mode='fixture',fixture_seed=2,measure=ideal)
        self.assertEqual(d['decision'],'ABORT_QUOTAS')
        self.assertFalse(d['hpke_export_authorized'])

if __name__=='__main__': unittest.main()
