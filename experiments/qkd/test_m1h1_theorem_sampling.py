import unittest
from dataclasses import dataclass
from m1h1_theorem_sampling import select, diagnostic

@dataclass(frozen=True)
class R:
    bit: int
    basis: int

class H1Tests(unittest.TestCase):
    def setUp(self):
        self.a = [R(i % 2, i % 2) for i in range(60)]
        self.b = [R(i % 2, i % 2) for i in range(60)]

    def test_basis_orientation(self):
        s=select(self.a,self.b,n_key=10,k_test=10,seed=7)
        self.assertTrue(all(self.a[i].basis == 1 for i in s.x_key_positions))
        self.assertTrue(all(self.a[i].basis == 0 for i in s.z_test_positions))

    def test_without_replacement(self):
        s=select(self.a,self.b,n_key=25,k_test=25,seed=8)
        self.assertEqual(len(set(s.x_key_positions)),25)
        self.assertEqual(len(set(s.z_test_positions)),25)

    def test_determinism_fixture_only(self):
        self.assertEqual(select(self.a,self.b,n_key=10,k_test=10,seed=3),
                         select(self.a,self.b,n_key=10,k_test=10,seed=3))

    def test_fresh_randomness_marker(self):
        self.assertFalse(select(self.a,self.b,n_key=10,k_test=10).public_seed_used)

    def test_insufficient_quota_rejected(self):
        with self.assertRaises(ValueError):
            select(self.a,self.b,n_key=31,k_test=10,seed=1)

    def test_corrupt_records_rejected(self):
        b=list(self.b); b[0]=R(2,0)
        with self.assertRaises(ValueError):
            select(self.a,b,n_key=10,k_test=10,seed=1)

    def test_mismatched_records_rejected(self):
        with self.assertRaises(ValueError):
            select(self.a,self.b[:-1],n_key=10,k_test=10,seed=1)

    def test_errors_are_z_only(self):
        b=list(self.b); b[0]=R(1,0); b[1]=R(0,1)
        s=select(self.a,b,n_key=30,k_test=30,seed=1)
        self.assertEqual(s.z_test_errors,1)

    def test_no_security_claim(self):
        from m1g5c1_measurement_transcript import AliceRecord, BobRecord
        def ideal(bit, prep, basis): return bit if prep==basis else 0
        d=diagnostic(n_key=12,k_test=12,max_transmissions=300,seed=3,measure=ideal)
        self.assertEqual(d['decision'],'SAMPLE_SELECTED_UNQUALIFIED')
        self.assertFalse(d['security_model_validated'])
        self.assertFalse(d['hpke_export_authorized'])
        self.assertEqual(d['key_basis'],'X')
        self.assertEqual(d['test_basis'],'Z')

if __name__ == '__main__': unittest.main()
