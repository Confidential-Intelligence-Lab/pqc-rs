"""S2.A3 fail-closed distillation integration regression tests."""
import json
import unittest
from dataclasses import dataclass
from unittest.mock import patch

from m2a_authenticated_distillation import run_distillation
from s2a2_syndrome_reconciliation import SyndromeError

@dataclass(frozen=True)
class Record:
    bit: int
    basis: int

def fixture(nx=256, nz=40, flips=()):
    alice = [Record((i*7 + i//5) & 1, 1) for i in range(nx)]
    alice += [Record(i & 1, 0) for i in range(nz)]
    bob = list(alice)
    for i in flips:
        bob[i] = Record(1-alice[i].bit, alice[i].basis)
    return alice,bob

class S2A3Tests(unittest.TestCase):
    def run_key(self, n=128, nx=256, nz=40, **kwargs):
        a,b = fixture(nx,nz)
        return run_distillation(a,b,n_key=n,k_test=8,max_transmissions=1000,
                                selection_seed=19,**kwargs)

    def test_authentication_and_new_correctness_evidence(self):
        r=self.run_key()
        self.assertEqual(r['reconciliation']['status'],'PASS')
        self.assertEqual(r['reconciliation']['mechanism'],'S2A2_AUTHENTICATED_SYNDROME')
        self.assertEqual(r['reconciliation']['syndrome_leak_bits'],32)
        self.assertEqual(r['reconciliation']['confirmation_leak_bits'],40)
        self.assertEqual(r['correctness_bound'],'2^-40')
        self.assertEqual(r['finite_key']['leakage_bits'],72)
        self.assertEqual(r['finite_key']['reason'],'NO_EXTERNALLY_JUSTIFIED_MIN_ENTROPY_BOUND')
        self.assertFalse(r['hpke_export_authorized'])
        self.assertFalse(r['qkd_psk_available'])

    def test_multiple_blocks(self):
        r=self.run_key(n=256)
        self.assertEqual(r['reconciliation']['syndrome_leak_bits'],64)
        self.assertEqual(r['finite_key']['leakage_bits'],104)

    def test_short_keys_fail_closed_without_padding(self):
        r=self.run_key(n=16)
        self.assertEqual(r['decision'],'ABORT_UNSUPPORTED_RECONCILIATION_SIZE')
        self.assertEqual(r['reconciliation']['status'],'NOT_RUN')
        self.assertEqual(r['privacy_amplification']['status'],'NOT_RUN')

    def test_legacy_private_key_equality_not_used(self):
        import inspect
        import m2a_authenticated_distillation as module
        source=inspect.getsource(module.run_distillation)
        self.assertNotIn('corrected != alice_key',source)
        self.assertNotIn('reconcile_single_error_blocks',source)
        self.assertIn('reconcile_syndromes(',source)

    def test_syndrome_failure_aborts(self):
        with patch('m2a_authenticated_distillation.reconcile_syndromes', side_effect=SyndromeError('reject')):
            r=self.run_key()
        self.assertEqual(r['decision'],'ABORT_RECONCILIATION')
        self.assertFalse(r['hpke_export_authorized'])

    def test_missing_entropy_still_rejects(self):
        r=self.run_key(n=256)
        self.assertEqual(r['finite_key']['decision'],'REJECT')
        self.assertEqual(r['privacy_amplification']['status'],'NOT_RUN')
        self.assertFalse(r['security_model_validated'])

    def test_hypothetical_entropy_not_authorized(self):
        r=self.run_key(n=512,nx=600,nz=64,requested_key_bits=16,
                       demo_pre_leak_min_entropy_bits=512)
        self.assertEqual(r['finite_key']['decision'],'CONDITIONAL_PASS')
        self.assertEqual(r['privacy_amplification']['status'],'HYPOTHETICAL_DEMO_ONLY')
        self.assertFalse(r['qkd_psk_available'])
        self.assertFalse(r['hpke_export_authorized'])

    def test_z_qber_abort_prevents_syndrome(self):
        a,b=fixture(256,40,flips=[256,257,258])  # 3/40 = 7.5%, strictly above the 5% cutoff
        r=run_distillation(a,b,n_key=128,k_test=8,max_transmissions=1000,selection_seed=19)
        self.assertEqual(r['decision'],'ABORT_PARAMETER_ESTIMATION')
        self.assertEqual(r['reconciliation']['status'],'NOT_RUN')

    def test_public_only_json(self):
        r=self.run_key()
        wire=json.dumps(r)
        for marker in ('"raw_key"', '"psk"', '"secret_bytes"', '"authentication_key"', '"matrix_seed"'):
            self.assertNotIn(marker,wire)

    def test_invalid_confirmation_tag(self):
        a,b=fixture()
        with self.assertRaises(ValueError):
            run_distillation(a,b,n_key=128,k_test=8,max_transmissions=1000,
                             confirmation_tag_bits=0)

    def test_wrong_block_size(self):
        a,b=fixture()
        with self.assertRaises(ValueError):
            run_distillation(a,b,n_key=128,k_test=8,max_transmissions=1000,
                             block_size=32)

if __name__=='__main__':
    unittest.main()
