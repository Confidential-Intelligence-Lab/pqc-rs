"""S4.C independent arithmetic and leakage-accounting checks; NOT a security proof."""
from __future__ import annotations
import math
import unittest
from decimal import Decimal, localcontext
from dataclasses import asdict
from m1g3_tomamichel_bound import BoundInput, evaluate as tlgr_evaluate
from m1e3_finite_key import FiniteKeyInput, evaluate as entropy_evaluate
from s2a2_syndrome_reconciliation import BLOCK_SIZE, SYNDROME_ROWS


def independent_equation_two(n, k, qtol, leak, esec, ecor, quality=1):
    """Decimal reconstruction independent of m1g3 implementation.

    This tests transcription/arithmetic only; it DOES NOT certify the theorem's
    applicability or independence/quality of simulated randomness.
    """
    with localcontext() as ctx:
        ctx.prec = 65
        D = lambda v: Decimal(str(v))
        n, k, p, leakage, es, ec, q = map(D, (n, k, qtol, leak, esec, ecor, quality))
        ln2 = D(2).ln()
        mu = (((n+k)/(n*k))*((k+1)/k)*(D(2)/es).ln()).sqrt()
        phase = p+mu
        if phase >= D('0.5'):
            return {'mu':float(mu), 'phase':float(phase), 'raw':None, 'max':0}
        h = -(phase*phase.ln()+(1-phase)*(1-phase).ln())/ln2
        cost = (D(2)/(es*es*ec)).ln()/ln2
        raw = n*(q-h)-leakage-cost
        maximum = max(0, min(int(n), math.floor(raw)))
        return {'mu':float(mu), 'phase':float(phase), 'raw':float(raw), 'max':maximum}


class FiniteKeyAndLeakageTests(unittest.TestCase):
    def test_equation_two_independent_decimal(self):
        for n,k,leak in [(4096,4096,1024),(16384,8192,4096),(65536,16384,16384)]:
            with self.subTest(n=n,k=k):
                p=BoundInput(n,k,.02,leak,1e-10,2**-40)
                actual=tlgr_evaluate(p)
                oracle=independent_equation_two(n,k,.02,leak,1e-10,2**-40)
                self.assertAlmostEqual(actual['mu'],oracle['mu'],places=12)
                self.assertAlmostEqual(actual['phase_error_upper'],oracle['phase'],places=12)
                if oracle['raw'] is not None:
                    self.assertAlmostEqual(actual['raw_bound_bits'],oracle['raw'],places=7)
                self.assertEqual(actual['maximum_numerical_key_bits'],oracle['max'])
                self.assertFalse(actual['security_qualified'])
                self.assertFalse(actual['hpke_export_authorized'])
                self.assertFalse(actual['protocol_assumptions_verified'])

    def test_oversized_phase_bound_yields_no_key(self):
        out=tlgr_evaluate(BoundInput(128,8,.05,32,1e-10,2**-40))
        self.assertEqual(out['maximum_numerical_key_bits'],0)
        self.assertEqual(out['reason'],'FINITE_SAMPLE_PHASE_BOUND_NOT_USEFUL')

    def test_syndrome_leakage_uses_ceiling_blocks(self):
        self.assertEqual(BLOCK_SIZE,128)
        self.assertEqual(SYNDROME_ROWS,32)
        for n in [128,129,255,256,257,4096,65536]:
            blocks=(n+BLOCK_SIZE-1)//BLOCK_SIZE
            self.assertEqual(blocks*SYNDROME_ROWS,32*math.ceil(n/128))
        self.assertEqual(32*math.ceil(129/128),64)

    def test_ledger_keeps_confirmation_separate(self):
        n,t=257,40
        syndrome=32*math.ceil(n/128)
        self.assertEqual(syndrome,96)
        self.assertEqual(syndrome+t,136)
        # This is the m1e3 convention, NOT TLGR Eq. (2)'s accounting.
        p=FiniteKeyInput(sifted_bits=300,test_bits=43,test_errors=0,
            reconciled_bits=n,reconciliation_leak_bits=syndrome,
            confirmation_leak_bits=t,requested_key_bits=32,epsilon_pa=1e-6,
            pre_leak_min_entropy_bits=None,entropy_evidence_id=None,
            authenticated_transcript=True,uniform_independent_toeplitz_seed=True,
            reconciliation_confirmed=True)
        r=entropy_evaluate(p)
        self.assertEqual(r.leakage_bits,syndrome+t)
        self.assertEqual(r.decision,'REJECT')
        self.assertFalse(r.hpke_export_authorized)

    def test_qber_is_not_entropy_evidence(self):
        for error_count in [0,1,10]:
            p=FiniteKeyInput(sifted_bits=400,test_bits=100,test_errors=error_count,
                reconciled_bits=256,reconciliation_leak_bits=64,
                confirmation_leak_bits=40,requested_key_bits=32,epsilon_pa=1e-6,
                authenticated_transcript=True,uniform_independent_toeplitz_seed=True,
                reconciliation_confirmed=True)
            r=entropy_evaluate(p)
            self.assertEqual(r.decision,'REJECT')
            self.assertEqual(r.reason,'NO_EXTERNALLY_JUSTIFIED_MIN_ENTROPY_BOUND')
            self.assertFalse(r.security_qualified)

    def test_hypothetical_entropy_never_authorizes(self):
        p=FiniteKeyInput(sifted_bits=10000,test_bits=1000,test_errors=0,
            reconciled_bits=8192,reconciliation_leak_bits=2048,
            confirmation_leak_bits=40,requested_key_bits=32,epsilon_pa=1e-6,
            pre_leak_min_entropy_bits=8192,entropy_evidence_id='ILLUSTRATIVE_ONLY',
            authenticated_transcript=True,uniform_independent_toeplitz_seed=True,
            reconciliation_confirmed=True)
        result=entropy_evaluate(p)
        self.assertEqual(result.decision,'CONDITIONAL_PASS')
        self.assertFalse(result.security_qualified)
        self.assertFalse(result.hpke_export_authorized)

    def test_correction_budget_not_equivalent_to_tag_count(self):
        # If epsilon_cor = 2^-40, the TLGR penalty contains log2(1/epsilon_cor).
        # The separately reported tag length is NOT another Eq. (2) deduction.
        es,ec=1e-10,2**-40
        penalty=math.log2(2/(es*es*ec))
        self.assertAlmostEqual(penalty,1+2*math.log2(1/es)+40,places=8)

    def test_no_security_claim_in_reference_reports(self):
        out=tlgr_evaluate(BoundInput(65536,16384,.01,16384,1e-10,2**-40))
        for name in ('security_model_validated','security_qualified','hpke_export_authorized'):
            self.assertIs(out[name],False)

if __name__=='__main__':
    unittest.main()
