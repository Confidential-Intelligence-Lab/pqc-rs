"""S5.B standards mapping does not silently confer cryptographic assurance."""
from pathlib import Path
import tempfile
import unittest
from s5b_standards_disposition import (ResearchDisposition, REQUIRED_EVIDENCE,
                                      OPEN_PROOF_BLOCKERS, STANDARD_SET)

class StandardsAlignmentTests(unittest.TestCase):
    def test_complete_inventory_remains_review_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in REQUIRED_EVIDENCE:
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text('test-only placeholder')
            result = ResearchDisposition(root).assess()
            self.assertTrue(result['document_inventory_complete'])
            self.assertEqual(result['research_profile_alignment'], 'DOCUMENTED_MAPPING_REVIEW_REQUIRED')
            self.assertFalse(result['conditional_security_supported'])

    def test_missing_evidence_fails_mapping_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = ResearchDisposition(tmp).assess()
            self.assertFalse(result['document_inventory_complete'])
            self.assertEqual(len(result['missing_evidence_documents']), len(REQUIRED_EVIDENCE))

    def test_no_positive_crypto_security_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = ResearchDisposition(tmp).assess()
            for k in ('formal_standards_conformance_certified', 'gate_a_approved_by_this_report',
                      'conditional_security_supported','theorem_applicability_proven',
                      'security_model_validated','security_qualified','hpke_export_authorized',
                      'qkd_psk_available','production_handoff_permitted'):
                self.assertIs(r[k], False, k)

    def test_proof_blockers_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = ResearchDisposition(tmp).assess()
            self.assertIn('OBSERVED_K_SUBSTITUTION_UNJUSTIFIED', r['proof_obligations_open'])
            self.assertIn('COMPUTATIONAL_MULTI_MAC_ADVANTAGE_UNPROVED', r['proof_obligations_open'])
            self.assertEqual(len(r['proof_obligations_open']), len(OPEN_PROOF_BLOCKERS))

    def test_reference_versions_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = ResearchDisposition(tmp).assess()
            self.assertEqual(len(r['reference_set']), len(STANDARD_SET))
            self.assertIn('ETSI-GS-QKD-005-V1.1.1', r['reference_set'])
            self.assertIn('ETSI-GS-QKD-016-V2.1.1-FCS_QKD.1', r['reference_set'])

if __name__ == '__main__':
    unittest.main()
