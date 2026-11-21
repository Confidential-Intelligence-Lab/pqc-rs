import tempfile
import unittest
from pathlib import Path
from m1g5d_conformance_audit import FILES, REQUIREMENTS, SIGNALS, audit


class ConformanceAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for rel in FILES.values():
            (self.root / rel).write_text('# simulated incomplete source\n', encoding='utf-8')

    def test_missing_source_rejected(self):
        (self.root / FILES['quota']).unlink()
        with self.assertRaises(ValueError):
            audit(self.root)

    def test_nonexistent_dir_rejected(self):
        with self.assertRaises(ValueError):
            audit(self.root / 'absent')

    def test_all_gaps_exposed(self):
        r = audit(self.root)
        self.assertTrue({'QKD-05', 'QKD-06', 'QKD-07', 'QKD-08', 'QKD-09', 'QKD-10'}.issubset(r['blocking_requirements']))

    def test_never_qualifies_even_when_all_indicators_present(self):
        for _, (key, fragments) in SIGNALS.items():
            p = self.root / FILES[key]
            p.write_text(p.read_text() + '\n'.join(fragments) + '\n')
        r = audit(self.root)
        self.assertTrue(all(i['present'] for i in r['implementation_indicators'].values()))
        self.assertFalse(r['security_model_validated'])
        self.assertFalse(r['hpke_export_authorized'])

    def test_no_raw_secrets_in_report(self):
        r = audit(self.root)
        self.assertNotIn('secret_hex', str(r))
        self.assertNotIn('key_bytes', str(r))

    def test_requirements_unique(self):
        ids = [x[0] for x in REQUIREMENTS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_indicators_not_security_evidence(self):
        r = audit(self.root)
        self.assertTrue(all('not a proof' in i['meaning'] for i in r['implementation_indicators'].values()))

    def test_reference_pinned(self):
        r = audit(self.root)
        self.assertEqual(r['reference_doi'], '10.1038/ncomms1631')
        self.assertEqual(r['decision'], 'BLOCKED_SECURITY_MODEL_NOT_VALIDATED')


if __name__ == '__main__':
    unittest.main()
