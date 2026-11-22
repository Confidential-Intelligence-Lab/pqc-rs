import unittest

from m1g5c1_measurement_transcript import (
    AliceRecord, BobRecord, authenticate_sifting, experiment, simulate_records)
from m1g5b_authenticated_transcript import TranscriptError


def ideal(bit, prep, measurement):
    return bit if prep == measurement else 0


class C1Tests(unittest.TestCase):
    def test_real_measurement_records_and_authentication(self):
        a, b = simulate_records(n_z=30, k_x=20, max_transmissions=500,
                                seed=42, measure=ideal)
        self.assertTrue(all(isinstance(x, AliceRecord) for x in a))
        self.assertTrue(all(isinstance(x, BobRecord) for x in b))
        r = authenticate_sifting(a, b, n_z=30, k_x=20, max_transmissions=500,
                                  authentication_key=b'Q' * 32,
                                  session_id=b'demo-test-session-id-001')
        self.assertEqual(r['decision'], 'QUOTAS_MET')
        self.assertTrue(r['basis_announcements_authenticated'])
        self.assertEqual(r['public_messages'], 3)
        self.assertTrue(r['matched_positions_agree'])
        self.assertTrue(r['accounting_valid'])
        self.assertEqual(r['z_accepted'], 30)
        self.assertEqual(r['x_accepted'], 20)

    def test_no_security_claim_or_key_export(self):
        r = experiment(n_z=20, k_x=20, max_transmissions=500, seed=42, measure=ideal)
        self.assertFalse(r['security_model_validated'])
        self.assertFalse(r['hpke_export_authorized'])
        self.assertFalse(r['parameter_estimation_authenticated'])
        self.assertFalse(r['authentication_key_provisioning_validated'])
        self.assertFalse(r['theorem_specific_protocol_validated'])
        self.assertNotIn('secret_hex', r)

    def test_deterministic_public_statistics(self):
        r1 = experiment(n_z=20, k_x=20, max_transmissions=500, seed=42, measure=ideal)
        r2 = experiment(n_z=20, k_x=20, max_transmissions=500, seed=42, measure=ideal)
        for field in ('transmissions', 'z_accepted', 'x_accepted', 'basis_mismatches'):
            self.assertEqual(r1[field], r2[field])

    def test_abort_limit_authenticated(self):
        r = experiment(n_z=30, k_x=30, max_transmissions=60, seed=42, measure=ideal)
        self.assertEqual(r['decision'], 'ABORT_MAX_TRANSMISSIONS')
        self.assertEqual(r['public_messages'], 3)
        self.assertTrue(r['transcript_hash_agreement'])

    def test_tampered_actual_bases_rejected(self):
        a, b = simulate_records(n_z=10, k_x=10, max_transmissions=200,
                                seed=42, measure=ideal)
        def tamper(kind, frame, tag):
            if kind == 'bob_bases':
                return frame.replace(b'"bases":[', b'"bases":[1,', 1), tag
            return frame, tag
        with self.assertRaises(TranscriptError):
            authenticate_sifting(a, b, n_z=10, k_x=10, max_transmissions=200,
                                  frame_hook=tamper)

    def test_omitted_frame_rejected(self):
        a, b = simulate_records(n_z=10, k_x=10, max_transmissions=200,
                                seed=42, measure=ideal)
        def omit(kind, frame, tag):
            if kind == 'alice_bases':
                return b'', tag
            return frame, tag
        with self.assertRaises(TranscriptError):
            authenticate_sifting(a, b, n_z=10, k_x=10, max_transmissions=200,
                                  frame_hook=omit)

    def test_wrong_mac_key_rejected(self):
        a, b = simulate_records(n_z=10, k_x=10, max_transmissions=200,
                                seed=42, measure=ideal)
        with self.assertRaises(ValueError):
            authenticate_sifting(a, b, n_z=10, k_x=10, max_transmissions=200,
                                  authentication_key=b'short')

    def test_invalid_measurement(self):
        with self.assertRaises(ValueError):
            experiment(n_z=10, k_x=10, max_transmissions=200,
                       seed=42, measure=lambda *args: 3)

    def test_bad_configuration(self):
        with self.assertRaises(ValueError):
            experiment(n_z=10, k_x=10, max_transmissions=19,
                       seed=42, measure=ideal)

    def test_no_private_bits_in_report(self):
        a, b = simulate_records(n_z=16, k_x=16, max_transmissions=200,
                                seed=7, measure=ideal)
        r = authenticate_sifting(a, b, n_z=16, k_x=16, max_transmissions=200)
        self.assertNotIn('alice_bits', r)
        self.assertNotIn('bob_bits', r)
        self.assertNotIn('key', r)


if __name__ == '__main__':
    unittest.main()
