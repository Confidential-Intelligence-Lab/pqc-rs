"""M1.E1 experimental correctness and negative tests."""
import unittest

from m1e1_reconciliation import (AuthenticatedTranscript, ReconciliationError,
                            reconcile_single_error_blocks)

AUTH = bytes(range(32))  # Test fixture, never a deployment authentication key.
RAW = ("00110100110110001010101110100011" * 8)

class TestM1E1(unittest.TestCase):
    def test_ideal(self):
        outcome, report = reconcile_single_error_blocks(RAW, RAW, AUTH)
        self.assertEqual(outcome, RAW)
        self.assertTrue(report.matched)
        self.assertEqual(report.corrected_bits, 0)
        self.assertEqual(report.parity_bits_revealed, 8)
        self.assertEqual(report.total_leakage_upper_bound_bits, 136)
        self.assertFalse(report.security_qualified)

    def test_single_error_per_block(self):
        flipped = list(RAW)
        for i in (3, 36, 129, 252):
            flipped[i] = "1" if flipped[i] == "0" else "0"
        outcome, report = reconcile_single_error_blocks(RAW, "".join(flipped), AUTH)
        self.assertEqual(outcome, RAW)
        self.assertEqual(report.corrected_bits, 4)
        self.assertGreater(report.parity_bits_revealed, 8)
        self.assertEqual(report.total_leakage_upper_bound_bits,
                         report.parity_bits_revealed + 128)

    def test_even_number_errors_detected_by_confirmation(self):
        flipped = list(RAW)
        for i in (1, 2):
            flipped[i] = "1" if flipped[i] == "0" else "0"
        with self.assertRaisesRegex(ReconciliationError, "confirmation failed"):
            reconcile_single_error_blocks(RAW, "".join(flipped), AUTH)

    def test_tamper_and_replay(self):
        sender = AuthenticatedTranscript(AUTH)
        receiver = AuthenticatedTranscript(AUTH)
        frame, tag = sender.send("parity", {"parity": 1})
        altered = frame.replace(b'"parity":1', b'"parity":0')
        with self.assertRaisesRegex(ReconciliationError, "authentication failed"):
            receiver.receive(altered, tag, "parity")
        self.assertEqual(receiver.receive(frame, tag, "parity"), {"parity": 1})
        with self.assertRaisesRegex(ReconciliationError, "replayed"):
            receiver.receive(frame, tag, "parity")

    def test_wrong_authentication_key(self):
        sender = AuthenticatedTranscript(AUTH)
        receiver = AuthenticatedTranscript(bytes(reversed(AUTH)))
        frame, tag = sender.send("parity", {"parity": 0})
        with self.assertRaisesRegex(ReconciliationError, "authentication failed"):
            receiver.receive(frame, tag, "parity")

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            reconcile_single_error_blocks("0102", "0101", AUTH)
        with self.assertRaises(ValueError):
            reconcile_single_error_blocks("01", "0", AUTH)
        with self.assertRaises(ValueError):
            reconcile_single_error_blocks("01", "01", b"short")

if __name__ == "__main__":
    unittest.main()
