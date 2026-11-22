"""Experimental authenticated BB84 raw-key reconciliation.

Not a secure QKD key-distillation implementation. Authentication requires a
separately provisioned, secret classical MAC key. No privacy amplification or
finite-key proof is provided.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from typing import Any

DOMAIN = b"pqc-rs/qkd/m1e1/authenticated-classical/v1\x00"
CONFIRM_BYTES = 16

class ReconciliationError(ValueError):
    """The authenticated transcript or reconciliation cannot be accepted."""

class AuthenticatedTranscript:
    """Local simulation of a sequenced, authenticated public channel."""
    def __init__(self, key: bytes):
        if len(key) < 32:
            raise ValueError("experimental MAC key must have at least 32 bytes")
        self._key = key
        self._next_send = 0
        self._next_receive = 0
        self.messages = 0

    def send(self, kind: str, payload: dict[str, Any]) -> tuple[bytes, bytes]:
        message = json.dumps({"seq": self._next_send, "kind": kind,
                              "payload": payload}, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
        tag = hmac.digest(self._key, DOMAIN + message, "sha256")
        self._next_send += 1
        return message, tag

    def receive(self, message: bytes, tag: bytes, expected_kind: str) -> dict[str, Any]:
        expected = hmac.digest(self._key, DOMAIN + message, "sha256")
        if not hmac.compare_digest(tag, expected):
            raise ReconciliationError("authentication failed")
        try:
            decoded = json.loads(message)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ReconciliationError("invalid transcript encoding") from exc
        if (not isinstance(decoded, dict) or decoded.get("seq") != self._next_receive
                or decoded.get("kind") != expected_kind
                or not isinstance(decoded.get("payload"), dict)):
            raise ReconciliationError("replayed, reordered, or invalid transcript message")
        self._next_receive += 1
        self.messages += 1
        return decoded["payload"]

@dataclass(frozen=True)
class ReconciliationReport:
    corrected_bits: int
    parity_bits_revealed: int
    confirmation_bits_revealed: int
    total_leakage_upper_bound_bits: int
    authenticated_messages: int
    matched: bool
    security_qualified: bool = False


def _bits(bits: str) -> None:
    if not bits or any(ch not in "01" for ch in bits):
        raise ValueError("bitstrings must be nonempty binary strings")


def reconcile_single_error_blocks(alice_bits: str, bob_bits: str,
                                  authentication_key: bytes,
                                  block_size: int = 32) -> tuple[str, ReconciliationReport]:
    """Correct at most one error per block, reject all uncorrected differences.

    For each block Alice discloses the block parity; if it disagrees with
    Bob's, binary search locates one flipped position using additional Alice
    parity disclosures. An independent equality confirmation rejects residual
    errors; it is *not* privacy amplification. The parity count plus 128 bits
    of revealed confirmation digest is a conservative leakage upper bound.

    The protocol is educational: no claim is made against active malicious
    parties, arbitrary attacks, or finite-key secrecy. Keys are not exported.
    """
    _bits(alice_bits)
    _bits(bob_bits)
    if len(alice_bits) != len(bob_bits):
        raise ValueError("raw keys must have identical length")
    if block_size < 2:
        raise ValueError("block_size must be >= 2")
    if len(alice_bits) > 1_000_000:
        raise ValueError("simulation guard: raw key too large")

    alice_channel = AuthenticatedTranscript(authentication_key)
    bob_channel = AuthenticatedTranscript(authentication_key)
    corrected = list(bob_bits)
    parity_bits = 0
    corrections = 0

    def alice_parity(indices: range) -> int:
        nonlocal parity_bits
        bit = sum(int(alice_bits[i]) for i in indices) & 1
        frame, tag = alice_channel.send("parity", {"start": indices.start,
                                                   "stop": indices.stop,
                                                   "parity": bit})
        data = bob_channel.receive(frame, tag, "parity")
        if data != {"start": indices.start, "stop": indices.stop, "parity": bit}:
            raise ReconciliationError("unexpected parity message")
        parity_bits += 1
        return bit

    for begin in range(0, len(alice_bits), block_size):
        end = min(begin + block_size, len(alice_bits))
        block = range(begin, end)
        if alice_parity(block) == (sum(int(corrected[i]) for i in block) & 1):
            continue
        lo, hi = begin, end
        while hi - lo > 1:
            mid = (lo + hi) // 2
            left = range(lo, mid)
            if alice_parity(left) != (sum(int(corrected[i]) for i in left) & 1):
                hi = mid
            else:
                lo = mid
        corrected[lo] = "1" if corrected[lo] == "0" else "0"
        corrections += 1

    result = "".join(corrected)
    # Explicit confirmation disclosure. Treat all 128 output bits as leakage.
    digest = hashlib.sha256(("m1e1-confirm:" + alice_bits).encode()).digest()[:CONFIRM_BYTES]
    message, tag = alice_channel.send("confirm", {"digest_hex": digest.hex()})
    data = bob_channel.receive(message, tag, "confirm")
    own_digest = hashlib.sha256(("m1e1-confirm:" + result).encode()).digest()[:CONFIRM_BYTES]
    matched = hmac.compare_digest(bytes.fromhex(data["digest_hex"]), own_digest)
    report = ReconciliationReport(
        corrected_bits=corrections,
        parity_bits_revealed=parity_bits,
        confirmation_bits_revealed=8 * CONFIRM_BYTES,
        total_leakage_upper_bound_bits=parity_bits + 8 * CONFIRM_BYTES,
        authenticated_messages=bob_channel.messages,
        matched=matched,
    )
    if not matched:
        raise ReconciliationError("reconciliation confirmation failed: discard raw key")
    return result, report
