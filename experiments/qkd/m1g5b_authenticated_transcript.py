"""G5.B experimental authenticated public discussion state machine.

Synthetic transcript demonstration only. Does not authenticate existing CUDA-Q
sifting, establish secret authentication key provisioning, or qualify QKD keys.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

DOMAIN = b"pqc-rs/qkd/g5b/public-channel/v1\x00"
STEPS = (("alice", "alice_bases"), ("bob", "bob_bases"),
         ("alice", "quota_status"), ("alice", "sample_selection"),
         ("bob", "sample_statistics"), ("alice", "final_decision"))


class TranscriptError(ValueError):
    pass


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _binary_bases(v: Any, name: str) -> None:
    if type(v) is not list or not v or len(v) > 100000 or any(type(x) is not int or x not in (0, 1) for x in v):
        raise TranscriptError(f"{name} must be a nonempty list of binary bases")


def _validate(kind: str, payload: Any) -> None:
    if type(payload) is not dict:
        raise TranscriptError("invalid payload")
    if kind in ("alice_bases", "bob_bases"):
        if set(payload) != {"bases"}:
            raise TranscriptError("invalid basis message fields")
        _binary_bases(payload["bases"], "bases")
    elif kind == "quota_status":
        if set(payload) != {"decision", "z_accepted", "x_accepted", "transmissions"}:
            raise TranscriptError("invalid quota fields")
        if payload["decision"] != "QUOTAS_MET":
            raise TranscriptError("quota failure: require abort")
        for k in ("z_accepted", "x_accepted", "transmissions"):
            if type(payload[k]) is not int or payload[k] < 1:
                raise TranscriptError("invalid quota counts")
        if payload["transmissions"] < payload["z_accepted"] + payload["x_accepted"]:
            raise TranscriptError("impossible quotas")
    elif kind == "sample_selection":
        if set(payload) != {"indices", "population_size"}:
            raise TranscriptError("invalid sample fields")
        n, indices = payload["population_size"], payload["indices"]
        if type(n) is not int or n <= 0 or type(indices) is not list or not indices:
            raise TranscriptError("invalid sample selection")
        if len(indices) > n or any(type(x) is not int or not 0 <= x < n for x in indices) or len(set(indices)) != len(indices):
            raise TranscriptError("invalid sample indices")
    elif kind == "sample_statistics":
        if set(payload) != {"sample_size", "error_count"}:
            raise TranscriptError("invalid sample statistics fields")
        n, e = payload["sample_size"], payload["error_count"]
        if type(n) is not int or type(e) is not int or n <= 0 or not 0 <= e <= n:
            raise TranscriptError("invalid sample statistics")
    elif kind == "final_decision":
        if set(payload) != {"decision"} or payload["decision"] not in ("CONTINUE_UNQUALIFIED", "ABORT"):
            raise TranscriptError("invalid final decision")
    elif kind == "abort":
        if set(payload) != {"reason"} or type(payload["reason"]) is not str or not 0 < len(payload["reason"]) <= 128:
            raise TranscriptError("invalid abort reason")
    else:
        raise TranscriptError("unsupported message kind")


class PublicDiscussion:
    """Per-peer sequenced authenticated transport with state and transcript binding.

    Supply an *independently provisioned secret* 32+ byte MAC key, a unique
    unpredictable session ID, and exactly matching peer configuration.
    This is not a substitute for independent provisioning or a QKD proof.
    """
    def __init__(self, key: bytes, session_id: bytes, own_role: str):
        if type(key) is not bytes or len(key) < 32:
            raise ValueError("secret MAC key must be 32+ bytes")
        if type(session_id) is not bytes or len(session_id) < 16 or len(session_id) > 64:
            raise ValueError("session ID must be 16 to 64 bytes")
        if own_role not in ("alice", "bob"):
            raise ValueError("role must be alice or bob")
        self._key = key
        self._sid = session_id.hex()
        self.role = own_role
        self.seq = 0
        self._chain = hashlib.sha256(DOMAIN + session_id).digest()
        self.aborted = False
        self._phase = 0
        self._alice_bases: list[int] | None = None
        self._bob_bases: list[int] | None = None
        self._selected_count: int | None = None
        self.finished = False

    @property
    def transcript_hash(self) -> str:
        return self._chain.hex()

    def _check_step(self, sender: str, kind: str, payload: dict[str, Any]) -> None:
        if self.aborted or self.finished:
            raise TranscriptError("session already terminated")
        if kind == "abort":
            _validate(kind, payload)
            return
        if self._phase >= len(STEPS) or (sender, kind) != STEPS[self._phase]:
            raise TranscriptError("unexpected message order or sender")
        _validate(kind, payload)
        if kind == "bob_bases" and len(payload["bases"]) != len(self._alice_bases):
            raise TranscriptError("basis lengths differ")
        if kind == "quota_status":
            a, b = self._alice_bases, self._bob_bases
            z = sum(x == y == 0 for x, y in zip(a, b))
            x = sum(x == y == 1 for x, y in zip(a, b))
            if payload["transmissions"] != len(a) or payload["z_accepted"] > z or payload["x_accepted"] > x:
                raise TranscriptError("quota summary inconsistent with public bases")
        if kind == "sample_selection" and payload["population_size"] != sum(
            x == y == 1 for x, y in zip(self._alice_bases, self._bob_bases)):
            raise TranscriptError("sample population inconsistent with X matches")
        if kind == "sample_statistics" and payload["sample_size"] != self._selected_count:
            raise TranscriptError("sample statistics count differs from selected indices")

    def _advance(self, kind: str, payload: dict[str, Any]) -> None:
        if kind == "abort":
            self.aborted = True
            return
        if kind == "alice_bases":
            self._alice_bases = payload["bases"]
        if kind == "bob_bases":
            self._bob_bases = payload["bases"]
        if kind == "sample_selection":
            self._selected_count = len(payload["indices"])
        self._phase += 1
        self.finished = self._phase == len(STEPS)

    def send(self, kind: str, payload: dict[str, Any]) -> tuple[bytes, bytes]:
        self._check_step(self.role, kind, payload)
        frame = {"v": 1, "sid": self._sid, "sender": self.role,
                 "seq": self.seq, "previous_hash": self._chain.hex(),
                 "kind": kind, "payload": payload}
        data = _canonical(frame)
        tag = hmac.digest(self._key, DOMAIN + data, "sha256")
        self._chain = hashlib.sha256(self._chain + data + tag).digest()
        self.seq += 1
        self._advance(kind, payload)
        return data, tag

    def receive(self, data: bytes, tag: bytes) -> dict[str, Any]:
        if self.aborted or self.finished:
            raise TranscriptError("session already terminated")
        if type(data) is not bytes or type(tag) is not bytes or len(tag) != 32 or len(data) > 1000000:
            raise TranscriptError("invalid authenticated frame")
        expected = hmac.digest(self._key, DOMAIN + data, "sha256")
        if not hmac.compare_digest(tag, expected):
            raise TranscriptError("MAC validation failed")
        try:
            frame = json.loads(data)
            if type(frame) is not dict or _canonical(frame) != data:
                raise ValueError("noncanonical JSON")
        except (UnicodeError, ValueError, TypeError) as exc:
            raise TranscriptError("invalid frame encoding") from exc
        if set(frame) != {"v", "sid", "sender", "seq", "previous_hash", "kind", "payload"}:
            raise TranscriptError("unexpected frame fields")
        if (frame["v"] != 1 or frame["sid"] != self._sid or
            frame["sender"] == self.role or frame["sender"] not in ("alice", "bob") or
            type(frame["seq"]) is not int or frame["seq"] != self.seq or
            frame["previous_hash"] != self._chain.hex()):
            raise TranscriptError("session, sequence, role, or chain mismatch")
        self._check_step(frame["sender"], frame["kind"], frame["payload"])
        self._chain = hashlib.sha256(self._chain + data + tag).digest()
        self.seq += 1
        self._advance(frame["kind"], frame["payload"])
        return frame["payload"]


def synthetic_demo() -> dict[str, Any]:
    """Synthetic public transcript, NOT actual authentication of CUDA-Q measurements."""
    alice = PublicDiscussion(b"A" * 32, b"demo-session-nonce-0001", "alice")
    bob = PublicDiscussion(b"A" * 32, b"demo-session-nonce-0001", "bob")
    messages = [
        (alice, bob, "alice_bases", {"bases": [0, 1, 0, 1, 0, 1]}),
        (bob, alice, "bob_bases", {"bases": [0, 1, 1, 1, 0, 1]}),
        (alice, bob, "quota_status", {"decision": "QUOTAS_MET", "z_accepted": 2, "x_accepted": 2, "transmissions": 6}),
        (alice, bob, "sample_selection", {"population_size": 3, "indices": [0, 2]}),
        (bob, alice, "sample_statistics", {"sample_size": 2, "error_count": 0}),
        (alice, bob, "final_decision", {"decision": "CONTINUE_UNQUALIFIED"}),
    ]
    for sender, receiver, kind, payload in messages:
        data, tag = sender.send(kind, payload)
        receiver.receive(data, tag)
    assert alice.finished and bob.finished and alice.transcript_hash == bob.transcript_hash
    return {"authenticated_synthetic_transcript": True, "messages": len(messages),
            "transcript_hash_agreement": True, "actual_cudaq_sifting_authenticated": False,
            "security_model_validated": False, "security_qualified": False,
            "hpke_export_authorized": False}


if __name__ == "__main__":
    print(json.dumps(synthetic_demo(), indent=2, sort_keys=True))
    print("QKD_M1G5B_TRANSCRIPT_PRIMITIVE_STATUS=PASS")
    print("QKD_M1G5B_SECURITY_MODEL_VALIDATED=false")
