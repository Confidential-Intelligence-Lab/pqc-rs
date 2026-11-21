"""G5.C1: actual BB84 measurement records to authenticated public basis discussion.

Diagnostic simulation only. No secret source bits, sample errors, or key bytes
are published. The authenticated transcript intentionally stops before G5.C2.
"""
from __future__ import annotations

import argparse
import json
import os
import random
from dataclasses import dataclass
from typing import Callable

from m1g5b_authenticated_transcript import PublicDiscussion, TranscriptError


@dataclass(frozen=True)
class AliceRecord:
    bit: int
    basis: int


@dataclass(frozen=True)
class BobRecord:
    bit: int
    basis: int


def _validate(n_z: int, k_x: int, max_transmissions: int, seed: int,
              z_probability: float, intercept_percent: int) -> None:
    for name, x in (("n_z", n_z), ("k_x", k_x), ("max_transmissions", max_transmissions)):
        if type(x) is not int or x <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if max_transmissions > 100000:
        raise ValueError("maximum exceeds authenticated transcript basis-list limit")
    if max_transmissions < n_z + k_x:
        raise ValueError("maximum transmissions below total quotas")
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a nonnegative integer")
    if type(z_probability) not in (int, float) or not 0 < z_probability < 1:
        raise ValueError("invalid basis selection probability")
    if type(intercept_percent) is not int or not 0 <= intercept_percent <= 100:
        raise ValueError("invalid interception percentage")


def _positions(alice_bases: list[int], bob_bases: list[int],
               n_z: int, k_x: int) -> tuple[list[int], list[int], int]:
    if len(alice_bases) != len(bob_bases):
        raise TranscriptError("basis announcement length mismatch")
    z: list[int] = []
    x: list[int] = []
    mismatches = 0
    for i, (a, b) in enumerate(zip(alice_bases, bob_bases)):
        if a != b:
            mismatches += 1
        elif a == 0 and len(z) < n_z:
            z.append(i)
        elif a == 1 and len(x) < k_x:
            x.append(i)
    return z, x, mismatches


def simulate_records(*, n_z: int, k_x: int, max_transmissions: int,
                     seed: int, z_probability: float = 0.5,
                     intercept_percent: int = 0,
                     measure: Callable[[int, int, int], int] | None = None
                     ) -> tuple[tuple[AliceRecord, ...], tuple[BobRecord, ...]]:
    _validate(n_z, k_x, max_transmissions, seed, z_probability, intercept_percent)
    if measure is None:
        import cudaq
        from bb84_cudaq import measured_bit
        cudaq.set_random_seed(seed)
        measure = measured_bit
    # Public deterministic randomness: reproduces experiment, NOT secrecy.
    rng = random.Random(seed)
    alice: list[AliceRecord] = []
    bob: list[BobRecord] = []
    z_seen = x_seen = 0
    while len(alice) < max_transmissions and (z_seen < n_z or x_seen < k_x):
        a_bit = rng.randrange(2)
        a_basis = 0 if rng.random() < z_probability else 1
        b_basis = 0 if rng.random() < z_probability else 1
        if rng.randrange(100) < intercept_percent:
            eve_basis = rng.randrange(2)
            eve_bit = measure(a_bit, a_basis, eve_basis)
            if type(eve_bit) is not int or eve_bit not in (0, 1):
                raise ValueError("invalid Eve measurement")
            observed = measure(eve_bit, eve_basis, b_basis)
        else:
            observed = measure(a_bit, a_basis, b_basis)
        if type(observed) is not int or observed not in (0, 1):
            raise ValueError("invalid Bob measurement")
        alice.append(AliceRecord(a_bit, a_basis))
        bob.append(BobRecord(observed, b_basis))
        if a_basis == b_basis == 0 and z_seen < n_z:
            z_seen += 1
        elif a_basis == b_basis == 1 and x_seen < k_x:
            x_seen += 1
    return tuple(alice), tuple(bob)


def authenticate_sifting(alice_records: tuple[AliceRecord, ...],
                         bob_records: tuple[BobRecord, ...], *, n_z: int, k_x: int,
                         max_transmissions: int,
                         authentication_key: bytes | None = None,
                         session_id: bytes | None = None,
                         frame_hook: Callable[[str, bytes, bytes], tuple[bytes, bytes]] | None = None
                         ) -> dict:
    if not alice_records or len(alice_records) != len(bob_records):
        raise ValueError("missing or mismatched local record lengths")
    if len(alice_records) > max_transmissions:
        raise ValueError("transmission limit exceeded")
    _validate(n_z, k_x, max_transmissions, 0, .5, 0)
    key = authentication_key if authentication_key is not None else os.urandom(32)
    sid = session_id if session_id is not None else os.urandom(24)
    alice_peer = PublicDiscussion(key, sid, "alice")
    bob_peer = PublicDiscussion(key, sid, "bob")
    # Each party's private measurement bits remain in its local record object.
    alice_bases = [r.basis for r in alice_records]
    bob_bases = [r.basis for r in bob_records]
    # Do not reconcile indices until each party receives peer bases authentically.
    def deliver(sender: PublicDiscussion, receiver: PublicDiscussion,
                kind: str, payload: dict) -> None:
        frame, tag = sender.send(kind, payload)
        if frame_hook is not None:
            frame, tag = frame_hook(kind, frame, tag)
        receiver.receive(frame, tag)

    deliver(alice_peer, bob_peer, "alice_bases", {"bases": alice_bases})
    deliver(bob_peer, alice_peer, "bob_bases", {"bases": bob_bases})
    received_a = alice_peer._bob_bases  # authenticated peer basis announcement
    received_b = bob_peer._alice_bases
    if received_a is None or received_b is None:
        raise TranscriptError("missing authenticated announcement")
    z_bob, x_bob, mismatch_b = _positions(received_b, bob_bases, n_z, k_x)
    z_alice, x_alice, mismatch_a = _positions(alice_bases, received_a, n_z, k_x)
    if (z_alice, x_alice, mismatch_a) != (z_bob, x_bob, mismatch_b):
        raise TranscriptError("authenticated sifting index disagreement")
    met = len(z_alice) == n_z and len(x_alice) == k_x
    if met:
        deliver(alice_peer, bob_peer, "quota_status", {
            "decision": "QUOTAS_MET", "z_accepted": len(z_alice),
            "x_accepted": len(x_alice), "transmissions": len(alice_records)})
    else:
        deliver(alice_peer, bob_peer, "abort", {"reason": "MATCHED_BASIS_QUOTAS_UNMET"})
    if alice_peer.transcript_hash != bob_peer.transcript_hash:
        raise TranscriptError("public transcript hash mismatch")
    total = len(alice_records)
    discarded = total - len(z_alice) - len(x_alice) - mismatch_a
    return {
        "decision": "QUOTAS_MET" if met else "ABORT_MAX_TRANSMISSIONS",
        "transmissions": total,
        "z_quota": n_z, "x_quota": k_x,
        "z_accepted": len(z_alice), "x_accepted": len(x_alice),
        "basis_mismatches": mismatch_a,
        "quota_filled_discards": discarded,
        "accounting_valid": discarded >= 0 and total == len(z_alice) + len(x_alice) + mismatch_a + discarded,
        "basis_announcements_authenticated": True,
        "matched_positions_agree": True,
        "transcript_hash_agreement": True,
        "transcript_sha256": alice_peer.transcript_hash,
        "public_messages": alice_peer.seq,
        "authentication_key_provisioning_validated": False,
        "parameter_estimation_authenticated": False,
        "theorem_specific_protocol_validated": False,
        "security_model_validated": False,
        "security_qualified": False,
        "hpke_export_authorized": False,
        "provenance": "CUDA_Q_SIMULATION_NOT_SECURE_QKD",
        "public_seed_is_not_secret": True,
    }


def experiment(*, n_z: int, k_x: int, max_transmissions: int, seed: int,
               z_probability: float = .5, intercept_percent: int = 0,
               measure: Callable[[int, int, int], int] | None = None) -> dict:
    alice, bob = simulate_records(n_z=n_z, k_x=k_x,
                                  max_transmissions=max_transmissions,
                                  seed=seed, z_probability=z_probability,
                                  intercept_percent=intercept_percent, measure=measure)
    return authenticate_sifting(alice, bob, n_z=n_z, k_x=k_x,
                                max_transmissions=max_transmissions)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n-z", type=int, default=128)
    ap.add_argument("--k-x", type=int, default=128)
    ap.add_argument("--max-transmissions", type=int, default=4096)
    ap.add_argument("--seed", type=int, default=20261120)
    ap.add_argument("--z-probability", type=float, default=.5)
    ap.add_argument("--intercept-percent", type=int, default=0)
    a = ap.parse_args()
    result = experiment(n_z=a.n_z, k_x=a.k_x, max_transmissions=a.max_transmissions,
                        seed=a.seed, z_probability=a.z_probability,
                        intercept_percent=a.intercept_percent)
    print(json.dumps(result, sort_keys=True, indent=2))
    if result["decision"] != "QUOTAS_MET" or not result["accounting_valid"]:
        raise SystemExit(2)
    print("QKD_M1G5C1_ACTUAL_BASIS_AUTHENTICATED_STATUS=PASS")
    print("QKD_M1G5C1_SECURITY_MODEL_VALIDATED=false")


if __name__ == "__main__":
    main()
