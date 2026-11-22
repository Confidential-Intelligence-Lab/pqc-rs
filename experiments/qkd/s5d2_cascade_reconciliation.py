"""S5.D-2 research-only, single-process authenticated Cascade-style reconciliation.

This is NOT a distributed authenticated-channel implementation. Alice and Bob
are both simulated in one process. Public parity pairs are MAC-protected and
accounted for; no secret keys are returned by the public report. This module
is an ALTERNATIVE experiment, not yet wired into S3.C/S4.E.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import hashlib
import hmac
import json
import math
import random
import secrets
from collections import deque

from s2a1_universal_confirmation import confirm_fixed_inputs, ConfirmationError

class CascadeError(ValueError):
    pass

@dataclass(frozen=True)
class CascadeReport:
    decision: str
    raw_key_bits: int
    passes: int
    public_parity_pairs: int
    parity_disclosure_upper_bits: int
    confirmation_tag_bits: int
    reconciliation_disclosure_upper_bits: int
    corrections: int
    authenticated_frames: int
    transcript_sha256: str
    security_model_validated: bool = False
    security_qualified: bool = False
    hpke_export_authorized: bool = False
    qkd_psk_available: bool = False


def reconcile_cascade(alice_bits: str, bob_bits: str, *, session_id: bytes,
                      authentication_key: bytes, tag_bits: int = 64,
                      block_sizes: tuple[int, ...] = (16, 32, 64, 128, 256, 512),
                      max_parity_pairs: int = 8192,
                      permutation_seed: bytes | None = None,
                      wire_hook=None) -> tuple[str, CascadeReport]:
    """Cascade-style iterative parity correction with bounded public disclosure.

    Permutations are publicly seeded; queries are driven solely by prior
    public parity answers. Every queried Alice/Bob parity pair is public and
    conservatively charged TWO bits. Index sets are deterministic given the
    public seed, query sequence and earlier public outcomes. MAC tags and
    full frame accounting require a separate authentication reduction.

    Returns corrected Bob bits for isolated testing only; no QKD key export.
    """
    n = len(alice_bits) if isinstance(alice_bits, str) else 0
    if not (1 <= n <= 65536 and isinstance(bob_bits, str) and len(bob_bits) == n
            and not (set(alice_bits) | set(bob_bits)) - {'0', '1'}):
        raise CascadeError('invalid raw bit strings')
    if not (isinstance(session_id, bytes) and 16 <= len(session_id) <= 128
            and isinstance(authentication_key, bytes) and len(authentication_key) >= 32):
        raise CascadeError('invalid authentication parameters')
    if (type(tag_bits) is not int or not 1 <= tag_bits <= 256 or
            type(max_parity_pairs) is not int or not 1 <= max_parity_pairs <= 100000 or
            type(block_sizes) is not tuple or not block_sizes or
            any(type(z) is not int or z < 2 or z > n for z in block_sizes)):
        raise CascadeError('invalid limits')
    if permutation_seed is None:
        permutation_seed = secrets.token_bytes(32)
    if not isinstance(permutation_seed, bytes) or len(permutation_seed) != 32:
        raise CascadeError('invalid public permutation seed')
    rng = random.Random(int.from_bytes(hashlib.sha256(b's5d2-perm\0'+permutation_seed).digest(), 'big'))
    alice = [int(c) for c in alice_bits]
    bob = [int(c) for c in bob_bits]
    layouts = []
    lookup = []
    digest = hashlib.sha256(b's5d2-cascade-v1\0'+session_id+permutation_seed)
    queries = 0
    flips = 0
    pending = deque()
    in_queue = set()

    def enqueue(p, bi):
        key = (p, bi)
        if key not in in_queue:
            pending.append(key)
            in_queue.add(key)

    def parity(v, indices):
        return sum(v[i] for i in indices) & 1

    def ask(indices):
        nonlocal queries
        if queries >= max_parity_pairs:
            raise CascadeError('public disclosure cap exhausted; abort')
        a = parity(alice, indices)
        b = parity(bob, indices)
        payload = json.dumps({'v': 1, 'sid': session_id.hex(), 'seq': queries,
                              'positions': list(indices), 'alice_parity': a,
                              'bob_parity': b}, sort_keys=True,
                             separators=(',', ':')).encode('ascii')
        tag = hmac.digest(authentication_key, b's5d2-cascade-mac-v1\0'+payload, 'sha256')
        if wire_hook:
            payload, tag = wire_hook(queries, payload, tag)
        if not isinstance(payload, bytes) or not isinstance(tag, bytes):
            raise CascadeError('invalid public frame')
        if not hmac.compare_digest(tag, hmac.digest(authentication_key, b's5d2-cascade-mac-v1\0'+payload, 'sha256')):
            raise CascadeError('authentication failure')
        expected = json.dumps({'v': 1, 'sid': session_id.hex(), 'seq': queries,
                               'positions': list(indices), 'alice_parity': a,
                               'bob_parity': b}, sort_keys=True,
                              separators=(',', ':')).encode('ascii')
        if payload != expected:
            raise CascadeError('replayed or substituted public frame')
        digest.update(len(payload).to_bytes(4, 'big')+payload+tag)
        queries += 1
        return a != b

    def correction(indices):
        nonlocal flips
        # Caller just checked odd parity mismatch for this whole block.
        subset = indices
        while len(subset) > 1:
            left = subset[:len(subset)//2]
            if ask(left):
                subset = left
            else:
                subset = subset[len(subset)//2:]
        pos = subset[0]
        bob[pos] ^= 1
        flips += 1
        # Cascade lookback: previously constructed permutations containing pos.
        for p in range(len(layouts)):
            enqueue(p, lookup[p][pos])

    for pass_index, block_size in enumerate(block_sizes):
        permutation = list(range(n))
        rng.shuffle(permutation)
        groups = tuple(tuple(permutation[i:i+block_size])
                       for i in range(0, n, block_size))
        inverse = [0]*n
        for bi, group in enumerate(groups):
            for pos in group:
                inverse[pos] = bi
        layouts.append(groups)
        lookup.append(inverse)
        for bi in range(len(groups)):
            enqueue(pass_index, bi)
        while pending:
            p, bi = pending.popleft()
            in_queue.remove((p, bi))
            group = layouts[p][bi]
            if ask(group):
                correction(group)
    fixed = ''.join(map(str, bob))
    try:
        confirm_fixed_inputs(alice_bits, fixed, session_id=session_id,
                             authentication_key=authentication_key, tag_bits=tag_bits)
    except ConfirmationError as exc:
        raise CascadeError('independent key confirmation failed; abort') from exc
    # Only public parity answer pairs are counted here; no claim that this
    # is the *complete* composable transcript leakage of a deployed system.
    leak = 2*queries
    return fixed, CascadeReport(
        decision='CASCADE_RECONCILIATION_PASS_UNQUALIFIED', raw_key_bits=n,
        passes=len(block_sizes), public_parity_pairs=queries,
        parity_disclosure_upper_bits=leak, confirmation_tag_bits=tag_bits,
        reconciliation_disclosure_upper_bits=leak+tag_bits,
        corrections=flips, authenticated_frames=queries+1,
        transcript_sha256=digest.hexdigest())


def public_report(report: CascadeReport) -> dict:
    return asdict(report)
