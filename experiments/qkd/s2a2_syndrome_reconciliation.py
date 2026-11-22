"""S2.A2: bounded-distance authenticated binary-syndrome reconciliation.

Research simulator only. A public random parity-check matrix is generated per
block and verified to have distinct syndromes for all error patterns of weight
0, 1 and 2. The decoder corrects such errors deterministically. Errors above
that radius may alias: the independent S2.A1 universal confirmation detects
remaining differences with probability at least 1-2^-tag_bits, subject to its
fresh-seed/independence assumptions. No secrecy, QKD qualification or export.

This is a bounded-distance reference design, NOT a production LDPC decoder.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import random
import secrets
from typing import Callable

from s2a1_universal_confirmation import ConfirmationError, confirm_fixed_inputs

DOMAIN = b'pqc-rs/qkd/s2a2/syndrome/v1\x00'
MAX_BITS = 65536
BLOCK_SIZE = 128
SYNDROME_ROWS = 32
COLUMN_WEIGHT = 10
MAX_MATRIX_ATTEMPTS = 128

class SyndromeError(ValueError):
    """Invalid authenticated syndrome, decode failure, or confirmation failure."""

@dataclass(frozen=True)
class SyndromeReport:
    """Public leakage/correctness metadata, never secret key material."""
    decision: str
    raw_key_bits: int
    block_count: int
    syndrome_leakage_upper_bound_bits: int
    confirmation_leakage_upper_bound_bits: int
    total_leakage_upper_bound_bits: int
    corrected_errors: int
    authenticated_syndrome_messages: int
    authenticated_confirmation_messages: int
    epsilon_correctness_bound: str
    decoder_guarantee: str
    independent_matrix_seed: bool
    authentication_provisioning_validated: bool = False
    quantum_min_entropy_proven: bool = False
    security_model_validated: bool = False
    security_qualified: bool = False
    hpke_export_authorized: bool = False


def _bits(bits: str) -> None:
    if not isinstance(bits, str) or not 1 <= len(bits) <= MAX_BITS or set(bits) - {'0', '1'}:
        raise ValueError('expected nonempty raw binary string <= 65536 bits')


def _matrix(seed: bytes, width: int) -> tuple[tuple[int, ...], dict[int, int]]:
    """Public seeded matrix with injectivity on all errors of weight <= 2.

    Each column is a 32-bit mask containing ten ones. A full collision audit
    rejects any candidate matrix lacking the bounded-distance property.
    """
    if not isinstance(seed, bytes) or len(seed) != 16 or not 1 <= width <= BLOCK_SIZE:
        raise ValueError('invalid matrix seed or block size')
    for attempt in range(MAX_MATRIX_ATTEMPTS):
        material = hashlib.sha256(b's2a2-matrix-v1\x00' + seed + attempt.to_bytes(4,'big')).digest()
        rng = random.Random(int.from_bytes(material, 'big'))
        columns = tuple(sum(1 << row for row in rng.sample(range(SYNDROME_ROWS), COLUMN_WEIGHT))
                        for _ in range(width))
        mapping = {0: 0}
        valid = True
        for i, c in enumerate(columns):
            if c in mapping:
                valid = False
                break
            mapping[c] = 1 << i
        if not valid:
            continue
        for i in range(width):
            if not valid:
                break
            for j in range(i+1, width):
                syn = columns[i] ^ columns[j]
                if syn in mapping:
                    valid = False
                    break
                mapping[syn] = (1 << i) | (1 << j)
        if valid:
            return columns, mapping
    raise SyndromeError('could not construct injective bounded-distance matrix')


def _syndrome(bits: str, columns: tuple[int, ...]) -> int:
    value = 0
    for b, c in zip(bits, columns):
        if b == '1':
            value ^= c
    return value


def _encode(session: bytes, seq: int, start: int, width: int,
            seed: bytes, syndrome: int) -> bytes:
    return json.dumps({'session': session.hex(), 'seq': seq, 'kind': 'syndrome',
                       'start': start, 'width': width,
                       'matrix_seed': seed.hex(), 'syndrome': f'{syndrome:08x}'},
                      sort_keys=True, separators=(',', ':')).encode('ascii')


def reconcile_syndromes(alice_bits: str, bob_bits: str, *, session_id: bytes,
                        authentication_key: bytes, tag_bits: int = 40,
                        wire_hook: Callable[[int, bytes, bytes], tuple[bytes, bytes]] | None = None,
                        matrix_seed_source: Callable[[int], bytes] = secrets.token_bytes,
                        confirmation_seed_source=None) -> tuple[str, SyndromeReport]:
    """Reconcile local Alice/Bob test records through authenticated syndromes.

    The output string is private Bob-side state for local testing, not a QKD
    PSK or an authorization credential. The receiver does not compare secrets
    to Alice's key. Confirmation is performed via independent S2.A1 hashing.
    """
    _bits(alice_bits)
    _bits(bob_bits)
    if len(alice_bits) != len(bob_bits):
        raise ValueError('raw key lengths differ')
    if not isinstance(session_id, bytes) or not 16 <= len(session_id) <= 128:
        raise ValueError('invalid session ID')
    if not isinstance(authentication_key, bytes) or len(authentication_key) < 32:
        raise ValueError('authentication key must be >= 32 bytes')
    if type(tag_bits) is not int or not 1 <= tag_bits <= 256:
        raise ValueError('invalid confirmation tag length')
    if len(alice_bits) > MAX_BITS:
        raise ValueError('raw key too large')

    bob_fixed = list(bob_bits)
    corrections = 0
    blocks = 0
    for start in range(0, len(alice_bits), BLOCK_SIZE):
        width = min(BLOCK_SIZE, len(alice_bits)-start)
        seed = matrix_seed_source(16)
        if not isinstance(seed, bytes) or len(seed) != 16:
            raise SyndromeError('invalid matrix seed')
        columns, table = _matrix(seed, width)
        alice_syn = _syndrome(alice_bits[start:start+width], columns)
        frame = _encode(session_id, blocks, start, width, seed, alice_syn)
        tag = hmac.digest(authentication_key, DOMAIN + frame, 'sha256')
        if wire_hook is not None:
            frame, tag = wire_hook(blocks, frame, tag)
        if not isinstance(frame, bytes) or not isinstance(tag, bytes):
            raise SyndromeError('invalid wire types')
        if not hmac.compare_digest(tag, hmac.digest(authentication_key, DOMAIN + frame, 'sha256')):
            raise SyndromeError('authentication failed')
        try:
            payload = json.loads(frame)
        except (UnicodeDecodeError, ValueError) as exc:
            raise SyndromeError('invalid syndrome payload') from exc
        if not isinstance(payload, dict) or set(payload) != {'session','seq','kind','start','width','matrix_seed','syndrome'}:
            raise SyndromeError('unexpected syndrome frame')
        if payload != json.loads(_encode(session_id, blocks, start, width, seed, alice_syn)):
            raise SyndromeError('syndrome frame replay, substitution or mismatch')
        bob_syn = _syndrome(''.join(bob_fixed[start:start+width]), columns)
        delta = alice_syn ^ bob_syn
        if delta not in table:
            raise SyndromeError('decoder failed: discard raw key')
        error_mask = table[delta]
        for offset in range(width):
            if (error_mask >> offset) & 1:
                pos = start+offset
                bob_fixed[pos] = '1' if bob_fixed[pos] == '0' else '0'
                corrections += 1
        blocks += 1
    result = ''.join(bob_fixed)
    try:
        params = dict(session_id=session_id, authentication_key=authentication_key, tag_bits=tag_bits)
        if confirmation_seed_source is not None:
            params['seed_source'] = confirmation_seed_source
        confirm = confirm_fixed_inputs(alice_bits, result, **params)
    except ConfirmationError as exc:
        raise SyndromeError('universal confirmation failed: discard raw key') from exc
    syndrome_leak = blocks * SYNDROME_ROWS
    report = SyndromeReport(
        decision='RECONCILIATION_PASS_UNQUALIFIED', raw_key_bits=len(alice_bits),
        block_count=blocks, syndrome_leakage_upper_bound_bits=syndrome_leak,
        confirmation_leakage_upper_bound_bits=tag_bits,
        total_leakage_upper_bound_bits=syndrome_leak+tag_bits,
        corrected_errors=corrections,
        authenticated_syndrome_messages=blocks,
        authenticated_confirmation_messages=confirm.authenticated_messages,
        epsilon_correctness_bound=confirm.epsilon_correctness_bound,
        decoder_guarantee='EXACT_FOR_AT_MOST_TWO_ERRORS_PER_BLOCK',
        independent_matrix_seed=True,
    )
    return result, report


def public_report(report: SyndromeReport) -> dict:
    """Return only public metadata and explicit nonqualification flags."""
    return asdict(report)
