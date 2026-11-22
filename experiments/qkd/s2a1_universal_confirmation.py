"""S2.A1: independent-seed Toeplitz key confirmation, experimental only.

This is a *local two-party simulator*, not production authentication.
The information-theoretic collision bound 2**(-tag_bits) assumes the
possibly unequal strings are fixed independently of the fresh public seed.
It does not certify source entropy, authentication, or QKD secrecy.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import secrets
from typing import Callable

DOMAIN = b"pqc-rs/qkd/s2a1/confirmation/v1\x00"
MAX_BITS = 65536
MAX_TAG_BITS = 256


class ConfirmationError(ValueError):
    """Invalid or unauthenticated confirmation, or mismatched raw keys."""


@dataclass(frozen=True)
class ConfirmationReport:
    """Public diagnostic metadata, never a QKD security credential."""
    decision: str
    raw_key_bits: int
    confirmation_tag_bits_disclosed: int
    public_seed_bits: int
    epsilon_correctness_bound: str
    authenticated_messages: int
    session_bound: bool
    independent_seed_sampled_after_inputs: bool
    authentication_provisioning_validated: bool = False
    security_model_validated: bool = False
    security_qualified: bool = False
    hpke_export_authorized: bool = False


def _validate_bits(value: str, name: str) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_BITS or set(value) - {'0', '1'}:
        raise ValueError(f'{name}: expected nonempty binary string <= {MAX_BITS} bits')


def _validate_parameters(alice: str, bob: str, tag_bits: int, session_id: bytes, auth_key: bytes) -> None:
    _validate_bits(alice, 'alice_bits')
    _validate_bits(bob, 'bob_bits')
    if len(alice) != len(bob):
        raise ValueError('raw key lengths differ')
    if type(tag_bits) is not int or not 1 <= tag_bits <= MAX_TAG_BITS:
        raise ValueError('tag_bits outside supported range')
    if not isinstance(session_id, bytes) or not 16 <= len(session_id) <= 128:
        raise ValueError('session_id must be 16 to 128 bytes')
    if not isinstance(auth_key, bytes) or len(auth_key) < 32:
        raise ValueError('experimental authentication key must be >= 32 bytes')


def toeplitz_confirmation_tag(bits: str, seed_bits: str, tag_bits: int) -> str:
    """Multiply a binary Toeplitz matrix by a bit vector over GF(2).

    Matrix element (row, col) = seed_bits[n-1 + row-col].
    All binary seeds produce a two-universal family; no fixed seed is secure.
    """
    _validate_bits(bits, 'bits')
    _validate_bits(seed_bits, 'seed_bits')
    if type(tag_bits) is not int or not 1 <= tag_bits <= MAX_TAG_BITS:
        raise ValueError('invalid tag_bits')
    n = len(bits)
    if len(seed_bits) != n + tag_bits - 1:
        raise ValueError('Toeplitz seed length mismatch')
    # Integer arithmetic keeps local work proportional to t*n, bounded above.
    out = []
    for r in range(tag_bits):
        parity = 0
        base = n - 1 + r
        for c, bit in enumerate(bits):
            if bit == '1' and seed_bits[base - c] == '1':
                parity ^= 1
        out.append(str(parity))
    return ''.join(out)


def fresh_seed(bit_count: int) -> str:
    """Generate independent public randomness (must be sampled after inputs)."""
    if type(bit_count) is not int or not 1 <= bit_count <= MAX_BITS + MAX_TAG_BITS - 1:
        raise ValueError('invalid public seed length')
    return format(secrets.randbits(bit_count), f'0{bit_count}b')


def _encode_frame(session_id: bytes, seed: str, tag: str, n: int, t: int) -> bytes:
    return json.dumps({
        'session': session_id.hex(), 'seq': 0, 'kind': 'confirmation',
        'key_bits': n, 'tag_bits': t, 'public_seed': seed, 'tag': tag,
    }, sort_keys=True, separators=(',', ':')).encode('ascii')


def confirm_fixed_inputs(
    alice_bits: str,
    bob_bits: str,
    *,
    session_id: bytes,
    authentication_key: bytes,
    tag_bits: int = 40,
    wire_hook: Callable[[bytes, bytes], tuple[bytes, bytes]] | None = None,
    seed_source: Callable[[int], str] = fresh_seed,
) -> ConfirmationReport:
    """Authenticate and check a fresh-seed Toeplitz confirmation.

    This simulator holds both parties' inputs to test local public discussion;
    the receiver independently computes its tag. The sender's tag is public.
    An injected seed_source is for tests only and cannot qualify production.
    Raises ConfirmationError on any failure, never returns secret bits.
    """
    _validate_parameters(alice_bits, bob_bits, tag_bits, session_id, authentication_key)
    n = len(alice_bits)
    # Inputs are already fixed before selecting an independent public seed.
    seed = seed_source(n + tag_bits - 1)
    if not isinstance(seed, str) or len(seed) != n + tag_bits - 1 or set(seed) - {'0', '1'}:
        raise ConfirmationError('invalid public seed')
    sender_tag = toeplitz_confirmation_tag(alice_bits, seed, tag_bits)
    frame = _encode_frame(session_id, seed, sender_tag, n, tag_bits)
    mac = hmac.digest(authentication_key, DOMAIN + frame, 'sha256')
    if wire_hook is not None:
        frame, mac = wire_hook(frame, mac)
    if not isinstance(frame, bytes) or not isinstance(mac, bytes):
        raise ConfirmationError('invalid authenticated wire types')
    expected_mac = hmac.digest(authentication_key, DOMAIN + frame, 'sha256')
    if not hmac.compare_digest(expected_mac, mac):
        raise ConfirmationError('authentication failed')
    try:
        obj = json.loads(frame)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ConfirmationError('invalid message') from exc
    if not isinstance(obj, dict) or set(obj) != {'session', 'seq', 'kind', 'key_bits', 'tag_bits', 'public_seed', 'tag'}:
        raise ConfirmationError('invalid frame fields')
    if (obj['session'] != session_id.hex() or type(obj['seq']) is not int or obj['seq'] != 0
            or obj['kind'] != 'confirmation' or type(obj['key_bits']) is not int
            or obj['key_bits'] != n or type(obj['tag_bits']) is not int
            or obj['tag_bits'] != tag_bits or obj['public_seed'] != seed
            or obj['tag'] != sender_tag):
        raise ConfirmationError('session, sequence, or transcript mismatch')
    receiver_tag = toeplitz_confirmation_tag(bob_bits, obj['public_seed'], tag_bits)
    if not hmac.compare_digest(receiver_tag, obj['tag']):
        raise ConfirmationError('confirmation mismatch: discard reconciled keys')
    return ConfirmationReport(
        decision='CONFIRMATION_PASS_UNQUALIFIED', raw_key_bits=n,
        confirmation_tag_bits_disclosed=tag_bits,
        public_seed_bits=n + tag_bits - 1,
        epsilon_correctness_bound=f'2^-{tag_bits}',
        authenticated_messages=1, session_bound=True,
        independent_seed_sampled_after_inputs=True,
    )


def public_report(report: ConfirmationReport) -> dict:
    """Serialize only public metadata, never keys, hash tags, or MAC material."""
    return asdict(report)
