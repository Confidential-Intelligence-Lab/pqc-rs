"""S3.C-1 reference authenticated public transcript (UNQUALIFIED).

Standalone model-conformance fixture, not yet wired into H2/S2.A2/M2.A.
No quantum entropy certification or QKD-derived HPKE export is implemented.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json

DOMAIN = b'pqc-rs/qkd/s3c/transcript/v1\x00'
PROTOCOL = 'pqc-rs/bb84/idealized/v1'
PROFILE = 'qst1-research-v1'
MAX_PAYLOAD = 4000000  # bounded support for up to 100k public basis announcements
# Fixed reference trace retained for backwards compatibility.
SCHEDULE = (
    ('parameters', 'alice'), ('parameters', 'bob'),
    ('sifting', 'alice'), ('sifting', 'bob'),
    ('parameter_estimation', 'alice'), ('parameter_estimation', 'bob'),
    ('reconciliation', 'alice'), ('reconciliation', 'bob'),
    ('confirmation', 'alice'), ('confirmation', 'bob'),
    ('privacy_amplification', 'alice'), ('privacy_amplification', 'bob'),
    ('close', 'alice'), ('close', 'bob'),
)

# Actual H2/M1.H2 exchange. Separate success/abort schedules make omitted
# frames and unauthorized stage transitions reject before receiver processing.
H2_PASS = (
    ('h2_alice_bases', 'alice'), ('h2_bob_bases', 'bob'),
    ('h2_quota_status', 'alice'),
    ('h2_x_key_selection', 'alice'), ('h2_z_test_selection', 'alice'),
    ('h2_z_test_bits_alice', 'alice'), ('h2_z_test_bits_bob', 'bob'),
    ('h2_z_error_summary', 'bob'), ('h2_final_decision', 'alice'),
)
H2_ABORT_QUOTA = (
    ('h2_alice_bases', 'alice'), ('h2_bob_bases', 'bob'),
    ('h2_abort', 'alice'),
)
SCHEDULES = {'reference-v1': SCHEDULE, 'h2-pass-v1': H2_PASS,
             'h2-abort-quota-v1': H2_ABORT_QUOTA}
MAX_EC_BLOCKS = 512


PA_STAGES = (('pa_parameters', 'alice'), ('pa_ack', 'bob'), ('pa_commit', 'alice'))
PROOF_STAGES = (('proof_profile', 'alice'), ('proof_ack', 'bob'))


def distillation_schedule(blocks: int) -> tuple[tuple[str, str], ...]:
    """Bounded authenticated H2 -> EC -> confirmation -> commit schedule."""
    if type(blocks) is not int or not 1 <= blocks <= MAX_EC_BLOCKS:
        raise TranscriptError('invalid reconciliation block count')
    return (H2_PASS + (('ec_syndrome', 'alice'),) * blocks +
            (('ec_confirmation', 'alice'), ('ec_ack', 'bob'),
             ('ec_commit', 'alice')))


def full_distillation_schedule(blocks: int) -> tuple[tuple[str, str], ...]:
    """Extend the same authenticated chain through the PA planning exchange."""
    return distillation_schedule(blocks) + PA_STAGES


class TranscriptError(ValueError):
    """Invalid credentials, state, canonical encoding, authentication or replay."""


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _label(value: str, name: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 64 or not value.isascii() or not all(
        c.isalnum() or c in '._-' for c in value
    ):
        raise TranscriptError('invalid ' + name)
    return value


@dataclass(frozen=True)
class PublicStatus:
    event_count: int
    transcript_digest: str
    closed: bool
    aborted: bool
    security_model_validated: bool = False
    security_qualified: bool = False
    hpke_export_authorized: bool = False


class TranscriptSession:
    """Per-peer authenticated transcript with a single global event sequence.

    Both parties independently construct sessions from the same externally
    provisioned >=32-byte shared secret. Keys remain outside wire frames.
    The sender must deliver each frame before either side advances again.
    Underlying key origin, durable replay protection and cryptographic bounds
    are NOT established by this class.
    """

    def __init__(self, *, root: bytes, key_id: str, session_id: bytes,
                 role: str, alice_id: str, bob_id: str,
                 schedule_id: str = 'reference-v1',
                 reconciliation_blocks: int | None = None,
                 precommit_digest: str | None = None):
        if type(root) is not bytes or len(root) < 32:
            raise TranscriptError('requires externally provided root >=32 bytes')
        if type(session_id) is not bytes or not 16 <= len(session_id) <= 64:
            raise TranscriptError('session ID must be 16..64 bytes')
        if role not in ('alice', 'bob'):
            raise TranscriptError('invalid endpoint role')
        if schedule_id == 's4e-proof-v1' and reconciliation_blocks is None and precommit_digest is None:
            self._schedule = PROOF_STAGES
        elif schedule_id == 'h2-ec-pa-v1':
            self._schedule = full_distillation_schedule(reconciliation_blocks)
        elif schedule_id == 'h2-ec-v1':
            self._schedule = distillation_schedule(reconciliation_blocks)
        elif schedule_id in SCHEDULES and reconciliation_blocks is None:
            self._schedule = SCHEDULES[schedule_id]
        else:
            raise TranscriptError('unsupported schedule profile or block count')
        self._context = {
            'protocol_id': PROTOCOL, 'profile_id': PROFILE, 'version': 1,
            'key_id': _label(key_id, 'key ID'), 'sid': session_id.hex(),
            'alice_id': _label(alice_id, 'alice ID'),
            'bob_id': _label(bob_id, 'bob ID'),
        }
        if schedule_id != 'reference-v1':
            self._context['schedule_id'] = schedule_id
        if schedule_id in ('h2-ec-v1', 'h2-ec-pa-v1'):
            self._context['reconciliation_blocks'] = reconciliation_blocks
        if precommit_digest is not None:
            if (schedule_id not in ('h2-ec-pa-v1', 'h2-pass-v1', 'h2-abort-quota-v1') or type(precommit_digest) is not str or
                    len(precommit_digest) != 64 or
                    any(c not in '0123456789abcdef' for c in precommit_digest)):
                raise TranscriptError('invalid or unsupported precommitment binding')
            self._context['precommit_digest'] = precommit_digest
        if self._context['alice_id'] == self._context['bob_id']:
            raise TranscriptError('distinct endpoint identities required')
        self._role = role
        self._pos = 0
        self._closed = False
        self._aborted = False
        ctx = canonical(self._context)
        salt = hashlib.sha256(DOMAIN + b'extract\x00' + ctx).digest()
        prk = hmac.digest(salt, root, 'sha256')
        self._key = bytearray(hmac.digest(prk, DOMAIN + b'frame-mac\x00' + ctx + b'\x01', 'sha256'))
        self._digest = hashlib.sha256(DOMAIN + b'initial\x00' + ctx).digest()

    def _live(self) -> None:
        if self._aborted or self._closed:
            raise TranscriptError('terminal session')

    def _erase(self) -> None:
        for i in range(len(self._key)):
            self._key[i] = 0

    def abort(self) -> None:
        self._aborted = True
        self._erase()

    def _advance(self, body: bytes, tag: bytes) -> None:
        self._digest = hashlib.sha256(DOMAIN + b'chain\x00' + self._digest + body + tag).digest()
        self._pos += 1
        if self._pos == len(self._schedule):
            self._closed = True
            self._erase()

    def send(self, stage: str, payload: bytes) -> tuple[bytes, bytes]:
        self._live()
        if type(payload) is not bytes or len(payload) > MAX_PAYLOAD:
            self.abort()
            raise TranscriptError('invalid public payload')
        if self._pos >= len(self._schedule) or self._schedule[self._pos] != (stage, self._role):
            self.abort()
            raise TranscriptError('out-of-order local send')
        frame = dict(self._context, stage=stage, sender=self._role,
                     sequence=self._pos, previous_digest=self._digest.hex(),
                     payload_hex=payload.hex())
        body = canonical(frame)
        tag = hmac.digest(bytes(self._key), DOMAIN + b'mac\x00' + body, 'sha256')
        self._advance(body, tag)
        return body, tag

    def receive(self, body: bytes, tag: bytes) -> tuple[str, bytes]:
        self._live()
        try:
            if type(body) is not bytes or len(body) > (2 * MAX_PAYLOAD + 2048):
                raise ValueError('bad frame length')
            if type(tag) is not bytes or len(tag) != 32:
                raise ValueError('bad tag')
            frame = json.loads(body)
            required = set(self._context) | {
                'stage', 'sender', 'sequence', 'previous_digest', 'payload_hex'
            }
            if type(frame) is not dict or set(frame) != required or canonical(frame) != body:
                raise ValueError('invalid canonical frame')
            if any(type(frame[k]) is not type(v) or frame[k] != v
                   for k, v in self._context.items()):
                raise ValueError('session or profile mismatch')
            if type(frame['sequence']) is not int or frame['sequence'] != self._pos:
                raise ValueError('stale or skipped sequence')
            if frame['previous_digest'] != self._digest.hex():
                raise ValueError('transcript fork')
            if type(frame['stage']) is not str or type(frame['sender']) is not str:
                raise ValueError('malformed role or stage')
            if frame['sender'] == self._role or self._schedule[self._pos] != (
                frame['stage'], frame['sender']
            ):
                raise ValueError('unexpected sender or stage')
            raw = frame['payload_hex']
            if type(raw) is not str or len(raw) > 2 * MAX_PAYLOAD:
                raise ValueError('malformed payload')
            payload = bytes.fromhex(raw)
            if payload.hex() != raw:
                raise ValueError('noncanonical payload hex')
            expected = hmac.digest(bytes(self._key), DOMAIN + b'mac\x00' + body, 'sha256')
            if not hmac.compare_digest(tag, expected):
                raise ValueError('MAC mismatch')
        except (ValueError, TypeError, KeyError, UnicodeError, IndexError) as exc:
            self.abort()
            raise TranscriptError('authenticated transcript verification failed') from exc
        self._advance(body, tag)
        return frame['stage'], payload

    def status(self) -> PublicStatus:
        return PublicStatus(self._pos, self._digest.hex(), self._closed, self._aborted)
