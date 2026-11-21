"""S3.A experimental provisioned-key authentication with session lifecycle guards.

No source is attested: caller supplies a pre-shared secret outside the QKD
simulation. Volatile replay tracking is process-local, not crash-persistent.
The presence of a valid MAC never certifies quantum entropy or HPKE export.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import hashlib
import hmac
import json
import secrets

DOMAIN = b'pqc-rs/qkd/s3a/authentication-lifecycle/v1\x00'
STAGES = ('sifting', 'parameter_estimation', 'reconciliation', 'confirmation', 'privacy_amplification')
MAX_PAYLOAD = 65536


class LifecycleError(ValueError):
    """Invalid provisioning, stage transition, authenticated frame, or replay."""


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def _hkdf_expand(prk: bytes, info: bytes, size: int = 32) -> bytes:
    if size > 32:
        raise LifecycleError('unsupported derived key size')
    return hmac.digest(prk, info + b'\x01', 'sha256')[:size]


@dataclass(frozen=True)
class LifecycleReport:
    """Public-only evidence that does not imply authenticated-key provenance."""
    session_bound: bool
    authenticated_messages_sent: int
    authenticated_messages_received: int
    session_closed: bool
    replay_tracking_persistent: bool = False
    provisioning_origin_verified: bool = False
    authentication_failure_bound_proven: bool = False
    quantum_min_entropy_certified: bool = False
    security_model_validated: bool = False
    security_qualified: bool = False
    hpke_export_authorized: bool = False


class ProvisionedKeyStore:
    """Holds externally supplied secret key material and volatile session IDs.

    No key is generated from QKD observations. The caller remains responsible
    for independent entropy, secure provisioning, key rotation, and crash-safe
    session registry persistence. Do not treat this API as an HSM.
    """
    def __init__(self, key: bytes, key_id: str):
        if type(key) is not bytes or len(key) < 32:
            raise LifecycleError('externally provisioned secret must have >=32 bytes')
        if type(key_id) is not str or not 1 <= len(key_id) <= 64 or not key_id.isascii() or not all(
                c.isalnum() or c in '._-' for c in key_id):
            raise LifecycleError('invalid public key identifier')
        self._root = bytearray(key)
        self.key_id = key_id
        self._seen: set[bytes] = set()
        self._destroyed = False

    def open(self, session_id: bytes, role: str) -> 'AuthSession':
        if self._destroyed:
            raise LifecycleError('key store destroyed')
        if type(session_id) is not bytes or not 16 <= len(session_id) <= 64:
            raise LifecycleError('session ID must be 16-64 bytes')
        if role not in ('alice', 'bob'):
            raise LifecycleError('invalid role')
        if session_id in self._seen:
            raise LifecycleError('session ID reuse prohibited for this key')
        self._seen.add(session_id)  # burn the ID even if later phases abort
        # HKDF-Extract with domain/key-id/session salt; distinct independent session keys.
        salt = hashlib.sha256(DOMAIN + b'extract\x00' + self.key_id.encode('ascii') + session_id).digest()
        prk = hmac.digest(salt, bytes(self._root), 'sha256')
        session_key = _hkdf_expand(prk, DOMAIN + b'session\x00' + session_id)
        return AuthSession(bytearray(session_key), session_id, self.key_id, role)

    def destroy(self) -> None:
        for i in range(len(self._root)):
            self._root[i] = 0
        self._destroyed = True
        # Do not clear seen: no session IDs become reusable via destroy().


class AuthSession:
    """Directional HMAC-SHA256 frames with transcript, stage and replay binding."""
    def __init__(self, key: bytearray, sid: bytes, key_id: str, role: str):
        self._key = key
        self._sid = sid.hex()
        self._kid = key_id
        self._role = role
        self._closed = False
        self._seq = {'alice': 0, 'bob': 0}
        self._stage = {'alice': -1, 'bob': -1}
        initial = hashlib.sha256(DOMAIN + b'chain\x00' + sid).digest()
        self._chain = {'alice': initial, 'bob': initial}
        self._sent = 0
        self._received = 0

    def _require_live(self) -> None:
        if self._closed:
            raise LifecycleError('session closed')

    def _validate_stage(self, sender: str, stage: str) -> int:
        if stage not in STAGES:
            raise LifecycleError('unsupported stage; HPKE handoff never authorized here')
        index = STAGES.index(stage)
        if index < self._stage[sender]:
            raise LifecycleError('stage rollback')
        return index

    def _mac_key(self, sender: str, stage: str) -> bytes:
        return _hkdf_expand(bytes(self._key), DOMAIN + b'mac\x00' + sender.encode() + b'\x00' + stage.encode())

    def _advance(self, sender: str, stage_number: int, body: bytes, tag: bytes) -> None:
        self._chain[sender] = hashlib.sha256(self._chain[sender] + body + tag).digest()
        self._seq[sender] += 1
        self._stage[sender] = stage_number

    def send(self, stage: str, payload: bytes) -> tuple[bytes, bytes]:
        self._require_live()
        if type(payload) is not bytes or len(payload) > MAX_PAYLOAD:
            raise LifecycleError('invalid payload')
        position = self._validate_stage(self._role, stage)
        body = _canonical({'version': 1, 'sid': self._sid, 'kid': self._kid,
                           'sender': self._role, 'stage': stage,
                           'seq': self._seq[self._role],
                           'prev': self._chain[self._role].hex(),
                           'payload_hex': payload.hex()})
        tag = hmac.digest(self._mac_key(self._role, stage), DOMAIN + body, 'sha256')
        self._advance(self._role, position, body, tag)
        self._sent += 1
        return body, tag

    def receive(self, body: bytes, tag: bytes) -> tuple[str, bytes]:
        self._require_live()
        if type(body) is not bytes or len(body) > 2 * MAX_PAYLOAD + 1024 or type(tag) is not bytes or len(tag) != 32:
            raise LifecycleError('invalid frame')
        try:
            frame = json.loads(body)
            if type(frame) is not dict or _canonical(frame) != body or set(frame) != {
                'version', 'sid', 'kid', 'sender', 'stage', 'seq', 'prev', 'payload_hex'
            }:
                raise ValueError('noncanonical frame')
            sender = frame['sender']
            if sender not in ('alice', 'bob') or sender == self._role:
                raise ValueError('invalid sender')
            if (type(frame['version']) is not int or frame['version'] != 1 or
                    frame['sid'] != self._sid or frame['kid'] != self._kid or
                    type(frame['seq']) is not int or frame['seq'] != self._seq[sender] or
                    frame['prev'] != self._chain[sender].hex()):
                raise ValueError('invalid session / sequence / transcript')
            stage = frame['stage']
            position = self._validate_stage(sender, stage)
            if type(frame['payload_hex']) is not str or len(frame['payload_hex']) > 2 * MAX_PAYLOAD:
                raise ValueError('invalid payload size')
            data = bytes.fromhex(frame['payload_hex'])
            if data.hex() != frame['payload_hex']:
                raise ValueError('noncanonical payload')
        except (ValueError, TypeError, KeyError, UnicodeError, LifecycleError) as exc:
            raise LifecycleError('invalid authenticated frame') from exc
        expected = hmac.digest(self._mac_key(sender, stage), DOMAIN + body, 'sha256')
        if not hmac.compare_digest(expected, tag):
            raise LifecycleError('MAC verification failed')
        self._advance(sender, position, body, tag)
        self._received += 1
        return stage, data

    def report(self) -> LifecycleReport:
        return LifecycleReport(True, self._sent, self._received, self._closed)

    def close(self) -> None:
        if not self._closed:
            for i in range(len(self._key)):
                self._key[i] = 0
            self._closed = True


def self_check() -> None:
    """Exercise paired endpoints; report only unqualified safety markers."""
    sid = secrets.token_bytes(24)
    pre_shared = secrets.token_bytes(32)  # TEST FIXTURE ONLY, not attested provisioning
    alice_store = ProvisionedKeyStore(pre_shared, 's3a-fixture-v1')
    bob_store = ProvisionedKeyStore(pre_shared, 's3a-fixture-v1')
    alice = alice_store.open(sid, 'alice')
    bob = bob_store.open(sid, 'bob')
    frame, tag = alice.send('sifting', b'public basis choices')
    assert bob.receive(frame, tag) == ('sifting', b'public basis choices')
    alice.close(); bob.close(); alice_store.destroy(); bob_store.destroy()
    print(json.dumps(asdict(alice.report()), sort_keys=True, indent=2))
    print('QKD_S3A_AUTHENTICATION_LIFECYCLE_STATUS=PASS')
    print('QKD_S3A_PROVISIONING_ORIGIN_VERIFIED=false')
    print('QKD_S3A_SECURITY_MODEL_VALIDATED=false')
    print('QKD_S3A_HPKE_EXPORT_AUTHORIZED=false')


if __name__ == '__main__':
    self_check()
