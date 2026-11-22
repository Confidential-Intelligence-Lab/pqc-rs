"""S3.B experimental strict BB84 entry point and durable session-ID burn.

The root authentication secret is supplied by the caller, not generated from BB84
measurements. The registry prevents local re-use after process restart but does
not attest provisioning, stop rollback of external storage, or prove QKD secrecy.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from m2a_authenticated_distillation import run_distillation


class StrictSessionError(ValueError):
    """Invalid strict invocation, unsafe registry, or reused session identifier."""


def burn_session_id(registry_dir: str | Path, key_id: str, session_id: bytes) -> None:
    """Atomically and durably reserve (public key ID, session ID) before acquisition.

    Registry directory must already exist and be owned by this UID with mode
    0700. An O_EXCL marker, written before returning, persists over restarts.
    Storage snapshots, directory deletion, and cross-host duplication are out of scope.
    """
    if type(key_id) is not str or not 1 <= len(key_id) <= 64 or not key_id.isascii() or not all(
        c.isalnum() or c in '._-' for c in key_id
    ):
        raise StrictSessionError('invalid public key identifier')
    if type(session_id) is not bytes or not 16 <= len(session_id) <= 64:
        raise StrictSessionError('invalid session identifier')
    if not isinstance(registry_dir, (str, Path)):
        raise StrictSessionError('invalid registry directory')
    path = os.fspath(registry_dir)
    if not path or not os.path.isabs(path):
        raise StrictSessionError('registry path must be absolute')
    dir_flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        dfd = os.open(path, dir_flags)
    except OSError as exc:
        raise StrictSessionError('cannot open private registry directory') from exc
    try:
        st = os.fstat(dfd)
        import stat
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise StrictSessionError('registry must be owned by caller and private (0700)')
        marker = hashlib.sha256(b'pqc-rs/qkd/s3b/session/v1\x00' +
                                key_id.encode('ascii') + b'\x00' + session_id).hexdigest()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
        try:
            fd = os.open(marker, flags, 0o600, dir_fd=dfd)
        except FileExistsError as exc:
            raise StrictSessionError('session ID has already been consumed') from exc
        except OSError as exc:
            raise StrictSessionError('cannot reserve session ID') from exc
        try:
            os.write(fd, b'BURNED\n')
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(dfd)
    finally:
        os.close(dfd)


def run_strict_distillation(alice, bob, *, authentication_key: bytes,
                            key_id: str, session_id: bytes, registry_dir: str | Path,
                            n_key: int, k_test: int, max_transmissions: int,
                            **options) -> dict:
    """Invoke BB84 with supplied credentials and a one-use persistent session ID.

    No interface in this module can produce an authorized QKD-derived HPKE PSK.
    """
    if type(authentication_key) is not bytes or len(authentication_key) < 32:
        raise StrictSessionError('externally supplied root key of >=32 bytes required')
    forbidden = {'authentication_key', 'session_id', 'strict_provisioned',
                 'selection_seed', 'selection_streams', 'demo_pre_leak_min_entropy_bits', 'hook', 'precommit_digest'}
    if forbidden.intersection(options):
        raise StrictSessionError('strict path forbids overriding credentials or demo/fixture inputs')
    burn_session_id(registry_dir, key_id, session_id)
    return _run_strict_after_burn(
        alice, bob, authentication_key=authentication_key, key_id=key_id,
        session_id=session_id, registry_dir=registry_dir,
        n_key=n_key, k_test=k_test, max_transmissions=max_transmissions, **options)


def _run_strict_after_burn(alice, bob, *, authentication_key: bytes,
                           key_id: str, session_id: bytes, registry_dir: str | Path,
                           n_key: int, k_test: int, max_transmissions: int,
                           precommit_digest: str | None = None, **options) -> dict:
    # Internal post-burn path used after strict burn or S4.E handshake.
    scoped_key = hmac.digest(authentication_key,
                             b'pqc-rs/qkd/s3b/key-identity/v1\x00' + key_id.encode('ascii'),
                             'sha256')
    # S3.C-2a: the actual H2 messages now cross independent Alice/Bob
    # authenticated transcript states; they are not merely logged afterward.
    from s3c_authenticated_transcript import TranscriptSession
    from m1h2_authenticated_sampling import _matched
    a_bases = [r.basis for r in alice]
    b_bases = [r.basis for r in bob]
    quota_met = (len(_matched(a_bases, b_bases, 1)) >= n_key and
                 len(_matched(a_bases, b_bases, 0)) >= k_test)
    # Strict successful n_key >= 128 proceeds through S3.C-2b under one
    # digest chain. The bounded syndrome frame count is fixed before H2 starts.
    ec_blocks = (n_key + 127) // 128 if type(n_key) is int and n_key >= 128 else 0
    schedule_id = ('h2-ec-pa-v1' if quota_met and ec_blocks else
                   'h2-pass-v1' if quota_met else 'h2-abort-quota-v1')
    ctx = dict(root=scoped_key, key_id=key_id, session_id=session_id,
               alice_id='alice', bob_id='bob', schedule_id=schedule_id)
    if schedule_id == 'h2-ec-pa-v1':
        ctx['reconciliation_blocks'] = ec_blocks
    if precommit_digest is not None:
        ctx['precommit_digest'] = precommit_digest
    transcript_pair = (TranscriptSession(role='alice', **ctx),
                       TranscriptSession(role='bob', **ctx))
    result = run_distillation(alice, bob, n_key=n_key, k_test=k_test,
                              max_transmissions=max_transmissions,
                              authentication_key=scoped_key,
                              session_id=session_id, strict_provisioned=True,
                              s3c_pair=transcript_pair, **options)
    if result.get('hpke_export_authorized') is not False or result.get('security_qualified') is not False:
        raise StrictSessionError('downstream qualification invariant violated')
    # Burned state is intentionally retained on every failure and abort.
    result['replay_tracking_persistent'] = True
    result['provisioning_origin_verified'] = False
    return result
