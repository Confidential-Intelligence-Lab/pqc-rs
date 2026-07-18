#!/usr/bin/env python3
from __future__ import annotations
import hashlib, hmac
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEM_IDS = {"ML-KEM-512": 0x0040, "ML-KEM-768": 0x0041, "ML-KEM-1024": 0x0042}
KDF_ID = 0x0001  # HKDF-SHA256
AEAD_ID = 0x0001 # AES-128-GCM
NH, NK, NN = 32, 16, 12


def i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * NH, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length > 255 * NH:
        raise ValueError("HKDF output too long")
    out, t = bytearray(), b""
    for counter in range(1, (length + NH - 1) // NH + 1):
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out.extend(t)
    return bytes(out[:length])


def suite_id(parameter_set: str) -> bytes:
    return b"HPKE" + i2osp(KEM_IDS[parameter_set], 2) + i2osp(KDF_ID, 2) + i2osp(AEAD_ID, 2)


def labeled_extract(salt: bytes, label: bytes, ikm: bytes, sid: bytes) -> bytes:
    return hkdf_extract(salt, b"HPKE-v1" + sid + label + ikm)


def labeled_expand(prk: bytes, label: bytes, info: bytes, length: int, sid: bytes) -> bytes:
    return hkdf_expand(prk, i2osp(length, 2) + b"HPKE-v1" + sid + label + info, length)


@dataclass(frozen=True)
class Context:
    suite_id: bytes
    key: bytes
    base_nonce: bytes
    exporter_secret: bytes
    key_schedule_context: bytes
    sequence: int = 0

    def nonce(self) -> bytes:
        seq = i2osp(self.sequence, NN)
        return bytes(a ^ b for a, b in zip(self.base_nonce, seq))

    def seal(self, aad: bytes, plaintext: bytes) -> tuple[bytes, "Context"]:
        ciphertext = AESGCM(self.key).encrypt(self.nonce(), plaintext, aad)
        return ciphertext, Context(
            self.suite_id,
            self.key,
            self.base_nonce,
            self.exporter_secret,
            self.key_schedule_context,
            self.sequence + 1,
        )

    def open(self, aad: bytes, ciphertext: bytes) -> tuple[bytes, "Context"]:
        plaintext = AESGCM(self.key).decrypt(self.nonce(), ciphertext, aad)
        return plaintext, Context(
            self.suite_id,
            self.key,
            self.base_nonce,
            self.exporter_secret,
            self.key_schedule_context,
            self.sequence + 1,
        )

    def export(self, exporter_context: bytes, length: int) -> bytes:
        return labeled_expand(
            self.exporter_secret,
            b"sec",
            exporter_context,
            length,
            self.suite_id,
        )


def setup_base(parameter_set: str, shared_secret: bytes, info: bytes) -> Context:
    sid = suite_id(parameter_set)
    psk_id_hash = labeled_extract(b"", b"psk_id_hash", b"", sid)
    info_hash = labeled_extract(b"", b"info_hash", info, sid)
    key_schedule_context = b"\x00" + psk_id_hash + info_hash
    secret = labeled_extract(shared_secret, b"secret", b"", sid)
    key = labeled_expand(secret, b"key", key_schedule_context, NK, sid)
    base_nonce = labeled_expand(secret, b"base_nonce", key_schedule_context, NN, sid)
    exporter_secret = labeled_expand(secret, b"exp", key_schedule_context, NH, sid)
    return Context(sid, key, base_nonce, exporter_secret, key_schedule_context)
