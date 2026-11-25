#!/usr/bin/env python3
"""Independent Base-mode HPKE interoperability reference."""

import hashlib
import hmac
import json
import secrets
import subprocess
import sys

from pathlib import Path

import cryptography

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends.openssl.backend import backend

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


INFO = b"pqc-rs/independent-provider/hpke/v1"
AAD = b"independent-provider-aad"

MSG1 = bytes.fromhex("2143658709")
MSG2 = b"second authenticated message"

EXPORT_CONTEXT = b"independent-provider-export"

KEMS = {
    "pure": 0x0041,
    "hybrid": 0x647A,
}

KDFS = {
    "sha2": (0x0001, hashlib.sha256),
    "sha3": (0xFF01, hashlib.sha3_256),
}

# Exact revision-pinned X25519/ML-KEM combiner label.
HYBRID_LABEL = bytes.fromhex("5c2e2f2f5e5c")

TRIALS = 32


def u16(value):
    return value.to_bytes(2, "big")


def derive_seed(kind, ikm):
    label = b"DeriveKeyPair"

    length = 64 if kind == "pure" else 32

    data = (
        ikm
        + b"HPKE-v1"
        + b"KEM"
        + u16(KEMS[kind])
        + u16(len(label))
        + label
        + u16(length)
    )

    return hashlib.shake_256(data).digest(length)


def private_keys(kind, seed):
    if kind == "pure":
        assert len(seed) == 64

        return (
            MLKEM768PrivateKey.from_seed_bytes(seed),
            None,
        )

    assert len(seed) == 32

    material = hashlib.shake_256(seed).digest(96)

    return (
        MLKEM768PrivateKey.from_seed_bytes(material[:64]),
        X25519PrivateKey.from_private_bytes(material[64:]),
    )


def public_bytes(keys):
    pq, traditional = keys

    result = pq.public_key().public_bytes_raw()

    if traditional is not None:
        result += traditional.public_key().public_bytes_raw()

    return result


def combine(pq_secret, x_secret, x_ct, x_pk):
    assert len(pq_secret) == 32
    assert len(x_secret) == 32
    assert len(x_ct) == 32
    assert len(x_pk) == 32

    return hashlib.sha3_256(
        pq_secret
        + x_secret
        + x_ct
        + x_pk
        + HYBRID_LABEL
    ).digest()


def encapsulate(kind, pk):
    expected = 1184 if kind == "pure" else 1216
    assert len(pk) == expected

    pq_public = MLKEM768PublicKey.from_public_bytes(
        pk[:1184]
    )

    pq_secret, pq_ct = pq_public.encapsulate()

    assert len(pq_ct) == 1088

    if kind == "pure":
        return pq_secret, pq_ct

    x_pk = pk[1184:]

    ephemeral = X25519PrivateKey.generate()

    x_ct = ephemeral.public_key().public_bytes_raw()

    x_secret = ephemeral.exchange(
        X25519PublicKey.from_public_bytes(x_pk)
    )

    secret = combine(
        pq_secret, x_secret, x_ct, x_pk
    )

    return secret, pq_ct + x_ct


def decapsulate(kind, keys, enc):
    pq, traditional = keys

    expected = 1088 if kind == "pure" else 1120
    assert len(enc) == expected

    pq_secret = pq.decapsulate(enc[:1088])

    if kind == "pure":
        return pq_secret

    x_ct = enc[1088:]

    x_secret = traditional.exchange(
        X25519PublicKey.from_public_bytes(x_ct)
    )

    x_pk = traditional.public_key().public_bytes_raw()

    return combine(
        pq_secret, x_secret, x_ct, x_pk
    )


def extract(hash_fn, salt, ikm):
    if not salt:
        salt = bytes(32)

    return hmac.new(salt, ikm, hash_fn).digest()


def expand(hash_fn, prk, info, length):
    assert len(prk) >= 32
    assert 0 <= length <= 255 * 32

    output = bytearray()
    block = b""

    for counter in range(1, (length + 31) // 32 + 1):
        block = hmac.new(
            prk,
            block + info + bytes([counter]),
            hash_fn,
        ).digest()

        output.extend(block)

    return bytes(output[:length])


def schedule(kind, kdf, secret):
    kdf_id, hash_fn = KDFS[kdf]

    suite = (
        b"HPKE"
        + u16(KEMS[kind])
        + u16(kdf_id)
        + u16(0x0002)
    )

    def lextract(salt, label, ikm):
        return extract(
            hash_fn,
            salt,
            b"HPKE-v1" + suite + label + ikm,
        )

    def lexpand(prk, label, info, length):
        return expand(
            hash_fn,
            prk,
            u16(length)
            + b"HPKE-v1"
            + suite
            + label
            + info,
            length,
        )

    context = (
        b"\x00"
        + lextract(b"", b"psk_id_hash", b"")
        + lextract(b"", b"info_hash", INFO)
    )

    intermediate = lextract(secret, b"secret", b"")

    key = lexpand(intermediate, b"key", context, 32)

    nonce = lexpand(
        intermediate, b"base_nonce", context, 12
    )

    exporter = lexpand(intermediate, b"exp", context, 32)

    exported = lexpand(
        exporter,
        b"sec",
        EXPORT_CONTEXT,
        64,
    )

    return key, nonce, exported


def nonce_for(base, sequence):
    encoded = sequence.to_bytes(12, "big")

    return bytes(
        lhs ^ rhs for lhs, rhs in zip(base, encoded)
    )


def encrypt_pair(kind, kdf, secret):
    key, base_nonce, exported = schedule(kind, kdf, secret)

    aead = AESGCM(key)

    ct1 = aead.encrypt(nonce_for(base_nonce, 0), MSG1, AAD)
    ct2 = aead.encrypt(nonce_for(base_nonce, 1), MSG2, AAD)

    return ct1, ct2, exported


def must_reject(operation):
    try:
        operation()
    except InvalidTag:
        return

    raise AssertionError("Authentication unexpectedly succeeded")


def decrypt_pair(kind, kdf, secret, ct1, ct2):
    key, base_nonce, exported = schedule(kind, kdf, secret)

    aead = AESGCM(key)

    nonce0 = nonce_for(base_nonce, 0)

    must_reject(
        lambda: aead.decrypt(nonce0, ct1, b"wrong aad")
    )

    modified = bytes([ct1[0] ^ 1]) + ct1[1:]

    must_reject(
        lambda: aead.decrypt(nonce0, modified, AAD)
    )

    other = "sha3" if kdf == "sha2" else "sha2"

    wrong_key, wrong_nonce, _ = schedule(
        kind, other, secret
    )

    must_reject(
        lambda: AESGCM(wrong_key).decrypt(
            wrong_nonce, ct1, AAD
        )
    )

    assert aead.decrypt(nonce0, ct1, AAD) == MSG1

    assert aead.decrypt(
        nonce_for(base_nonce, 1), ct2, AAD
    ) == MSG2

    return exported


def main():
    binary = Path(sys.argv[1]).resolve()
    destination = Path(sys.argv[2])

    process = subprocess.Popen(
        [str(binary)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    def request(*fields):
        process.stdin.write(" ".join(fields) + "\n")
        process.stdin.flush()

        response = process.stdout.readline()

        assert response, "Rust interoperability process failed"

        return response.strip().split()

    results = []

    try:
        for kind in KEMS:
            for kdf in KDFS:
                seen = set()

                for trial in range(TRIALS):
                    # Independently derive a fresh synthetic
                    # recipient key pair in both providers.
                    ikm = secrets.token_bytes(64)

                    seed = derive_seed(kind, ikm)
                    keys = private_keys(kind, seed)
                    public = public_bytes(keys)

                    rust_seed, rust_public = map(
                        bytes.fromhex,
                        request("keys", kind, ikm.hex()),
                    )

                    assert rust_seed == seed
                    assert rust_public == public

                    # Direction 1: Rust sender,
                    # independent OpenSSL receiver.

                    enc, ct1, ct2, rust_export = map(
                        bytes.fromhex,
                        request(
                            "send",
                            kind,
                            kdf,
                            public.hex(),
                        ),
                    )

                    assert enc not in seen
                    seen.add(enc)

                    assert len(ct1) == len(MSG1) + 16
                    assert len(ct2) == len(MSG2) + 16

                    secret = decapsulate(kind, keys, enc)

                    independent_export = decrypt_pair(
                        kind, kdf, secret, ct1, ct2
                    )

                    assert rust_export == independent_export

                    results.append({
                        "kem": kind,
                        "kdf": kdf,
                        "trial": trial,
                        "direction": "pqc-rs-to-openssl",
                        "messages": 2,
                        "negative_checks": 3,
                        "status": "PASS",
                    })

                    # Direction 2: independent OpenSSL sender,
                    # Rust receiver.

                    secret, enc = encapsulate(kind, public)

                    assert enc not in seen
                    seen.add(enc)

                    ct1, ct2, independent_export = encrypt_pair(
                        kind, kdf, secret
                    )

                    status, rust_export = request(
                        "receive",
                        kind,
                        kdf,
                        seed.hex(),
                        enc.hex(),
                        ct1.hex(),
                        ct2.hex(),
                    )

                    assert status == "PASS"

                    assert (
                        bytes.fromhex(rust_export)
                        == independent_export
                    )

                    results.append({
                        "kem": kind,
                        "kdf": kdf,
                        "trial": trial,
                        "direction": "openssl-to-pqc-rs",
                        "messages": 2,
                        "negative_checks": 3,
                        "status": "PASS",
                    })

                assert len(seen) == 2 * TRIALS

                print(
                    f"KEM={kind} KDF={kdf} "
                    f"RUST_TO_OPENSSL={TRIALS}/{TRIALS} "
                    f"OPENSSL_TO_RUST={TRIALS}/{TRIALS}",
                    flush=True,
                )

        process.stdin.close()

        assert process.wait(timeout=30) == 0

    finally:
        if process.poll() is None:
            process.kill()
            process.wait()

    assert len(results) == 256

    report = {
        "reference_provider": "Python cryptography / OpenSSL",
        "cryptography_version": cryptography.__version__,
        "openssl_version": backend.openssl_version_text(),
        "kem_constructions": 2,
        "kdf_algorithms": 2,
        "trials_per_direction_per_suite": TRIALS,
        "independent_recipient_key_derivations": 128,
        "successful_interoperability_cases": len(results),
        "authenticated_messages": sum(
            case["messages"] for case in results
        ),
        "negative_authentication_checks": sum(
            case["negative_checks"] for case in results
        ),
        "mode": "Base",
        "aead": "AES-256-GCM",
        "experimental_kdf_identifier": "0xff01",
        "cases": results,
    }

    destination.write_text(
        json.dumps(report, indent=2) + "\n"
    )

    print("INDEPENDENT_KEY_DERIVATIONS=128")
    print("BIDIRECTIONAL_INTEROPERABILITY_CASES=256")
    print("AUTHENTICATED_MESSAGES=512")
    print("NEGATIVE_AUTHENTICATION_CHECKS=768")
    print("INDEPENDENT_PROVIDER_INTEROPERABILITY=PASS")


if __name__ == "__main__":
    main()
