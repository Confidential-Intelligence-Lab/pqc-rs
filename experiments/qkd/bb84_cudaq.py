#!/usr/bin/env python3
"""Experimental circuit-level BB84 producer for the Rust paired-key HPKE demo.

Not a security-qualified QKD implementation. No optical losses, authenticated
public discussion, information reconciliation, privacy-amplification proof,
finite-key security, or side-channel modeling is implemented. The SHA-256
compression below is a demonstration fixture derivation, NOT secure QKD.
Never supply generated keys to production systems or publish fixture contents.
"""
import argparse
import hashlib
import os
from pathlib import Path
import random
import stat
import sys

import cudaq


@cudaq.kernel
def prepare_and_measure(bit: int, preparation_basis: int, measurement_basis: int):
    q = cudaq.qubit()
    if bit == 1:
        x(q)
    if preparation_basis == 1:
        h(q)
    if measurement_basis == 1:
        h(q)
    mz(q)


def measured_bit(bit: int, prep: int, basis: int) -> int:
    counts = cudaq.sample(prepare_and_measure, bit, prep, basis, shots_count=1)
    outcome = next(iter(counts))
    if outcome not in ("0", "1"):
        raise RuntimeError(f"unexpected measurement output {outcome!r}")
    return int(outcome)


def run(bits: int, seed: int, intercept_percent: int):
    rng = random.Random(seed)  # reproducible simulator experiment, NOT cryptographic RNG
    cudaq.set_random_seed(seed)
    sift_alice = []
    sift_bob = []
    for _ in range(bits):
        a_bit = rng.randrange(2)
        a_basis = rng.randrange(2)
        b_basis = rng.randrange(2)
        if rng.randrange(100) < intercept_percent:
            eve_basis = rng.randrange(2)
            eve_bit = measured_bit(a_bit, a_basis, eve_basis)
            observed = measured_bit(eve_bit, eve_basis, b_basis)
        else:
            observed = measured_bit(a_bit, a_basis, b_basis)
        if a_basis == b_basis:
            sift_alice.append(a_bit)
            sift_bob.append(observed)
    errors = sum(a != b for a, b in zip(sift_alice, sift_bob))
    return sift_alice, sift_bob, errors


def packed_bits(bits):
    result = bytearray((len(bits) + 7) // 8)
    for index, value in enumerate(bits):
        result[index // 8] |= value << (7 - index % 8)
    return bytes(result)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bits", type=int, default=1024)
    ap.add_argument("--seed", type=int, default=20261120)
    ap.add_argument("--intercept-percent", type=int, default=0)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    if args.bits < 512 or not 0 <= args.intercept_percent <= 100:
        ap.error("require at least 512 transmissions and intercept percentage in [0,100]")
    a, b, errors = run(args.bits, args.seed, args.intercept_percent)
    sifted = len(a)
    qber = errors / sifted if sifted else 0.0
    print(f"BB84_TRANSMITTED={args.bits}")
    print(f"BB84_SIFTED={sifted}")
    print(f"BB84_ERRORS={errors}")
    print(f"BB84_QBER={qber:.8f}")
    print(f"BB84_INTERCEPT_PERCENT={args.intercept_percent}")
    if args.intercept_percent:
        print("BB84_DIAGNOSTIC_ATTACK_MODE=PASS")
        if args.output:
            raise SystemExit("refusing to export paired keys from an eavesdropping diagnostic")
        return
    if errors != 0 or a != b or sifted < 256:
        raise SystemExit("BB84_FIXTURE_STATUS=REJECT: nonmatching or insufficient sifted material")
    if args.output is None:
        print("BB84_IDEAL_BASELINE_STATUS=PASS")
        return
    # Domain-separated deterministic *fixture* compression. Not a QKD proof.
    digest = hashlib.sha256(b"pqc-rs/bb84-cudaq/insecure-fixture/v1\x00" + len(a).to_bytes(8, 'big') + packed_bits(a)).digest()
    key_id = f"cudaq-bb84-{args.seed}-{args.bits}"
    # File intentionally contains BOTH parties' shared secret as a fixture.
    # Creation is exclusive and mode 0600. Delete promptly after use.
    text = ("QKD_SIM_FIXTURE_V1\n"
            f"key_id={key_id}\n"
            "provenance=cudaq-bb84-insecure-fixture\n"
            f"transmissions={args.bits}\n"
            f"sifted={sifted}\n"
            f"errors={errors}\n"
            f"secret_hex={digest.hex()}\n")
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(text)
    print("BB84_EXPERIMENTAL_FIXTURE_STATUS=PASS")
    print(f"BB84_FIXTURE_PATH={args.output}")


if __name__ == "__main__":
    main()
