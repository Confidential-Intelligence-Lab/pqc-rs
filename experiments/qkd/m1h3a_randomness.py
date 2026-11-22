"""M1.H3.A: experimental independent-role randomness for BB84 simulation.

Deterministic mode is an explicitly non-secret reproducibility fixture.
OS mode draws from Python's secrets (OS-backed CSPRNG) but DOES NOT constitute
proof of private independent quantum sources, device security, or QKD secrecy.
No keys, seeds, basis choices, or raw bits are written to the diagnostics.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import secrets
from dataclasses import dataclass
from typing import Callable

from m1g5c1_measurement_transcript import AliceRecord, BobRecord

STREAM_NAMES = ("alice_bits", "alice_bases", "bob_bases", "eve", "sampling")
DRAW_PRECISION = 1 << 53


class RandomnessError(ValueError):
    """Invalid randomness mode, arguments, or measurement result."""


class _SecureStream:
    def randbelow(self, bound: int) -> int:
        return secrets.randbelow(bound)


class _FixtureStream:
    def __init__(self, seed: int, domain: str):
        material = hashlib.sha256(
            b"pqc-rs/qkd/m1h3a/deterministic-fixture/v1\x00"
            + seed.to_bytes(max(1, (seed.bit_length() + 7) // 8), "big")
            + b"\x00" + domain.encode("ascii")
        ).digest()
        self._rng = random.Random(int.from_bytes(material, "big"))

    def randbelow(self, bound: int) -> int:
        return self._rng.randrange(bound)


@dataclass(frozen=True)
class RandomnessConfiguration:
    mode: str = "os"
    fixture_seed: int | None = None


class RandomnessStreams:
    def __init__(self, config: RandomnessConfiguration):
        if config.mode not in ("os", "fixture"):
            raise RandomnessError("mode must be os or fixture")
        if config.mode == "os" and config.fixture_seed is not None:
            raise RandomnessError("OS mode forbids a deterministic seed")
        if config.mode == "fixture" and (
            type(config.fixture_seed) is not int or config.fixture_seed < 0
        ):
            raise RandomnessError("fixture mode requires a nonnegative integer seed")
        self.mode = config.mode
        self._streams = {
            name: (_SecureStream() if config.mode == "os" else
                   _FixtureStream(config.fixture_seed, name))
            for name in STREAM_NAMES
        }

    def randbelow(self, domain: str, bound: int) -> int:
        if domain not in self._streams:
            raise RandomnessError("unknown random-stream domain")
        if type(bound) is not int or bound <= 0:
            raise RandomnessError("random bound must be positive integer")
        return self._streams[domain].randbelow(bound)

    def sample_indices(self, population: int, selected: int) -> tuple[int, ...]:
        if (type(population) is not int or type(selected) is not int or
            population < 0 or not 0 <= selected <= population):
            raise RandomnessError("invalid sampling population or size")
        # Partial Fisher-Yates: exactly uniform without replacement if
        # randbelow() is uniform; sample domain is separate from source choices.
        indices = list(range(population))
        for index in range(selected):
            other = index + self.randbelow("sampling", population - index)
            indices[index], indices[other] = indices[other], indices[index]
        return tuple(indices[:selected])


def _basis(streams: RandomnessStreams, domain: str, z_probability: float) -> int:
    return 0 if streams.randbelow(domain, DRAW_PRECISION) < int(z_probability * DRAW_PRECISION) else 1


def simulate_records(*, n_z: int, k_x: int, max_transmissions: int,
                     randomness: RandomnessStreams, z_probability: float = 0.5,
                     intercept_percent: int = 0,
                     measure: Callable[[int, int, int], int] | None = None
                     ) -> tuple[tuple[AliceRecord, ...], tuple[BobRecord, ...]]:
    """Generate separate Alice/Bob records, preserving H3.A mode boundaries.

    The orchestration sees both records for simulation/testing only; the
    authenticated application protocol must preserve separate peer views.
    """
    for name, value in (("n_z", n_z), ("k_x", k_x),
                        ("max_transmissions", max_transmissions)):
        if type(value) is not int or value <= 0:
            raise RandomnessError(f"{name} must be positive integer")
    if max_transmissions < n_z + k_x or max_transmissions > 100000:
        raise RandomnessError("invalid transmission limit")
    if type(z_probability) not in (int, float) or not math.isfinite(z_probability) or not 0 < z_probability < 1:
        raise RandomnessError("z_probability must be finite and within (0,1)")
    if type(intercept_percent) is not int or not 0 <= intercept_percent <= 100:
        raise RandomnessError("intercept_percent must be in [0,100]")
    if not isinstance(randomness, RandomnessStreams):
        raise RandomnessError("randomness provider required")
    if measure is None:
        from bb84_cudaq import measured_bit
        measure = measured_bit
    a_records: list[AliceRecord] = []
    b_records: list[BobRecord] = []
    z_count = x_count = 0
    while len(a_records) < max_transmissions and (z_count < n_z or x_count < k_x):
        bit = randomness.randbelow("alice_bits", 2)
        a_basis = _basis(randomness, "alice_bases", float(z_probability))
        b_basis = _basis(randomness, "bob_bases", float(z_probability))
        if randomness.randbelow("eve", 100) < intercept_percent:
            e_basis = randomness.randbelow("eve", 2)
            e_bit = measure(bit, a_basis, e_basis)
            if type(e_bit) is not int or e_bit not in (0, 1):
                raise RandomnessError("invalid Eve measurement")
            measured = measure(e_bit, e_basis, b_basis)
        else:
            measured = measure(bit, a_basis, b_basis)
        if type(measured) is not int or measured not in (0, 1):
            raise RandomnessError("invalid Bob measurement")
        a_records.append(AliceRecord(bit, a_basis))
        b_records.append(BobRecord(measured, b_basis))
        if a_basis == b_basis == 0 and z_count < n_z:
            z_count += 1
        elif a_basis == b_basis == 1 and x_count < k_x:
            x_count += 1
    return tuple(a_records), tuple(b_records)


def report(alice: tuple[AliceRecord, ...], bob: tuple[BobRecord, ...],
           randomness: RandomnessStreams, n_z: int, k_x: int) -> dict:
    if not alice or len(alice) != len(bob):
        raise RandomnessError("missing or inconsistent peer records")
    z = x = mismatch = 0
    for a, b in zip(alice, bob):
        if a.basis != b.basis:
            mismatch += 1
        elif a.basis == 0 and z < n_z:
            z += 1
        elif a.basis == 1 and x < k_x:
            x += 1
    return {
        "decision": "QUOTAS_MET" if z == n_z and x == k_x else "ABORT_MAX_TRANSMISSIONS",
        "transmissions": len(alice), "z_accepted": z, "x_accepted": x,
        "basis_mismatches": mismatch,
        "quota_filled_discards": len(alice) - z - x - mismatch,
        "randomness_mode": randomness.mode,
        "source_randomness_os_backed": randomness.mode == "os",
        "public_deterministic_fixture": randomness.mode == "fixture",
        "quantum_measurement_randomness_qualified": False,
        "private_independence_theorem_assumptions_verified": False,
        "authenticated_h2_integration": False,
        "security_model_validated": False, "security_qualified": False,
        "hpke_export_authorized": False,
        "provenance": "CUDA_Q_SIMULATION_NOT_SECURE_QKD",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("os", "fixture"), default="os")
    parser.add_argument("--fixture-seed", type=int)
    parser.add_argument("--n-z", type=int, default=32)
    parser.add_argument("--k-x", type=int, default=32)
    parser.add_argument("--max-transmissions", type=int, default=1024)
    parser.add_argument("--z-probability", type=float, default=0.5)
    parser.add_argument("--intercept-percent", type=int, default=0)
    args = parser.parse_args()
    try:
        source = RandomnessStreams(RandomnessConfiguration(args.mode, args.fixture_seed))
        if args.mode == "fixture":
            import cudaq
            cudaq.set_random_seed(args.fixture_seed)
        a, b = simulate_records(n_z=args.n_z, k_x=args.k_x,
            max_transmissions=args.max_transmissions,
            randomness=source, z_probability=args.z_probability,
            intercept_percent=args.intercept_percent)
        result = report(a, b, source, args.n_z, args.k_x)
    except RandomnessError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    print("QKD_M1H3A_RANDOMNESS_ABSTRACTION_STATUS=PASS")
    print("QKD_M1H3A_SECURITY_MODEL_VALIDATED=false")
    if result["decision"] != "QUOTAS_MET":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
