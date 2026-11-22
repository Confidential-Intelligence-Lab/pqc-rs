#!/usr/bin/env python3
"""Quota-based BB84 diagnostic simulator (NOT a security-conformant QKD protocol).

Only aggregate counts are returned. Basis announcements and key sampling are NOT
authenticated. Pseudorandom simulation seeds are public/reproducible; results are
not secret keys and MUST NOT be exported to cryptographic applications.
"""
from __future__ import annotations

import argparse
import json
import random
from typing import Callable


def experiment(*, n_z: int, k_x: int, max_transmissions: int, seed: int,
               z_probability: float = 0.5, intercept_percent: int = 0,
               measure: Callable[[int, int, int], int] | None = None) -> dict:
    for name, value in (("n_z", n_z), ("k_x", k_x),
                        ("max_transmissions", max_transmissions)):
        if type(value) is not int or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if max_transmissions < n_z + k_x:
        raise ValueError("max_transmissions cannot be below both quota totals")
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a nonnegative integer")
    if type(z_probability) not in (float, int) or not 0 < z_probability < 1:
        raise ValueError("z_probability must be strictly between zero and one")
    if type(intercept_percent) is not int or not 0 <= intercept_percent <= 100:
        raise ValueError("intercept_percent must be an integer in [0,100]")

    if measure is None:
        import cudaq
        from bb84_cudaq import measured_bit
        cudaq.set_random_seed(seed)
        measure = measured_bit

    rng = random.Random(seed)  # NOT secret cryptographic randomness
    z_matches = x_matches = z_errors = x_errors = mismatches = 0
    transmissions = 0
    # Stop collecting in each basis when its quota is full. The other basis
    # remains active until its own quota is met or the transmission cap is hit.
    while transmissions < max_transmissions and (z_matches < n_z or x_matches < k_x):
        transmissions += 1
        bit = rng.randrange(2)
        a_basis = 0 if rng.random() < z_probability else 1
        b_basis = 0 if rng.random() < z_probability else 1
        if rng.randrange(100) < intercept_percent:
            eve_basis = rng.randrange(2)
            eve_bit = measure(bit, a_basis, eve_basis)
            if type(eve_bit) is not int or eve_bit not in (0, 1):
                raise ValueError("measurement function returned a non-binary Eve bit")
            observed = measure(eve_bit, eve_basis, b_basis)
        else:
            observed = measure(bit, a_basis, b_basis)
        if type(observed) is not int or observed not in (0, 1):
            raise ValueError("measurement function must return a binary integer")
        if a_basis != b_basis:
            mismatches += 1
        elif a_basis == 0 and z_matches < n_z:
            z_matches += 1
            z_errors += (bit != observed)
        elif a_basis == 1 and x_matches < k_x:
            x_matches += 1
            x_errors += (bit != observed)
        # Quota-filled same-basis events are discarded, not counted as mismatch.
    accepted = z_matches + x_matches
    quota_discarded = transmissions - accepted - mismatches
    quotas_met = (z_matches == n_z and x_matches == k_x)
    return {
        "decision": "QUOTAS_MET" if quotas_met else "ABORT_MAX_TRANSMISSIONS",
        "abort_reason": None if quotas_met else "MATCHED_BASIS_QUOTAS_UNMET",
        "transmissions": transmissions,
        "max_transmissions": max_transmissions,
        "z_quota": n_z,
        "x_quota": k_x,
        "z_matched_accepted": z_matches,
        "x_matched_accepted": x_matches,
        "z_errors": z_errors,
        "x_errors": x_errors,
        "z_qber": z_errors / z_matches if z_matches else None,
        "x_qber": x_errors / x_matches if x_matches else None,
        "basis_mismatches": mismatches,
        "quota_filled_discards": quota_discarded,
        "accounting_valid": transmissions == accepted + mismatches + quota_discarded,
        "z_probability": float(z_probability),
        "intercept_percent": intercept_percent,
        "reproducible_public_seed": True,
        "basis_announcement_authenticated": False,
        "theorem_specific_protocol_validated": False,
        "security_model_validated": False,
        "security_qualified": False,
        "hpke_export_authorized": False,
        "provenance": "CUDA_Q_SIMULATION_NOT_SECURE_QKD",
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n-z", type=int, default=256)
    ap.add_argument("--k-x", type=int, default=256)
    ap.add_argument("--max-transmissions", type=int, default=4096)
    ap.add_argument("--seed", type=int, default=20261120)
    ap.add_argument("--z-probability", type=float, default=0.5)
    ap.add_argument("--intercept-percent", type=int, default=0)
    args = ap.parse_args()
    result = experiment(n_z=args.n_z, k_x=args.k_x,
                        max_transmissions=args.max_transmissions,
                        seed=args.seed, z_probability=args.z_probability,
                        intercept_percent=args.intercept_percent)
    print(json.dumps(result, sort_keys=True, indent=2))
    if not result["accounting_valid"]:
        raise SystemExit("QKD_M1G5A_ACCOUNTING_STATUS=FAIL")
    print("QKD_M1G5A_QUOTA_SIFTING_STATUS=PASS")
    print("QKD_M1G5A_SECURITY_MODEL_VALIDATED=false")
    if result["decision"] != "QUOTAS_MET":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
