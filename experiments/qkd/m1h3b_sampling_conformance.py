"""H3.B diagnostic: OS/fixture randomness carried through authenticated H2 selection.

NO theorem-conformance or security qualification. The quota-acquisition scheme is
still not shown to have the sampling/stopping distribution of TLGR 2012 Box 1.
"""
from __future__ import annotations

import argparse
import json
import math
import secrets

from m1h3a_randomness import RandomnessConfiguration, RandomnessStreams, simulate_records
from m1h2_authenticated_sampling import run_records


def experiment(*, n_key: int, k_test: int, max_transmissions: int,
               randomness_mode: str = "os", fixture_seed: int | None = None,
               oversample: int = 2, z_probability: float = .5,
               intercept_percent: int = 0, q_tolerance: float = .05,
               measure=None, hook=None) -> dict:
    """End-to-end simulated acquisition + authenticated H2 with shared RNG config.

    Oversampling ensures selected subsets are not necessarily the entire matched
    populations. It is NOT a substitute for matching the published stopping rule.
    """
    if type(oversample) is not int or oversample < 1:
        raise ValueError("oversample must be positive integer")
    if type(n_key) is not int or n_key < 1 or type(k_test) is not int or k_test < 1:
        raise ValueError("invalid key/test quotas")
    if type(max_transmissions) is not int or max_transmissions < 1 or max_transmissions > 100000:
        raise ValueError("invalid transmission bound")
    if n_key * oversample + k_test * oversample > max_transmissions:
        raise ValueError("transmission cap lower than acquisition quotas")
    if type(q_tolerance) not in (float, int) or not math.isfinite(q_tolerance) or not 0 <= q_tolerance <= .5:
        raise ValueError("invalid error threshold")
    randomness = RandomnessStreams(RandomnessConfiguration(randomness_mode, fixture_seed))
    if measure is None:
        import cudaq
        if randomness_mode == "fixture":
            cudaq.set_random_seed(fixture_seed)
        else:
            cudaq.set_random_seed(secrets.randbits(32))
    alice, bob = simulate_records(n_z=k_test * oversample,
                                  k_x=n_key * oversample,
                                  max_transmissions=max_transmissions,
                                  randomness=randomness,
                                  z_probability=z_probability,
                                  intercept_percent=intercept_percent,
                                  measure=measure)
    result = run_records(alice, bob, n_key=n_key, k_test=k_test,
                         max_transmissions=max_transmissions,
                         q_tolerance=q_tolerance,
                         selection_streams=randomness,
                         hook=hook)
    if result['decision'] == 'ABORT_QUOTAS':
        return dict(result, randomness_mode=randomness_mode,
                    protocol_randomness_integrated=True,
                    theorem_stopping_rule_validated=False,
                    theorem_sampling_distribution_validated=False,
                    security_qualified=False)
    return dict(result, randomness_mode=randomness_mode,
                acquisition_x_quota=n_key * oversample,
                acquisition_z_quota=k_test * oversample,
                selection_population_x_at_least=n_key * oversample,
                selection_population_z_at_least=k_test * oversample,
                protocol_randomness_integrated=True,
                selection_randomness_os_backed=randomness_mode == 'os',
                classical_authentication_key_independently_provisioned=False,
                theorem_stopping_rule_validated=False,
                theorem_sampling_distribution_validated=False,
                security_model_validated=False,
                security_qualified=False,
                hpke_export_authorized=False)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=('os', 'fixture'), default='os')
    p.add_argument('--fixture-seed', type=int)
    p.add_argument('--n-key', type=int, default=32)
    p.add_argument('--k-test', type=int, default=32)
    p.add_argument('--oversample', type=int, default=2)
    p.add_argument('--max-transmissions', type=int, default=2048)
    p.add_argument('--z-probability', type=float, default=.5)
    p.add_argument('--intercept-percent', type=int, default=0)
    p.add_argument('--q-tolerance', type=float, default=.05)
    a = p.parse_args()
    result = experiment(n_key=a.n_key, k_test=a.k_test,
                        max_transmissions=a.max_transmissions,
                        randomness_mode=a.mode, fixture_seed=a.fixture_seed,
                        oversample=a.oversample, z_probability=a.z_probability,
                        intercept_percent=a.intercept_percent,
                        q_tolerance=a.q_tolerance)
    print(json.dumps(result, indent=2, sort_keys=True))
    print('QKD_M1H3B_RANDOMNESS_AUTH_INTEGRATION_STATUS=PASS')
    print('QKD_M1H3B_THEOREM_SAMPLING_VALIDATED=false')
    print('QKD_M1H3B_SECURITY_MODEL_VALIDATED=false')
    if result['decision'] != 'PARAMETER_ESTIMATION_PASS_UNQUALIFIED':
        raise SystemExit(2)


if __name__ == '__main__':
    main()
