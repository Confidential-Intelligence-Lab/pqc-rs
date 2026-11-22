"""S2.B1 source-evidence audit for BB84 finite-key certification.

This is a gate AUDIT, never a proof, entropy certificate or PSK exporter.
No external research bibliography is stored in this repository module.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from dataclasses import dataclass, asdict

SOURCE_FILES = (
    'm1h2_authenticated_sampling.py',
    'm1g3_tomamichel_bound.py',
    'm1e3_finite_key.py',
    'm2a_authenticated_distillation.py',
    's2a1_universal_confirmation.py',
    's2a2_syndrome_reconciliation.py',
)

@dataclass(frozen=True)
class Obligation:
    id: str
    state: str
    evidence: str


def audit(source_dir: str | Path, *, n_key: int = 4096, k_test: int = 4096,
          q_tolerance: float = 0.05, syndrome_leak_bits: int = 1024,
          confirmation_leak_bits: int = 40, epsilon_secrecy: float = 1e-10,
          epsilon_correctness: float = 2 ** -40) -> dict:
    root = Path(source_dir)
    sources = {}
    fingerprints = {}
    for name in SOURCE_FILES:
        path = root / name
        if not path.is_file():
            raise ValueError('required source missing: ' + name)
        data = path.read_bytes()
        sources[name] = data.decode('utf-8')
        fingerprints[name] = hashlib.sha256(data).hexdigest()
    h2, g3, fk, m2a, confirm, syndrome = (sources[n] for n in SOURCE_FILES)
    # These are deliberately source-level indicators, not proofs or validations.
    markers = {
        'h2_full_z_disclosure_marker': 'all_eligible_z_disclosed' in h2,
        'h2_actual_z_count_marker': 'eligible_z_count' in h2,
        'g3_numerical_theorem_equation_marker': 'math.sqrt' in g3 and 'phase_bound' in g3,
        'g3_explicit_unqualified_marker': "'protocol_assumptions_verified': False" in g3,
        'finite_key_external_entropy_gate': 'NO_EXTERNALLY_JUSTIFIED_MIN_ENTROPY_BOUND' in fk,
        'm2a_demo_entropy_only': 'HYPOTHETICAL_ONLY_NOT_EVIDENCE' in m2a,
        'm2a_no_export_marker': "'hpke_export_authorized': False" in m2a,
        'm2a_source_simulation_marker': 'CUDA_Q_SIMULATION_NOT_SECURE_QKD' in m2a,
        'm2a_syndrome_integration': 'reconcile_syndromes(' in m2a,
        'm2a_confirmation_leakage_accounted': 'confirmation_leak_bits=ec.confirmation_leakage_upper_bound_bits' in m2a,
        'confirmation_code_present': 'toeplitz' in confirm.lower(),
        'syndrome_code_present': 'syndrome' in syndrome.lower(),
    }
    if not all(markers.values()):
        raise ValueError('source drift or missing fail-closed marker: ' +
                         ', '.join(k for k,v in markers.items() if not v))
    if n_key < 1 or k_test < 1 or syndrome_leak_bits < 0 or confirmation_leak_bits < 0:
        raise ValueError('invalid sample/leakage values')
    from m1g3_tomamichel_bound import BoundInput, evaluate
    numerical = evaluate(BoundInput(n_key=n_key, k_test=k_test,
        q_tolerance=q_tolerance,
        leakage_ec_bits=syndrome_leak_bits,
        epsilon_secrecy=epsilon_secrecy,
        epsilon_correctness=epsilon_correctness,
        preparation_quality=1.0))
    obligations = [
      Obligation('B1-01', 'OPEN', 'Reference protocol equivalence: quota overshoot, full-Z population, optional oversampling and transmission-cap abort require theorem mapping'),
      Obligation('B1-02', 'OPEN', 'Proof that acquisition and selection remain valid against arbitrary Eve with quantum side information; classical sampling checks are insufficient'),
      Obligation('B1-03', 'OPEN', 'Trusted preparation quality q and model of imperfect source, detector, loss and basis-independent detection'),
      Obligation('B1-04', 'OPEN', 'Source randomness, basis choices and independence assumptions under actual acquisition model'),
      Obligation('B1-05', 'OPEN', 'Validated sampling-tail/phase-error bound using theorem parameters and selection/stopping semantics'),
      Obligation('B1-06', 'OPEN', 'Composable allocation of secrecy, smoothing, parameter estimation, correctness and authentication errors'),
      Obligation('B1-07', 'OPEN', 'Authenticated channel key provisioning and reduction of MAC forgery probability'),
      Obligation('B1-08', 'OPEN', 'Reconciliation leakage and universal-hash correctness proof matched to public transcript and decoder'),
      Obligation('B1-09', 'OPEN', 'Independent validation of privacy-amplification extractor and input entropy after all public disclosures'),
      Obligation('B1-10', 'OPEN', 'Trusted secure-key provider and HPKE composition; public claimed flags are not authority'),
    ]
    return {
      'decision': 'THEOREM_CONFORMANCE_NOT_ESTABLISHED',
      'reference_equation': 'Tomamichel-2012-Eq2',
      'source_sha256': fingerprints,
      'implementation_markers': markers,
      'numerical_diagnostic_only': {
          'n_key': n_key, 'k_test': k_test,
          'syndrome_leak_bits': syndrome_leak_bits,
          'confirmation_leak_bits_not_subtracted_twice_in_eq2': confirmation_leak_bits,
          'confirmation_cost_in_eq2_epsilon_correctness_penalty': True,
          'q_tolerance_not_observed_qber': q_tolerance,
          'epsilon_secrecy': epsilon_secrecy,
          'epsilon_correctness': epsilon_correctness,
          'maximum_numerical_key_bits': numerical['maximum_numerical_key_bits'],
          'phase_error_upper': numerical['phase_error_upper'],
          'finite_sample_mu': numerical['mu'],
          'positive_length_is_not_entropy_evidence': True,
      },
      'open_obligations': [asdict(o) for o in obligations],
      'theorem_sampling_validated': False,
      'pre_leak_min_entropy_certified': False,
      'authentication_provisioning_validated': False,
      'security_model_validated': False,
      'security_qualified': False,
      'qkd_psk_available': False,
      'hpke_export_authorized': False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-dir', default=str(Path(__file__).parent))
    p.add_argument('--n-key', type=int, default=4096)
    p.add_argument('--k-test', type=int, default=4096)
    p.add_argument('--q-tolerance', type=float, default=.05)
    p.add_argument('--syndrome-leak', type=int, default=1024)
    p.add_argument('--confirmation-leak', type=int, default=40)
    args = p.parse_args()
    print(json.dumps(audit(args.source_dir, n_key=args.n_key,
         k_test=args.k_test, q_tolerance=args.q_tolerance,
         syndrome_leak_bits=args.syndrome_leak,
         confirmation_leak_bits=args.confirmation_leak), indent=2, sort_keys=True))
    print('QKD_S2B1_THEOREM_AUDIT_STATUS=PASS')
    print('QKD_S2B1_MIN_ENTROPY_CERTIFIED=false')
    print('QKD_S2B1_SECURITY_MODEL_VALIDATED=false')
    print('QKD_S2B1_HPKE_EXPORT_AUTHORIZED=false')

if __name__ == '__main__':
    main()
