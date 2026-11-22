"""S5.D-1 read-only research assurance audit; never certifies QKD security.

The independent Bernoulli-error calculation is a *toy robustness illustration*.
It assumes independent equal-rate X-basis bit errors, which the finite-key
protocol and a general quantum adversary DO NOT guarantee.
"""
from __future__ import annotations
import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path

SOURCE_FILES = (
    'm1g3_tomamichel_bound.py',
    'm1h2_authenticated_sampling.py',
    's2a1_universal_confirmation.py',
    's2a2_syndrome_reconciliation.py',
    'm1e2_privacy_amplification.py',
    's3d_authentication_contract.py',
    's5c_research_profile.py',
)

@dataclass(frozen=True)
class AuditInputs:
    n_key: int = 16384
    block_size: int = 128
    max_correctable_per_block: int = 2
    assumed_iid_x_error_rate: float = 0.02
    syndrome_rows: int = 32
    confirmation_tag_bits: int = 64

    def __post_init__(self):
        if (type(self.n_key) is not int or self.n_key < 1 or
            type(self.block_size) is not int or self.block_size < 1 or
            type(self.max_correctable_per_block) is not int or
            not 0 <= self.max_correctable_per_block <= self.block_size or
            type(self.syndrome_rows) is not int or self.syndrome_rows < 1 or
            type(self.confirmation_tag_bits) is not int or not 1 <= self.confirmation_tag_bits <= 256 or
            type(self.assumed_iid_x_error_rate) is not float or
            not math.isfinite(self.assumed_iid_x_error_rate) or
            not 0 <= self.assumed_iid_x_error_rate <= 1):
            raise ValueError('invalid audit input')


def audit(inputs: AuditInputs = AuditInputs(), *, source_dir: str | Path | None = None) -> dict:
    """Produce reproducible evidence inventory; no positive cryptographic flags."""
    if type(inputs) is not AuditInputs:
        raise ValueError('exact AuditInputs required')
    n, b, t, p = (inputs.n_key, inputs.block_size,
                   inputs.max_correctable_per_block, inputs.assumed_iid_x_error_rate)
    sizes = [min(b, n - start) for start in range(0, n, b)]
    def prob_success(size):
        return math.fsum(math.comb(size, j) * p**j * (1-p)**(size-j)
                         for j in range(min(t, size)+1))
    pass_probs = [prob_success(s) for s in sizes]
    # This expression applies only to independent Bernoulli errors per bit.
    session_pass = math.prod(pass_probs)
    root = Path(source_dir) if source_dir is not None else Path(__file__).resolve().parent
    sha256 = {}
    missing = []
    for name in SOURCE_FILES:
        path = root / name
        if path.is_file():
            sha256[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            missing.append(name)
    return {
        'stage': 'S5D1_EVIDENCE_AND_ROBUSTNESS_AUDIT',
        'research_input': asdict(inputs),
        'source_sha256': sha256,
        'missing_source_files': missing,
        'source_inventory_complete': len(missing) == 0,
        'syndrome_disclosure_upper_bits': len(sizes) * inputs.syndrome_rows,
        'confirmation_tag_bits_disclosed': inputs.confirmation_tag_bits,
        'confirmation_collision_probability_candidate': 2.0**(-inputs.confirmation_tag_bits),
        'toy_model': 'INDEPENDENT_BERNOULLI_X_ERRORS_NOT_QKD_SECURITY_EVIDENCE',
        'toy_block_success_probability': pass_probs[0],
        'toy_session_success_probability': session_pass,
        'toy_expected_uncorrectable_blocks': math.fsum(1-v for v in pass_probs),
        'note': 'Assumed X error rate is separate from observed Z QBER. Actual decoder can sometimes alias higher-weight errors; this is the probability every block lies inside the guaranteed correction radius, not an exact session acceptance probability.',
        'theorem_supplement_reviewed': False,
        'quantum_cap_coupling_proven': False,
        'complete_postprocessing_security_reduction_proven': False,
        'multi_mac_authentication_advantage_proven': False,
        'conditional_security_supported': False,
        'security_model_validated': False,
        'security_qualified': False,
        'hpke_export_authorized': False,
        'qkd_psk_available': False,
    }

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    print(json.dumps(audit(source_dir=args.source_dir), indent=2, sort_keys=True))
    print('QKD_S5D1_SECURITY_QUALIFIED=false')
