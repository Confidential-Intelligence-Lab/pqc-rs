"""S5.B: fail-closed source/protocol correspondence diagnostics, NOT a proof.

Finite-prefix observations, public abort filtering, and equation arguments are
checked separately. No model security or production HPKE export is authorized.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import ast

from s2b2_strict_theorem_reference import assess_prefix


class CorrespondenceError(ValueError):
    pass


@dataclass(frozen=True)
class CouplingWitness:
    decision: str
    transmissions: int
    stop_index: int | None
    cap: int
    x_count: int
    z_count: int
    k_min: int
    k_actual: int
    public_filter_eligible: bool
    accepted_history_prefix_matches: bool
    numerical_k_equals_precommitted_k: bool
    quantum_coupling_proven: bool = False
    entropy_proven: bool = False
    security_qualified: bool = False
    hpke_export_authorized: bool = False


def analyze_prefix(alice, bob, *, n_key: int, k_test: int,
                   max_transmissions: int, numerical_k: int | None = None) -> dict:
    """Evaluate *observed* first-hit/cap correspondence for a finite record trace.

    This cannot prove a coupling of interactive quantum processes or Eve's
    general quantum side information. Accepted-prefix equality is purely
    classical for a given pair of immutable record sequences.
    """
    if numerical_k is None:
        numerical_k = k_test
    if type(numerical_k) is not int or numerical_k < 1:
        raise CorrespondenceError('numerical sample size must be a positive integer')
    p = assess_prefix(alice, bob, n_key=n_key, k_test=k_test,
                      max_transmissions=max_transmissions)
    accepted = p.decision == 'PREFIX_CONFORMS_UNQUALIFIED'
    if p.decision == 'REJECT_POST_STOP_RECORDS':
        verdict = 'REJECT_POST_STOP_RECORDS'
    elif accepted:
        verdict = ('CLASSICAL_PREFIX_MATCH_NUMERICAL_K_UNREVIEWED' if
                   numerical_k == p.matched_z and numerical_k != k_test else
                   'CLASSICAL_PREFIX_MATCH_NONCERTIFYING')
    else:
        verdict = 'ABORT_QUOTAS_NOT_MET'
    witness = CouplingWitness(
        decision=verdict, transmissions=p.records_received,
        stop_index=p.first_quota_hit_index, cap=max_transmissions,
        x_count=p.matched_x, z_count=p.matched_z,
        k_min=k_test, k_actual=p.matched_z,
        public_filter_eligible=accepted and p.first_quota_hit_index is not None
                               and p.first_quota_hit_index < max_transmissions,
        accepted_history_prefix_matches=accepted,
        numerical_k_equals_precommitted_k=numerical_k == k_test,
    )
    out = asdict(witness)
    out.update(stage='S5B_FINITE_PREFIX_CORRESPONDENCE',
               proof_obligations_open=[
                   'TLGR_SUPPLEMENTARY_HYPOTHESES_REVIEW',
                   'GENERAL_EVE_CAUSAL_QUANTUM_CAP_COUPLING',
                   'RANDOM_TEST_SIZE_THEOREM_OR_PREDECLARED_K_CONVENTION',
                   'AUTHENTICATED_ABORT_AND_DISCLOSURE_TIMING',
                   'PREPARATION_DETECTION_MEMORYLESSNESS_ASSUMPTIONS',
                   'CONDITIONAL_MIN_ENTROPY_FOR_ACCEPTED_BRANCH',
               ],
               theorem_applicability_proven=False,
               security_model_validated=False,
               qkd_psk_available=False)
    return out


def audit_h2_numerical_argument(path: str | Path | None = None) -> dict:
    """AST-audit that H2 passes observed Z size, not theorem profile minimum.

    Presence of an AST call does not imply theorem applicability. Detect a
    source change and require manual security review rather than guessing.
    """
    path = Path(path) if path is not None else Path(__file__).with_name('m1h2_authenticated_sampling.py')
    tree = ast.parse(path.read_text(encoding='utf-8'))
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'BoundInput':
            calls.append(node)
    # First call validates supplied params; second computes published diagnostic.
    if len(calls) != 2:
        raise CorrespondenceError('H2 numerical call sites changed; manual review required')
    if len(calls[1].args) < 2 or not isinstance(calls[1].args[1], ast.Name):
        raise CorrespondenceError('H2 numerical sample input changed; manual review required')
    observed_name = calls[1].args[1].id
    if observed_name != 'actual_z_test_size':
        raise CorrespondenceError('H2 sample-size mapping changed; manual review required')
    return {
        'stage': 'S5B_H2_NUMERICAL_SOURCE_AUDIT',
        'observed_sample_argument': observed_name,
        'precommitted_theorem_k_argument': 'k_test',
        'uses_observed_k_for_diagnostic': True,
        'observed_k_substitution_theorem_justified': False,
        'suggested_next_step': 'Keep diagnostic unqualified; establish lemma or use predeclared k_min',
        'theorem_applicability_proven': False,
        'security_qualified': False,
        'hpke_export_authorized': False,
    }
