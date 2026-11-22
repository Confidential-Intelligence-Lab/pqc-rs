"""S4.F: source-circuit structural audit and constrained BB84 acquisition adapter.

Research simulator only. Neither AST matching nor CUDA-Q tests attest a physical
quantum source, Eve independence, or composable secrecy. No key material exported.
"""
from __future__ import annotations

import ast
from pathlib import Path

from m1h3a_randomness import RandomnessConfiguration, RandomnessStreams, simulate_records
from s3b_persistent_strict_path import StrictSessionError
from s4e_proof_precommit import ProofProfile, run_precommitted_distillation

# Parse without importing CUDA-Q, so structural checks work on CPU-only hosts.
_EXPECTED_BODY = '''
if bit == 1:
    x(q)
if preparation_basis == 1:
    h(q)
if measurement_basis == 1:
    h(q)
mz(q)
'''


def audit_prepare_and_measure(path: str | Path | None = None) -> dict:
    """Enforce exact BB84 gate sequence, rejecting unreviewed circuit changes.

    This audit is structural only, NOT a measured state-fidelity certificate.
    """
    source = Path(path) if path is not None else Path(__file__).with_name('bb84_cudaq.py')
    tree = ast.parse(source.read_text(encoding='utf-8'))
    candidates = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                  and node.name == 'prepare_and_measure']
    if len(candidates) != 1 or not isinstance(candidates[0], ast.FunctionDef):
        raise StrictSessionError('missing or ambiguous BB84 quantum kernel')
    node = candidates[0]
    if (len(node.decorator_list) != 1 or ast.unparse(node.decorator_list[0]) != 'cudaq.kernel'):
        raise StrictSessionError('BB84 quantum kernel decorator changed')
    if ([a.arg for a in node.args.args] != ['bit', 'preparation_basis', 'measurement_basis']
            or node.args.defaults or node.args.vararg or node.args.kwarg):
        raise StrictSessionError('BB84 quantum kernel signature changed')
    expected = ast.parse('q = cudaq.qubit()\n' + _EXPECTED_BODY).body
    if ast.dump(ast.Module(body=node.body, type_ignores=[]), include_attributes=False) != ast.dump(
            ast.Module(body=expected, type_ignores=[]), include_attributes=False):
        raise StrictSessionError('BB84 quantum kernel gate sequence changed; manual review required')
    # Gate pattern: |b> -> H^a -> H^m -> Z measurement.
    return {'circuit_structure_matches_ideal_model': True,
            'basis_encoding': {'Z': 0, 'X': 1},
            'theoretical_matched_basis_error_probability': 0.0,
            'theoretical_mismatched_basis_one_probability': 0.5,
            'quantum_source_attested': False,
            'security_model_validated': False,
            'security_qualified': False,
            'hpke_export_authorized': False}


class ProfiledAcquisition:
    """Constrained simulator adapter: committed parameters used at every call.

    Optional measure injection exists for tests; it never qualifies the source.
    """
    def __init__(self, *, measure=None):
        if measure is not None and not callable(measure):
            raise StrictSessionError('invalid diagnostic measurement callback')
        self._measure = measure

    def __call__(self, profile: ProofProfile):
        if type(profile) is not ProofProfile:
            raise StrictSessionError('acquisition requires exact proof profile')
        audit_prepare_and_measure()
        streams = RandomnessStreams(RandomnessConfiguration(mode='os', fixture_seed=None))
        if streams.mode != profile.randomness_mode:
            raise StrictSessionError('acquisition randomness mode mismatches proof profile')
        return simulate_records(
            n_z=profile.k_test,
            k_x=profile.n_key,
            max_transmissions=profile.max_transmissions,
            randomness=streams,
            z_probability=profile.z_probability_ppm / 1000000,
            intercept_percent=0,
            measure=self._measure,
        )


def run_profiled_simulation(*, proof_profile: ProofProfile,
                            authentication_key: bytes, key_id: str,
                            session_id: bytes, registry_dir,
                            bob_expected_profile: ProofProfile | None = None,
                            measure=None) -> dict:
    """Acquire via fixed S4.F adapter after authenticated S4.E precommitment.

    Not a qualified QKD path: source and OS randomness are not attested.
    """
    adapter = ProfiledAcquisition(measure=measure)
    result = run_precommitted_distillation(
        adapter, proof_profile=proof_profile,
        authentication_key=authentication_key, key_id=key_id,
        session_id=session_id, registry_dir=registry_dir,
        bob_expected_profile=bob_expected_profile)
    result['s4f_source_adapter_enforced'] = True
    result['s4f_circuit_structure_reviewed'] = True
    result['s4f_source_attested'] = False
    result['security_model_validated'] = False
    result['security_qualified'] = False
    result['hpke_export_authorized'] = False
    result['qkd_psk_available'] = False
    return result
