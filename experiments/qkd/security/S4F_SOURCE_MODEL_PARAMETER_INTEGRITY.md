# S4.F - Quantum source-model conformance and proof-parameter integrity

**Status:** EXPERIMENTAL / UNQUALIFIED - no quantum-security proof or source attestation
**Baseline:** `9fd36b21cc1971cb81030c743d68a76c9300ea7f`, `research/qkd-security-qst1`
**Parent:** S4.E authenticated pre-acquisition proof-profile contract

## Objective and boundary

S4.E authenticates a caller-supplied proof profile before invoking an arbitrary record-acquisition callback. S4.F adds a **separate constrained simulator entry point** whose acquisition arguments are derived solely from the immutable profile. The earlier generic callback entry remains available for research tests and is not recategorized as source-verified. Neither entry point attests hardware, OS RNG independence in an information-theoretic sense, nor the declared quantum assumptions.

## Circuit structural correspondence

`bb84_cudaq.prepare_and_measure` performs `q=cudaq.qubit()`, optional `X` for bit one, optional `H` for preparation basis one, optional `H` for measurement basis one, then `mz`. The ideal states are `|0>`, `|1>`, `|+>`, `|->`. Matching preparation and measurement bases give the encoded bit deterministically in the ideal noiseless circuit; opposite bases produce equiprobable binary results. The new AST-based source guard rejects any change in this precise gate sequence pending review. This is not a quantum measurement fidelity test. The pre-existing `bb84_cudaq.run` remains a deterministic demo, not an S4.F source.

## Enforced acquisition mapping

| Profile field | S4.F adapter mapping | Audit state |
|---|---|---|
| `source_model_id`, `measurement_model_id`, `theorem_id` | Validated by `ProofProfile` on construction | Claimed model only |
| `randomness_mode=os` | New `RandomnessStreams(RandomnessConfiguration('os', None))` | Computational OS-backed stream, not attested |
| `n_key` | `simulate_records(k_x=n_key)` | Fixed before callback |
| `k_test` | `simulate_records(n_z=k_test)` | Fixed before callback |
| `max_transmissions` | `simulate_records(max_transmissions=...)` | Fixed before callback |
| `z_probability_ppm` | `simulate_records(z_probability=ppm/1_000_000)` | Fixed before callback |
| `intercept_percent` | Explicitly zero in constrained adapter | Not a model of general Eve |
| `q_tolerance_ppm` | S4.E -> M2.A H2 (unchanged) | Bound through existing call |
| `epsilon_secrecy`, `epsilon_correctness` | S4.E -> M2.A -> H2 numerical evaluator | **S4.F forwarding fix** |
| `requested_key_bits`, `epsilon_pa`, `confirmation_tag_bits`, `block_size` | S4.E -> M2.A | Bound through existing call |

Tests patch the acquisition function to record arguments without creating simulated quantum data. They do not claim that tests can establish independent randomness, or that the callback cannot be modified by a hostile actor.

## Parameter accounting limitation

H2's TLGR numerical diagnostic uses `epsilon_secrecy` and `epsilon_correctness`; before S4.F, S4.E did not forward either value to M2.A, whose H2 path therefore used defaults. S4.F makes these explicit through both call boundaries. This fixes diagnostic parameter provenance but does **not** turn TLGR Equation (2) into validated entropy evidence.

The finite-key `m1e3_finite_key` conditional evaluator uses `epsilon_pa`, plus separately counted syndrome and confirmation disclosures. Do not confuse this with the TLGR Equation (2) budget convention or subtract a confirmation term twice.

## Remaining proof obligations

- Physical source and measurement attestation, lossy optical model, coherent quantum Eve, independent private quantum randomness, or separated endpoints remain open.
- Exact probability sampling is discrete (`floor(p*2^53)/2^53`) under the current H3.A `_basis` implementation. The proof must distinguish its realized discrete basis probability from the declared `ppm` rational; S4.F does not assert equality.
- `simulate_records` does not expose an independent quantum-source audit log; the single-host callback can be replaced by an adversary with execution privilege.
- Stopping/cap and accepted-branch smooth entropy theorem applicability remain open.
- All security/export flags remain false regardless of test results.

## Acceptance evidence

Run `test_s4f_source_conformance.py`, previous S4.E tests, and all QKD regression tests, then `git diff --check`. Inspect all modified sources and confirm no inadvertent qualification or key export. These are source-level conformance checks, **not** composable security certification.
