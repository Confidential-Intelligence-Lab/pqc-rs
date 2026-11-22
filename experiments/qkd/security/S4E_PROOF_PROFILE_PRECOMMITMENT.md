# S4.E - Authenticated pre-acquisition proof-profile contract

**Status:** EXPERIMENTAL / UNQUALIFIED

**Baseline:** `research/qkd-security-qst1`, commit `4e404d8173a2cad1d71a5301c0fb57bca50437e9`

## Decision

S4.E adds a separate precommitted acquisition API. Unlike the legacy
`run_strict_distillation(alice, bob, ...)`, this API does **not** receive
already-acquired records. It authenticates an immutable proof-profile object
between two simulated peer transcript states **before invoking** the source
acquisition callback. The source callback and two-peer isolation remain
unattested, so this is order/binding evidence, not quantum security evidence.

## Protocol

1. Validate an immutable, explicitly supplied `ProofProfile` containing exact
   theorem, source, measurement and authentication model IDs; OS randomness
   mode; quotas, cap, basis probability, QBER threshold, output length,
   correctness-confirmation size, block size, and proposed epsilon parameters.
2. Burn `(key_id, session_id)` in the durable local registry **before**
   authenticated precommitment or acquisition. No retry of a failed session.
3. Exchange `proof_profile` Alice -> Bob, then `proof_ack` Bob -> Alice,
   optionally rejecting a mismatched independently configured Bob profile,
   using fresh S3.C `s4e-proof-v1` session state. Require matching closed digests.
4. Invoke `acquire_records(profile)` only after both precommit frames succeed.
   Reject any returned record sequence continuing beyond the first quota hit.
5. Start normal S3.C H2/EC/PA session with the **precommitment digest bound
   into its authenticated context and MAC key derivation**. Existing frame
   ordering and strict fail-closed session behavior remain in force.
6. Keep all qualification and HPKE export booleans false regardless of results.

## Critical limitations

- Unless an independently configured `bob_expected_profile` is supplied,
  simulated Bob accepts the validated Alice proposal rather than comparing
  against a separate endpoint policy. The orchestrator cannot establish true
  distributed peer independence.
- The application can still supply a callback that ignores the profile, lies
  about the configured source or uses a deterministic seed. This is not
  detection of malicious acquisition or measurement equipment. It must not be
  described as proof of physical precommitment or source attestation.
- The primary strict API still accepts previously generated records. It is
  deliberately **not** labeled precommitted and remains supported for the
  earlier protocol-regression suites.
- The exact source, measurement and authentication identifiers are selected
  *research assumptions* and not validations or provider certifications.
- The acquisition callback is executed by a single-host orchestrator with
  access to both parties' state; distributed peer isolation is not established.
- S4.E checks callback ordering, session binding and source-record first-hit
  conformance. It does not establish the quantum sampling theorem, the finite-
  key smooth conditional min-entropy lower bound, independent randomness,
  computational MAC composition, or a qualified key provider.
- The selected profile includes `z_probability_ppm` and proposed epsilon
  budgets. The current H2 application uses some legacy fixed defaults for
  its *numerical diagnostic* `m1g3` call. That diagnostic is still unqualified;
  the S4.E evidence must not be interpreted as complete equation-profile
  enforcement. A later incremental audit should align every numerical
  diagnostic parameter with the precommitted values.

## Security invariant

`security_model_validated=false`, `security_qualified=false`,
`hpke_export_authorized=false`, `qkd_psk_available=false` always.

## Tests

`python3 -m unittest discover -s experiments/qkd -p 'test_s4e_proof_precommitment.py' -v`

## Next research task

Independently attest or explicitly formalize the acquisition-callback and
source-randomness assumptions; align precommitted proof-budget parameters
with all downstream theorem diagnostic APIs; review actual TLGR lemma hypotheses.
