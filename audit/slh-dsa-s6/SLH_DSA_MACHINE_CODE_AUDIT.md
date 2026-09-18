# SLH-DSA Optimized Machine-Code Audit

## Scope

This S6.2d audit examines optimized release machine code for the
secret-bearing SLH-DSA PRF boundaries.

Audited wrappers:

- `audit_slh_shake_prf`
- `audit_slh_shake_prf_msg`
- `audit_slh_sha2_prf`
- `audit_slh_sha2_prf_msg`
- `audit_slh_sha2_128_prf_msg`

The wrappers are compiled with release optimization, `target-cpu=native`,
debug information sufficient for audit recovery, frame pointers enabled,
stable `#[inline(never)]` wrapper boundaries, and `black_box` around
sensitive inputs.

This audit is compiler-, target-, and configuration-specific. It is not a
formal constant-time proof.

## Configuration Coverage

The SHAKE wrappers exercise the SHAKE256 PRF and PRF_msg implementations.

The SHA2 wrappers exercise:

- `PRF` with `n = 32`;
- `PRF_msg` with `n = 32`, selecting HMAC-SHA-512;
- `PRF_msg` with `n = 16`, selecting HMAC-SHA-256.

The `n = 24` SHA2 PRF_msg configuration follows the same HMAC-SHA-512
implementation family as `n = 32`.

## Results

| Wrapper | Conditional branches | Conditional selects | Divisions | Table lookups | Secret-indexed memory |
|---|---:|---:|---:|---:|---:|
| `audit_slh_shake_prf` | 1 | 0 | 0 | 0 | 0 found |
| `audit_slh_shake_prf_msg` | 1 | 0 | 0 | 0 | 0 found |
| `audit_slh_sha2_prf` | 1 | 0 | 0 | 0 | 0 found |
| `audit_slh_sha2_prf_msg` | 1 | 0 | 0 | 0 | 0 found |
| `audit_slh_sha2_128_prf_msg` | 1 | 0 | 0 | 0 | 0 found |

## Branch Classification

Each wrapper contains one conditional branch following the underlying PRF or
PRF_msg call.

The generated-code sequence is structurally:

    call PRF/PRF_msg
    load Result discriminant
    compare discriminant
    branch to error/expect path

Source review establishes that the corresponding error results depend on
public configuration and length validation: configured hash-output length,
input lengths, output-buffer length, and supported parameter configuration.

No returned error condition derives from the contents of `SK.seed`, `SK.prf`,
or optional signing randomness.

The observed branches are therefore classified as public
validation/error-path branches, not secret-dependent branches.

## Memory-Address Classification

The conservative scanner reported operands such as fixed-offset
`[sp, #constant]` and `[x29, #constant]` accesses. These are stack/frame
accesses rather than secret-derived indexed-memory accesses.

No secret-derived indexed-memory access was identified in the five audited
wrappers.

## Findings

### S6.2d-F1 — SHAKE PRF

**PASS.** No secret-dependent branch or secret-indexed memory access
identified.

### S6.2d-F2 — SHAKE PRF_msg

**PASS.** No secret-dependent branch or secret-indexed memory access
identified.

### S6.2d-F3 — SHA2 PRF

**PASS.** No secret-dependent branch or secret-indexed memory access
identified.

### S6.2d-F4 — SHA2 PRF_msg, HMAC-SHA-512 path

**PASS.** No secret-dependent branch or secret-indexed memory access
identified.

### S6.2d-F5 — SHA2 PRF_msg, HMAC-SHA-256 path

**PASS.** No secret-dependent branch or secret-indexed memory access
identified.

### S6.2d-F6 — Arithmetic and Lookup Candidates

**PASS.** No conditional-select, division, or table-lookup instructions were
identified in the five audited wrappers.

## Claim Boundary

This audit establishes generated-machine-code evidence for selected SLH-DSA
PRF boundaries on the recorded compiler, host, target, and optimization
configuration.

It does not establish:

- a formal constant-time proof;
- equivalence across compiler versions or architectures;
- fixed-time execution of complete SLH-DSA signing.

Complete SLH-DSA signing remains intentionally public/transcript-variable-time.
