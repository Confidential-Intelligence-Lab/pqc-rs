# SLH-DSA Dynamic Secret-Taint Audit

## Scope

This S6.2f audit evaluates secret-dependent execution in selected SLH-DSA
PRF boundaries using Linux Valgrind Memcheck client requests.

Secret buffers are explicitly marked undefined with
`VALGRIND_MAKE_MEM_UNDEFINED` before cryptographic execution and restored
with `VALGRIND_MAKE_MEM_DEFINED` afterward.

A Valgrind diagnostic therefore indicates that secret definedness reached
an operation requiring a defined value, including conditional control flow
or memory addressing.

This is dynamic execution evidence, not a formal proof of constant-time
behavior.

## Environment

The audit executes in GitHub Actions on Linux using Valgrind Memcheck.

Public CI run:

- repository: `Confidential-Intelligence-Lab/pqc-rs`
- workflow: `SLH-DSA S6 Secret Taint`
- run ID: `35054904228`

## Positive Control

An intentional branch on a tainted byte is executed before the cryptographic
cases.

**Result: PASS — Valgrind detected the positive-control secret-dependent
branch.**

The cryptographic zero-finding results are therefore supported by an active
taint mechanism rather than an unverified instrumentation path.

## Results

| Case | Secret material marked undefined | Result |
|---|---|---|
| Positive control | one branch-controlling byte | DETECTED |
| SHAKE PRF | `SK.seed` | PASS |
| SHAKE PRF_msg | `SK.prf`, optional randomness | PASS |
| SHA2 PRF | `SK.seed` | PASS |
| SHA2 PRF_msg (`n=32`) | `SK.prf`, optional randomness | PASS |
| SHA2 PRF_msg (`n=16`) | `SK.prf`, optional randomness | PASS |

## Findings

### S6.2f-F1 — Positive Control

**PASS.** The intentionally secret-dependent branch triggered Valgrind,
confirming that the client-request taint mechanism was operational.

### S6.2f-F2 — SHAKE PRF

**PASS.** No Valgrind secret-taint finding was reported.

### S6.2f-F3 — SHAKE PRF_msg

**PASS.** No Valgrind secret-taint finding was reported.

### S6.2f-F4 — SHA2 PRF

**PASS.** No Valgrind secret-taint finding was reported.

### S6.2f-F5 — SHA2 PRF_msg, HMAC-SHA-512 path

**PASS.** No Valgrind secret-taint finding was reported.

### S6.2f-F6 — SHA2 PRF_msg, HMAC-SHA-256 path

**PASS.** No Valgrind secret-taint finding was reported.

## Claim Boundary

This audit provides Linux dynamic secret-dependency evidence for the selected
SLH-DSA PRF and PRF_msg configurations.

It does not constitute a formal non-interference proof and does not establish
fixed-time execution of complete SLH-DSA signing.

The result complements source dependency review, optimized machine-code
inspection, and statistical fixed-vs-varying timing screening.
