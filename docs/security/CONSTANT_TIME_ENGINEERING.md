# Constant-Time Engineering Standard

## 1. Purpose

This standard defines repository-wide requirements for implementing,
reviewing, and validating cryptographic code intended to avoid secret-dependent
timing and memory-access behavior.

It applies to:

- ML-KEM;
- ML-DSA;
- SLH-DSA;
- HPKE;
- hybrid constructions;
- shared arithmetic, encoding, sampling, and key-management code.

## 2. Security objective

For operations that process secret key material, secret polynomial
coefficients, secret intermediate values, or secret-dependent randomness, the
implementation must avoid:

- secret-dependent conditional branches;
- secret-dependent loop bounds;
- secret-indexed memory accesses;
- secret-dependent allocation behavior;
- secret-dependent error paths;
- variable-time division or remainder when operand latency is architecture
  dependent;
- compiler transformations that reintroduce secret-dependent control flow.

This standard does not require constant runtime across public inputs,
parameter sets, malformed input handling, or rejection-sampling iteration
counts unless those differences can reveal secret information.

## 3. Data classification

Every reviewed value should be classified as one of:

- `public-parameter`;
- `public-input`;
- `public-result`;
- `public-loop-index`;
- `transcript-derived`;
- `randomness`;
- `secret-key`;
- `secret-coefficient`;
- `secret-intermediate`;
- `implementation-control`;
- `mixed`.

When classification is uncertain, treat the value as secret until reviewed.

## 4. Branching rules

### 4.1 Prohibited

Do not branch on:

- secret key bits;
- secret polynomial coefficients;
- secret-dependent comparison outcomes;
- secret-dependent validity predicates;
- secret-derived table indices.

Examples of prohibited patterns:

```rust
if secret_value == 0 {
    ...
}

while secret_value > bound {
    ...
}

match secret_bit {
    0 => ...,
    _ => ...,
}
```

### 4.2 Allowed with review

Branches may depend on:

- public parameter-set selection;
- public message or ciphertext lengths;
- public transcript values;
- public verification results;
- fixed public loop counters;
- allocation and panic paths that are proven independent of secrets;
- rejection-sampling control flow when documented and empirically analyzed.

### 4.3 Preferred substitutions

Prefer:

- arithmetic masking;
- constant-time selection;
- conditional assignment primitives;
- fixed-iteration loops;
- table-free arithmetic;
- public-indexed lookup tables only.

## 5. Memory-access rules

Prohibited:

```rust
let value = table[secret_index];
```

Preferred:

```rust
let mut selected = 0;
for (index, candidate) in table.iter().enumerate() {
    let mask = ct_eq(index, secret_index);
    selected = ct_select(mask, *candidate, selected);
}
```

Exceptions require documented proof that the index is public.

Stack- and frame-relative accesses using fixed offsets are implementation
control and are not secret-indexed.

## 6. Arithmetic rules

### 6.1 Division and remainder

Avoid integer division and remainder on secret values unless:

- the target architecture guarantees fixed latency;
- generated machine code is reviewed;
- timing tests show no distinguishability;
- the review record explicitly accepts the implementation.

Prefer multiplication by reciprocals, Barrett reduction, Montgomery reduction,
or branchless correction where appropriate.

### 6.2 Conditional correction

Secret-dependent arithmetic corrections should compile to branchless
instructions such as ARM64 `csel` or x86-64 `cmov`, not conditional jumps.

### 6.3 Overflow

Use integer widths and reduction schedules that make overflow behavior
explicit. Do not rely on debug-only overflow checks in security-critical
arithmetic.

## 7. Sampling and rejection sampling

Sampling code must document:

- whether loop bounds are fixed or data dependent;
- whether acceptance depends on secret, random, transcript-derived, or public
  data;
- whether memory addresses depend on sampled values;
- whether timing variation is expected by the algorithm.

Rejection sampling must be separately characterized because variable attempt
counts may be algorithmically expected.

For signing algorithms, validation should include:

- attempt-count distributions;
- rejection-category distributions;
- timing correlation with attempt count;
- fixed-key versus varying-key comparisons;
- residual timing after conditioning on attempt count.

## 8. Encoding and decoding

Encoding and decoding of secret-bearing objects must avoid:

- secret-dependent lengths;
- secret-dependent allocations;
- secret-indexed memory;
- secret-dependent early exits.

Malformed public input handling may be variable time, but the distinction must
not depend on secret key data.

## 9. Error handling

`Result`, panic, and allocator cleanup branches are acceptable only when the
error condition is independent of secret data.

Do not use `unwrap()` in production cryptographic paths. Audit-only binaries
may use `unwrap()` when inputs are fixed and the resulting branch is explicitly
classified as implementation control.

## 10. Compiler requirements

Security review applies to generated code, not only source code.

For every release target:

- record rustc version;
- record LLVM version;
- record target triple;
- record compiler flags;
- preserve machine-code audit artifacts;
- re-run audits after compiler upgrades.

Compiler upgrades are security-relevant changes.

## 11. Validation requirements

The minimum validation set for secret-bearing primitives is:

1. functional tests;
2. known-answer or ACVP vectors where available;
3. fixed-versus-random timing tests;
4. per-primitive localization;
5. generated-code inspection;
6. source-to-assembly dependency classification;
7. finding-register review;
8. cross-architecture validation before portability claims.

Non-detection in timing tests is not proof of constant-time execution.

## 12. Review disposition

Each finding must be classified as:

- `expected`;
- `constant-time-select`;
- `expected-rejection`;
- `declassified`;
- `mitigated`;
- `review`.

Each finding must have one status:

- `open`;
- `provisional`;
- `accepted`;
- `closed`.

No release may claim constant-time engineering conformance while unresolved
secret-dependent control-flow or secret-indexed-memory findings remain.

## 13. Release claims

Permitted wording:

> The implementation is engineered using constant-time design principles and
> has undergone source, timing, and generated-code review for the documented
> compiler and target configuration.

Prohibited wording without formal proof:

> The implementation is constant time on all platforms.

## 14. Scope limitations

This standard does not by itself address:

- power analysis;
- electromagnetic leakage;
- speculative-execution attacks;
- fault injection;
- operating-system scheduling effects;
- shared-resource leakage;
- compiler bugs outside the reviewed build;
- undocumented microarchitectural behavior.
