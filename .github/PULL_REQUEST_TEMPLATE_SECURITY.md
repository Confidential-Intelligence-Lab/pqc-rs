## Security impact

- [ ] This change does not affect cryptographic control flow, memory access,
      arithmetic, sampling, encoding, key handling, signing, verification,
      encapsulation, or decapsulation.
- [ ] This change affects security-critical code and the analysis below is
      complete.

### Secret-bearing inputs

Describe any secret key, secret coefficient, secret intermediate, or
secret-dependent randomness processed by the changed code.

### Control flow

Describe any new or changed branches, loop bounds, early exits, or Result paths.

### Memory access

Describe any new or changed indexing, table lookup, allocation, or deallocation.

### Arithmetic

Describe any division, remainder, conditional correction, overflow assumption,
SIMD operation, or architecture-specific behavior.

### Validation evidence

- [ ] Unit tests
- [ ] Known-answer or ACVP vectors
- [ ] Timing screen
- [ ] Per-primitive localization
- [ ] Generated-code inspection
- [ ] Finding-register update
- [ ] Cross-architecture validation

### Compiler and target

Record rustc, LLVM, target triple, optimization profile, and target features.

### Reviewer disposition

- [ ] No unresolved secret-dependent branch
- [ ] No unresolved secret-indexed memory
- [ ] Any accepted variable-time behavior is documented
