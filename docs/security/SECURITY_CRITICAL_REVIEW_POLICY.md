# Security-Critical Code Review Policy

Changes to cryptographic arithmetic, sampling, serialization, key handling,
signing, decapsulation, verification, or shared constant-time utilities require:

1. a security-impact statement in the pull request;
2. identification of secret-bearing inputs;
3. tests for functional behavior;
4. timing or generated-code evidence when control flow or memory access changes;
5. review by at least one maintainer familiar with constant-time cryptographic
   implementation.

The following changes automatically require renewed generated-code review:

- compiler or LLVM upgrade;
- target-feature change;
- optimization-level change;
- new use of division, remainder, table lookup, unsafe code, SIMD, or assembly;
- new branch in a secret-bearing function;
- new allocation in a secret-bearing function;
- refactoring of sampling, rounding, encoding, signing, or decapsulation code.

Pull requests must not claim constant-time behavior solely from source review.
