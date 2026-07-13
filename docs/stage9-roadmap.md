# Stage 9: ML-DSA / FIPS 204

## Stage 9A — Foundation

- parameter-set definitions;
- object-size constants;
- typed error model;
- stable module layout;
- public API placeholder;
- no conformance claim.

## Stage 9B — Polynomial and field arithmetic

- modulus and Montgomery representation;
- polynomial type;
- NTT and inverse NTT;
- pointwise multiplication;
- coefficient reduction;
- arithmetic known-answer tests.

## Stage 9C — Sampling and decomposition

- ExpandA;
- ExpandS;
- ExpandMask;
- SampleInBall;
- Power2Round;
- Decompose;
- HighBits and LowBits;
- MakeHint and UseHint.

## Stage 9D — Encoding

- public-key encoding and decoding;
- private-key encoding and decoding;
- signature encoding and decoding;
- strict canonical decoding;
- malformed-input tests.

## Stage 9E — Key generation

- deterministic internal key generation;
- randomized public API;
- FIPS 204 vectors;
- trace support.

## Stage 9F — Signing

- pure ML-DSA;
- context-string handling;
- deterministic and hedged variants;
- rejection-loop instrumentation;
- no secret formatting.

## Stage 9G — Verification

- strict signature parsing;
- challenge recomputation;
- malformed-signature rejection;
- negative tests.

## Stage 9H — ACVP and hardening

- ACVP harnesses;
- fuzzing;
- Miri and sanitizers;
- secret-lifetime review;
- performance and size baseline.
